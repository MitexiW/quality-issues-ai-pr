#!/usr/bin/env python3
# CodeQL pipeline entry point.
"""Execute CodeQL job manifests with resumable status tracking."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from experiment import EXPECTED_CODEQL_VERSION, query_spec
from utils import clean_text, setup_logging

ROOT = Path(__file__).resolve().parents[2]

STATE_FIELDS = [
    "attempts",
    "last_error",
    "updated_at",
    "log_path",
    "database_seconds",
    "analysis_seconds",
    "retry_excluded",
    "retry_excluded_reason",
]
RUNNABLE_STATUSES = {
    "prepared",
    "database_ready",
    "database_failed",
    "analysis_failed",
}
FAILED_STATUSES = {"database_failed", "analysis_failed"}
PROCESS_TERMINATE_GRACE_SECONDS = 10.0
_ACTIVE_PROCESSES: set[subprocess.Popen[Any]] = set()
_ACTIVE_PROCESSES_LOCK = threading.Lock()


@dataclass
class JobResult:
    index: int
    status: str
    error: str
    database_seconds: float
    analysis_seconds: float
    log_path: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="可恢复地执行 CodeQL 作业清单")
    parser.add_argument("--jobs", default="data/metadata/codeql_jobs.csv")
    parser.add_argument("--codeql", default="codeql")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--repo", action="append", default=[])
    parser.add_argument("--job-id", action="append", default=[])
    parser.add_argument(
        "--revisions",
        nargs="+",
        choices=("before", "after"),
        default=["before", "after"],
    )
    parser.add_argument("--logs-dir", default="data/logs/codeql")
    parser.add_argument("--skip-analysis", action="store_true")
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="重新执行 database_failed/analysis_failed 作业",
    )
    parser.add_argument(
        "--rebuild-database",
        action="store_true",
        help="删除并重建所选作业已有的 CodeQL 数据库",
    )
    parser.add_argument("--timeout", type=int, default=0, help="每个命令超时秒数，0 表示不限")
    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        help="传给 codeql database create/analyze 的 -j；0=用满所有核，默认 1（单线程）",
    )
    parser.add_argument(
        "--ram",
        type=int,
        default=0,
        help="每个 CodeQL 作业传给 database create/analyze 的 --ram（MB）；0=不显式限制",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_jobs(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    for field in STATE_FIELDS:
        if field not in fields:
            fields.append(field)
    return fields, rows


def write_jobs(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temp.replace(path)


def database_ready(path: Path) -> bool:
    if not (path / "codeql-database.yml").is_file():
        return False
    if (path / "working").exists():
        return False
    return any(child.is_dir() and child.name.startswith("db-") for child in path.iterdir())


def sarif_ready(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size == 0:
        return False
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload.get("version") == "2.1.0" and isinstance(payload.get("runs"), list)
    except (OSError, json.JSONDecodeError, AttributeError):
        return False


def installed_codeql_version(executable: str) -> str:
    result = subprocess.run(
        [executable, "version", "--format=terse"],
        check=True,
        text=True,
        capture_output=True,
    )
    output = result.stdout + result.stderr
    for line in output.splitlines():
        line = line.strip()
        if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+].*)?", line):
            return line
    raise RuntimeError(f"无法解析 CodeQL 版本输出: {output[-1000:]}")


def reconcile_job(job: dict[str, str]) -> None:
    sarif = Path(job["sarif_path"])
    database = Path(job["database_dir"])
    if sarif_ready(sarif):
        job["status"] = "completed"
    elif job.get("status", "") in FAILED_STATUSES:
        return
    elif database_ready(database):
        job["status"] = "database_ready"


def pair_key(job: dict[str, str]) -> tuple[str, str]:
    return job.get("repo_name", ""), job.get("pr_number", "")


def update_comparison_statuses(jobs: list[dict[str, str]]) -> None:
    groups: dict[tuple[str, str], list[dict[str, str]]] = {}
    for job in jobs:
        groups.setdefault(pair_key(job), []).append(job)
    for group in groups.values():
        statuses = {job.get("status", "") for job in group}
        if len(group) == 2 and statuses == {"completed"}:
            status = "analyzed"
        elif statuses & {"prepare_failed", "database_failed", "analysis_failed"}:
            status = "failed"
        elif statuses <= {"prepared", "database_ready", "completed"}:
            status = "prepared"
        else:
            status = "pending"
        for job in group:
            if job.get("comparison_status") != "compared":
                job["comparison_status"] = status


def validate_pair_configuration(jobs: list[dict[str, str]]) -> None:
    groups: dict[tuple[str, str], list[dict[str, str]]] = {}
    for job in jobs:
        groups.setdefault(pair_key(job), []).append(job)
    for key, group in groups.items():
        if len(group) != 2:
            continue
        versions = {job.get("codeql_version", "") for job in group}
        suites = {job.get("query_suite", "") for job in group}
        languages = {job.get("codeql_language", "") for job in group}
        if len(versions) != 1 or len(suites) != 1 or len(languages) != 1:
                raise ValueError(f"before/after 实验配置不一致: {key}")


def adjust_go_build_command(job: dict[str, str]) -> None:
    if job.get("codeql_language") != "go":
        return
    command = clean_text(job.get("build_command"))
    if command != "go build ./..." and not command.startswith("cd "):
        return
    source = Path(job.get("source_dir", ""))
    if source.joinpath("go.mod").is_file():
        return
    modules = sorted(
        path
        for path in source.rglob("go.mod")
        if "vendor" not in path.parts
    )
    if len(modules) != 1:
        return
    module_dir = modules[0].parent.relative_to(source).as_posix()
    helper = Path(__file__).resolve().parent / "go_build_in_dir.py"
    job["build_command"] = f"{sys.executable} {helper} {module_dir}"


def selected(job: dict[str, str], args: argparse.Namespace) -> bool:
    if job.get("revision") not in args.revisions:
        return False
    if args.repo and job.get("repo_name") not in args.repo:
        return False
    if args.job_id and job.get("job_id") not in args.job_id:
        return False
    if retry_excluded(job):
        return False
    status = job.get("status", "")
    if status in FAILED_STATUSES:
        return args.retry_failed
    return status in RUNNABLE_STATUSES or (
        args.rebuild_database and status == "completed"
    )


def safe_error(exc: BaseException) -> str:
    text = clean_text(exc)
    return text[-1000:]


def retry_excluded(job: dict[str, str]) -> bool:
    return clean_text(job.get("retry_excluded")).lower() in {
        "1",
        "true",
        "yes",
        "y",
    }


def signal_process_group(process: subprocess.Popen[Any], sig: signal.Signals) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, sig)
        elif sig == signal.SIGTERM:
            process.terminate()
        else:
            process.kill()
    except ProcessLookupError:
        return


def terminate_processes(
    processes: list[subprocess.Popen[Any]],
    *,
    grace_seconds: float = PROCESS_TERMINATE_GRACE_SECONDS,
) -> None:
    live = [process for process in processes if process.poll() is None]
    for process in live:
        signal_process_group(process, signal.SIGTERM)

    deadline = time.monotonic() + grace_seconds
    for process in live:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            pass

    survivors = [process for process in live if process.poll() is None]
    for process in survivors:
        signal_process_group(process, signal.SIGKILL)
    for process in survivors:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def terminate_active_processes() -> None:
    with _ACTIVE_PROCESSES_LOCK:
        processes = list(_ACTIVE_PROCESSES)
    terminate_processes(processes)


def install_shutdown_handlers() -> dict[signal.Signals, Any]:
    handled = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        handled.append(signal.SIGHUP)
    previous = {sig: signal.getsignal(sig) for sig in handled}

    def shutdown(signum: int, _frame: Any) -> None:
        terminate_active_processes()
        if signum == signal.SIGINT:
            raise KeyboardInterrupt
        raise SystemExit(128 + signum)

    for sig in handled:
        signal.signal(sig, shutdown)
    return previous


def restore_shutdown_handlers(previous: dict[signal.Signals, Any]) -> None:
    for sig, handler in previous.items():
        signal.signal(sig, handler)


def run_command(
    command: list[str],
    log_handle: Any,
    timeout: int,
    env: dict[str, str],
) -> float:
    started = time.monotonic()
    log_handle.write("$ " + " ".join(command) + "\n")
    log_handle.flush()
    process = subprocess.Popen(
        command,
        text=True,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        env=env,
        start_new_session=os.name == "posix",
    )
    with _ACTIVE_PROCESSES_LOCK:
        _ACTIVE_PROCESSES.add(process)
    try:
        try:
            returncode = process.wait(timeout=timeout or None)
        except subprocess.TimeoutExpired:
            log_handle.write(
                f"\n[timeout] 命令超过 {timeout} 秒，正在终止完整进程组\n"
            )
            log_handle.flush()
            terminate_processes([process])
            raise
        if returncode:
            raise subprocess.CalledProcessError(returncode, command)
    finally:
        with _ACTIVE_PROCESSES_LOCK:
            _ACTIVE_PROCESSES.discard(process)
    return time.monotonic() - started


def execution_env() -> dict[str, str]:
    env = os.environ.copy()
    paths = []
    local_jdk = ROOT / "tools/jdk-21"
    if local_jdk.joinpath("bin/javac").is_file():
        env["JAVA_HOME"] = str(local_jdk)
        paths.append(str(local_jdk / "bin"))
    java_cache = ROOT / "data/tool-cache/java"
    gradle_home = java_cache / "gradle"
    maven_home = java_cache / "maven"
    env.setdefault("GRADLE_USER_HOME", str(gradle_home))
    env["MAVEN_OPTS"] = (
        f"-Dmaven.repo.local={maven_home} "
        f"{env.get('MAVEN_OPTS', '')}"
    ).strip()
    for path in (gradle_home, maven_home):
        Path(path).mkdir(parents=True, exist_ok=True)
    local_go = ROOT / "tools/go/bin"
    if local_go.is_dir():
        paths.append(str(local_go))
        go_cache = ROOT / "data/tool-cache/go"
        env.setdefault("GOPATH", str(go_cache / "gopath"))
        env.setdefault("GOMODCACHE", str(go_cache / "pkg/mod"))
        env.setdefault("GOCACHE", str(go_cache / "build"))
        for path in (env["GOPATH"], env["GOMODCACHE"], env["GOCACHE"]):
            Path(path).mkdir(parents=True, exist_ok=True)
    # CodeQL's Python autobuilder selects ``python3``/``python`` from PATH.
    # Prefer this repository's virtual environment even when it was not
    # activated (or this script was accidentally started with system Python),
    # then fall back to the environment running this script. Project-pinned JDK
    # and Go toolchains intentionally remain ahead of the Python environment.
    venv_bin = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin")
    venv_python = venv_bin / ("python.exe" if os.name == "nt" else "python3")
    python_bin = venv_bin if venv_python.is_file() else Path(sys.executable).parent
    paths.append(str(python_bin))
    if paths:
        paths.append(env.get("PATH", ""))
        env["PATH"] = os.pathsep.join(path for path in paths if path)
    return env


def execute_job(
    index: int,
    job: dict[str, str],
    args: argparse.Namespace,
) -> JobResult:
    source = Path(job["source_dir"])
    database = Path(job["database_dir"])
    sarif = Path(job["sarif_path"])
    log_path = Path(args.logs_dir) / f"{job['job_id']}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    database_seconds = 0.0
    analysis_seconds = 0.0
    env = execution_env()

    if not source.is_dir():
        return JobResult(
            index,
            "source_missing",
            f"源码目录不存在: {source}",
            0.0,
            0.0,
            str(log_path),
        )

    try:
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"\n[{utc_now()}] start {job['job_id']}\n")
            if args.rebuild_database and database.exists():
                shutil.rmtree(database)
            if not database_ready(database):
                if database.exists():
                    shutil.rmtree(database)
                database.parent.mkdir(parents=True, exist_ok=True)
                create_command = [
                    args.codeql,
                    "database",
                    "create",
                    str(database),
                    f"--language={job['codeql_language']}",
                    f"--source-root={source}",
                    f"--threads={args.threads}",
                ]
                if clean_text(job.get("build_command")):
                    create_command.append(f"--command={job['build_command']}")
                else:
                    create_command.append(f"--build-mode={job['build_mode']}")
                if args.ram:
                    create_command.append(f"--ram={args.ram}")
                database_seconds = run_command(
                    create_command,
                    log,
                    args.timeout,
                    env,
                )
            if args.skip_analysis:
                return JobResult(
                    index,
                    "database_ready",
                    "",
                    database_seconds,
                    0.0,
                    str(log_path),
                )

            sarif.parent.mkdir(parents=True, exist_ok=True)
            if sarif.exists():
                sarif.unlink()
            analyze_command = [
                args.codeql,
                "database",
                "analyze",
                str(database),
                query_spec(job["codeql_language"], job["query_suite"]),
                "--format=sarif-latest",
                f"--threads={args.threads}",
                f"--output={sarif}",
            ]
            if args.ram:
                analyze_command.append(f"--ram={args.ram}")
            analysis_seconds = run_command(
                analyze_command,
                log,
                args.timeout,
                env,
            )
            if not sarif_ready(sarif):
                raise RuntimeError(f"CodeQL 未生成有效 SARIF: {sarif}")
        return JobResult(
            index,
            "completed",
            "",
            database_seconds,
            analysis_seconds,
            str(log_path),
        )
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        status = "analysis_failed" if database_ready(database) else "database_failed"
        return JobResult(
            index,
            status,
            safe_error(exc),
            database_seconds,
            analysis_seconds,
            str(log_path),
        )


def apply_result(job: dict[str, str], result: JobResult) -> None:
    job["status"] = result.status
    job["last_error"] = result.error
    job["updated_at"] = utc_now()
    job["log_path"] = result.log_path
    job["database_seconds"] = f"{result.database_seconds:.3f}"
    job["analysis_seconds"] = f"{result.analysis_seconds:.3f}"
    job["attempts"] = str(int(clean_text(job.get("attempts")) or "0") + 1)


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)
    if args.workers < 1:
        raise SystemExit("--workers 必须大于等于 1")
    if args.ram < 0:
        raise SystemExit("--ram 必须大于等于 0")
    jobs_path = Path(args.jobs)
    fields, jobs = read_jobs(jobs_path)
    validate_pair_configuration(jobs)
    expected_versions = {
        clean_text(job.get("codeql_version")) or EXPECTED_CODEQL_VERSION
        for job in jobs
    }
    if len(expected_versions) != 1:
        raise SystemExit("作业清单包含多个 CodeQL 版本")
    expected_version = expected_versions.pop()
    actual_version = installed_codeql_version(args.codeql)
    if actual_version != expected_version:
        raise SystemExit(
            f"CodeQL 版本不匹配: 期望 {expected_version}，实际 {actual_version}"
        )
    for job in jobs:
        reconcile_job(job)
        adjust_go_build_command(job)
    update_comparison_statuses(jobs)

    indexes = [index for index, job in enumerate(jobs) if selected(job, args)]
    if args.limit is not None:
        indexes = indexes[: args.limit]
    write_jobs(jobs_path, fields, jobs)
    if not indexes:
        print("没有可执行的 CodeQL 作业")
        return

    completed = 0
    failed = 0
    previous_handlers = install_shutdown_handlers()
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures: dict[Future[JobResult], int] = {
                executor.submit(execute_job, index, dict(jobs[index]), args): index
                for index in indexes
            }
            for future in as_completed(futures):
                result = future.result()
                apply_result(jobs[result.index], result)
                update_comparison_statuses(jobs)
                write_jobs(jobs_path, fields, jobs)
                completed += int(result.status in {"completed", "database_ready"})
                failed += int(
                    result.status.endswith("_failed")
                    or result.status == "source_missing"
                )
                print(
                    f"[{completed + failed}/{len(indexes)}] "
                    f"{jobs[result.index]['job_id']}: {result.status}"
                )
    finally:
        terminate_active_processes()
        restore_shutdown_handlers(previous_handlers)

    print(f"执行结束：成功 {completed}，失败 {failed}，清单已更新: {jobs_path}")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
