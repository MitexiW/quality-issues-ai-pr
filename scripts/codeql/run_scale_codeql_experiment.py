#!/usr/bin/env python3
# CodeQL pipeline entry point.
"""Run a resumable large-scale CodeQL before/after experiment."""

from __future__ import annotations

import argparse
import csv
import os
import random
import shlex
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPTS.parent


@dataclass(frozen=True)
class ExperimentPaths:
    root: Path
    candidates_dir: Path
    candidate_prs: Path
    prs: Path
    jobs: Path
    repos: Path
    cache: Path
    databases: Path
    sarif: Path
    logs: Path
    results: Path
    retention: Path
    excluded_analyzed: Path


@dataclass(frozen=True)
class BackgroundPrepare:
    process: subprocess.Popen
    base_jobs: Path
    work_jobs: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "一键运行大规模 CodeQL before/after 实验，并按差分结果清理无变化数据库"
        )
    )
    parser.add_argument(
        "--output-root",
        default="data/experiments/security-and-quality/scale500",
    )
    parser.add_argument(
        "--databases-dir",
        default="",
        help=(
            "CodeQL database 输出根目录；可传绝对路径。"
            "为空时使用 <output-root>/codeql-db"
        ),
    )
    parser.add_argument("--target-prs", type=int, default=500)
    parser.add_argument(
        "--candidate-prs",
        default="",
        help="已有候选 PR CSV；为空时用 filter_fix_candidates.py 生成",
    )
    parser.add_argument("--aidev-cache-dir", default="data/aidev_parquet")
    parser.add_argument("--skip-download", action="store_true")
    parser.add_argument("--refresh-candidates", action="store_true")
    parser.add_argument("--refresh-jobs", action="store_true")
    parser.add_argument(
        "--setup-only",
        action="store_true",
        help="只生成 PR 样本和 CodeQL job 清单，不执行 prepare/scan/compare",
    )
    parser.add_argument(
        "--sample-seed",
        type=int,
        default=None,
        help="设置后对候选 PR 做确定性 shuffle，再取前 target-prs 个",
    )
    parser.add_argument(
        "--no-dedupe-analyzed",
        action="store_true",
        help="允许重新选择历史上已经分析过的 PR；默认会排除",
    )
    parser.add_argument(
        "--dedupe-root",
        action="append",
        default=[],
        help=(
            "扫描其中已有结果用于排除已分析 PR；可重复传入，默认扫描 data/"
        ),
    )
    parser.add_argument(
        "--dedupe-file",
        action="append",
        default=[],
        help="额外用于去重的 codeql_jobs.csv 或 pr_security_summary.csv 文件",
    )
    parser.add_argument("--query-suite", default="security-and-quality")
    parser.add_argument("--codeql", default="codeql")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        help="每个 CodeQL 作业的 -j 线程数;0=用满所有核,默认 1;透传给 run_codeql_jobs.py",
    )
    parser.add_argument(
        "--ram",
        type=int,
        default=0,
        help="每个 CodeQL 作业的内存上限（MB）；0=不显式限制，透传给 run_codeql_jobs.py",
    )
    parser.add_argument(
        "--prepare-workers",
        type=int,
        default=1,
        help="并行准备仓库的并发数(按仓库分组);透传给 prepare_repositories.py --workers",
    )
    parser.add_argument(
        "--overlap-prepare",
        action="store_true",
        help=(
            "运行当前 CodeQL 批次时后台准备下一批 PR；后台 prepare 使用临时清单，"
            "完成后只合并变更状态，避免与 CodeQL 同时写 codeql_jobs.csv"
        ),
    )
    parser.add_argument("--timeout", type=int, default=7200)
    parser.add_argument(
        "--prs-per-cycle",
        type=int,
        default=5,
        help="每轮尽量准备并扫描多少个 PR；用于控制磁盘峰值",
    )
    parser.add_argument(
        "--job-limit-per-cycle",
        type=int,
        default=0,
        help="每轮最多执行多少个 before/after job；0 表示 prs-per-cycle*2",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=0,
        help="最多执行多少轮；0 表示一直运行到没有可推进工作",
    )
    parser.add_argument("--require-token", action="store_true")
    parser.add_argument("--token-env", default="GH_TOKEN")
    parser.add_argument("--prepare-retries", type=int, default=4)
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help=(
            "本次运行重试已有 prepare_failed/database_failed/analysis_failed；"
            "prepare_failed 每次启动只重置并重试一次"
        ),
    )
    parser.add_argument("--rebuild-database", action="store_true")
    parser.add_argument(
        "--keep-all-databases",
        action="store_true",
        help="禁用数据库清理，保留所有 CodeQL database",
    )
    parser.add_argument(
        "--aggressive-cleanup",
        action="store_true",
        help=(
            "差分后删除所有 compared PR 的 CodeQL database；"
            "若同时传 --prune-source-dirs，也删除所有 compared PR 的源码 worktree"
        ),
    )
    parser.add_argument(
        "--cleanup-every",
        type=int,
        default=1,
        help=(
            "自动清理间隔（按 cycle 计）；1=每轮清理，N=每 N 轮清理，"
            "0=关闭自动清理，仅在 --cleanup-only 时清理"
        ),
    )
    parser.add_argument(
        "--prune-source-dirs",
        action="store_true",
        help="同时删除无 introduced/fixed PR 的源码 worktree；默认只删数据库",
    )
    parser.add_argument(
        "--dry-run-cleanup",
        action="store_true",
        help="只记录本轮会清理哪些目录，不实际删除",
    )
    parser.add_argument(
        "--cleanup-only",
        action="store_true",
        help="只根据已有 pr_security_summary.csv 执行数据库保留策略",
    )
    parser.add_argument("--min-stars", type=int, default=500)
    parser.add_argument("--min-prs-per-repo", type=int, default=3)
    parser.add_argument("--min-files", type=int, default=1)
    parser.add_argument("--max-files", type=int, default=20)
    parser.add_argument("--min-lines", type=int, default=1)
    parser.add_argument("--max-lines", type=int, default=1000)
    parser.add_argument(
        "--languages",
        nargs="+",
        default=[],
        help="传给 filter_fix_candidates.py；为空时使用它的默认语言集合",
    )
    parser.add_argument(
        "--task-types",
        nargs="+",
        default=[],
        help="传给 filter_fix_candidates.py；为空时只保留 fix",
    )
    parser.add_argument(
        "--all-task-types",
        action="store_true",
        help="传给 filter_fix_candidates.py；保留所有 AIDev task type",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def checked_int(name: str, value: int, *, minimum: int) -> None:
    if value < minimum:
        raise SystemExit(f"--{name} 必须 >= {minimum}")


def validate_args(args: argparse.Namespace) -> None:
    checked_int("target-prs", args.target_prs, minimum=1)
    checked_int("workers", args.workers, minimum=1)
    checked_int("threads", args.threads, minimum=0)
    checked_int("ram", args.ram, minimum=0)
    checked_int("prepare-workers", args.prepare_workers, minimum=1)
    checked_int("timeout", args.timeout, minimum=0)
    checked_int("prs-per-cycle", args.prs_per_cycle, minimum=1)
    checked_int("job-limit-per-cycle", args.job_limit_per_cycle, minimum=0)
    checked_int("max-cycles", args.max_cycles, minimum=0)
    checked_int("prepare-retries", args.prepare_retries, minimum=1)
    checked_int("cleanup-every", args.cleanup_every, minimum=0)
    if args.keep_all_databases and args.aggressive_cleanup:
        raise SystemExit("--keep-all-databases 不能和 --aggressive-cleanup 同时使用")
    if args.databases_dir and resolve_path(args.databases_dir).resolve() == Path("/"):
        raise SystemExit("--databases-dir 不能是文件系统根目录 /")


def resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def arg_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def paths_for(args: argparse.Namespace) -> ExperimentPaths:
    root = resolve_path(args.output_root).resolve()
    candidates_dir = root / "candidates"
    databases = (
        resolve_path(args.databases_dir).resolve()
        if args.databases_dir
        else root / "codeql-db"
    )
    return ExperimentPaths(
        root=root,
        candidates_dir=candidates_dir,
        candidate_prs=candidates_dir / "candidate_prs.csv",
        prs=root / "prs.csv",
        jobs=root / "codeql_jobs.csv",
        repos=root / "repos",
        cache=root / "repos" / ".cache",
        databases=databases,
        sarif=root / "sarif",
        logs=root / "logs" / "codeql",
        results=root / "results",
        retention=root / "results" / "database_retention.csv",
        excluded_analyzed=root / "results" / "excluded_analyzed_prs.csv",
    )


def run_script(
    script: str,
    arguments: Iterable[str],
    *,
    allow_failure: bool = False,
) -> int:
    command = [sys.executable, str(resolve_script(script)), *arguments]
    print("+", shlex.join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT)
    if result.returncode and not allow_failure:
        raise subprocess.CalledProcessError(result.returncode, command)
    return result.returncode


def start_script(script: str, arguments: Iterable[str]) -> subprocess.Popen:
    command = [sys.executable, str(resolve_script(script)), *arguments]
    print("+", shlex.join(command), "&", flush=True)
    return subprocess.Popen(command, cwd=ROOT)


def resolve_script(script: str) -> Path:
    """Resolve active helpers after the CodeQL scripts were grouped together."""

    local = SCRIPTS / script
    if local.is_file():
        return local
    shared = SCRIPTS_ROOT / script
    if shared.is_file():
        return shared
    raise FileNotFoundError(f"experiment helper script not found: {script}")


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temp.replace(path)


def job_key(row: dict[str, str]) -> tuple[str, str, str, str]:
    return (
        row.get("job_id", ""),
        row.get("repo_name", ""),
        row.get("pr_number", ""),
        row.get("revision", ""),
    )


def row_count(path: Path) -> int:
    if not path.is_file():
        return 0
    _, rows = read_csv(path)
    return len(rows)


def pr_key(row: dict[str, str]) -> tuple[str, str, str]:
    repo_name = (row.get("repo_name") or "").strip()
    pr_number = (row.get("pr_number") or "").strip()
    pr_id = (row.get("pr_id") or "").strip()
    if repo_name and pr_number:
        return "repo_pr", repo_name, pr_number
    if pr_id:
        return "pr_id", pr_id, ""
    return "", "", ""


def key_parts(key: tuple[str, str, str]) -> tuple[str, str, str]:
    if key[0] == "repo_pr":
        return key[1], key[2], ""
    if key[0] == "pr_id":
        return "", "", key[1]
    return "", "", ""


def find_dedupe_files(roots: list[str], explicit_files: list[str]) -> list[Path]:
    files: dict[Path, None] = {}
    for value in explicit_files:
        path = resolve_path(value)
        if path.is_file():
            files[path.resolve()] = None

    skip_dirs = {
        ".cache",
        ".git",
        "aidev_parquet",
        "candidates",
        "codeql-db",
        "logs",
        "node_modules",
        "repos",
        "sarif",
        "tool-cache",
    }
    for value in roots or ["data"]:
        root = resolve_path(value)
        if root.is_file():
            if root.name in {"codeql_jobs.csv", "pr_security_summary.csv"}:
                files[root.resolve()] = None
            continue
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in skip_dirs]
            for filename in filenames:
                if filename in {"codeql_jobs.csv", "pr_security_summary.csv"}:
                    files[(Path(dirpath) / filename).resolve()] = None
    return sorted(files)


def analyzed_from_summary(path: Path) -> dict[tuple[str, str, str], set[str]]:
    output: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    _, rows = read_csv(path)
    for row in rows:
        if row.get("comparison_status") != "compared":
            continue
        key = pr_key(row)
        if key[0]:
            output[key].add(arg_path(path))
    return output


def analyzed_from_jobs(path: Path) -> dict[tuple[str, str, str], set[str]]:
    output: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    _, rows = read_csv(path)
    groups = jobs_by_pair(rows)
    for jobs in groups.values():
        if len(jobs) != 2:
            continue
        comparison_statuses = {job.get("comparison_status", "") for job in jobs}
        statuses = {job.get("status", "") for job in jobs}
        already_analyzed = (
            comparison_statuses <= {"compared", "analyzed"}
            and bool(comparison_statuses)
        ) or statuses == {"completed"}
        if not already_analyzed:
            continue
        key = pr_key(jobs[0])
        if key[0]:
            output[key].add(arg_path(path))
    return output


def collect_analyzed_prs(
    args: argparse.Namespace,
) -> dict[tuple[str, str, str], set[str]]:
    if args.no_dedupe_analyzed:
        return {}
    analyzed: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for path in find_dedupe_files(args.dedupe_root, args.dedupe_file):
        try:
            if path.name == "pr_security_summary.csv":
                found = analyzed_from_summary(path)
            else:
                found = analyzed_from_jobs(path)
        except (OSError, csv.Error, KeyError):
            continue
        for key, sources in found.items():
            analyzed[key].update(sources)
    return analyzed


def write_excluded_analyzed(
    path: Path,
    excluded: dict[tuple[str, str, str], set[str]],
) -> None:
    fields = ["repo_name", "pr_number", "pr_id", "source_files"]
    rows = []
    for key, sources in sorted(excluded.items()):
        repo_name, pr_number, pr_id = key_parts(key)
        rows.append(
            {
                "repo_name": repo_name,
                "pr_number": pr_number,
                "pr_id": pr_id,
                "source_files": "|".join(sorted(sources)),
            }
        )
    write_csv(path, fields, rows)


def ensure_candidates(args: argparse.Namespace, paths: ExperimentPaths) -> bool:
    paths.root.mkdir(parents=True, exist_ok=True)
    source = resolve_path(args.candidate_prs) if args.candidate_prs else paths.candidate_prs

    if not args.candidate_prs and (
        args.refresh_candidates or not paths.candidate_prs.is_file()
    ):
        filter_args = [
            "--cache-dir",
            arg_path(resolve_path(args.aidev_cache_dir)),
            "--output-dir",
            arg_path(paths.candidates_dir),
            "--min-stars",
            str(args.min_stars),
            "--min-prs-per-repo",
            str(args.min_prs_per_repo),
            "--min-files",
            str(args.min_files),
            "--max-files",
            str(args.max_files),
            "--min-lines",
            str(args.min_lines),
            "--max-lines",
            str(args.max_lines),
        ]
        if args.skip_download:
            filter_args.append("--skip-download")
        if args.languages:
            filter_args.extend(["--languages", *args.languages])
        if args.task_types:
            filter_args.extend(["--task-types", *args.task_types])
        if args.all_task_types:
            filter_args.append("--all-task-types")
        if args.verbose:
            filter_args.append("--verbose")
        run_script("filter_fix_candidates.py", filter_args)

    if not source.is_file():
        raise FileNotFoundError(f"候选 PR 文件不存在: {source}")

    should_write_prs = (
        args.refresh_candidates
        or not paths.prs.is_file()
        or row_count(paths.prs) != args.target_prs
    )
    if not should_write_prs:
        print(f"复用已选 PR: {arg_path(paths.prs)} ({row_count(paths.prs)} 个)")
        return False

    fields, rows = read_csv(source)
    if args.sample_seed is not None:
        random.Random(args.sample_seed).shuffle(rows)
    analyzed = collect_analyzed_prs(args)
    excluded_analyzed: dict[tuple[str, str, str], set[str]] = {}
    selected = []
    selected_keys: set[tuple[str, str, str]] = set()
    duplicate_candidates = 0
    for row in rows:
        key = pr_key(row)
        if key[0] and key in selected_keys:
            duplicate_candidates += 1
            continue
        if key[0] and key in analyzed:
            excluded_analyzed[key] = analyzed[key]
            continue
        selected.append(row)
        if key[0]:
            selected_keys.add(key)
        if len(selected) >= args.target_prs:
            break
    if len(selected) < args.target_prs:
        print(
            f"警告：候选 PR 只有 {len(selected)} 个，少于目标 {args.target_prs} 个",
            flush=True,
        )
    write_csv(paths.prs, fields, selected)
    write_excluded_analyzed(paths.excluded_analyzed, excluded_analyzed)
    print(f"已选择 {len(selected)} 个 PR -> {arg_path(paths.prs)}")
    if analyzed:
        print(
            f"已排除历史分析过的 PR {len(excluded_analyzed)} 个；"
            f"记录 -> {arg_path(paths.excluded_analyzed)}"
        )
    if duplicate_candidates:
        print(f"候选 CSV 内重复 PR 已跳过 {duplicate_candidates} 个")
    return True


def ensure_jobs(
    args: argparse.Namespace,
    paths: ExperimentPaths,
    *,
    prs_written: bool,
) -> None:
    if paths.jobs.is_file() and not args.refresh_jobs and not prs_written:
        print(f"复用作业清单: {arg_path(paths.jobs)}")
        if args.databases_dir:
            relocate_unfinished_database_dirs(paths)
        return
    run_script(
        "prepare_codeql_jobs.py",
        [
            "--prs",
            arg_path(paths.prs),
            "--output",
            arg_path(paths.jobs),
            "--repos-dir",
            arg_path(paths.repos),
            "--databases-dir",
            arg_path(paths.databases),
            "--sarif-dir",
            arg_path(paths.sarif),
            "--query-suite",
            args.query_suite,
            "--codeql",
            args.codeql,
        ],
    )


def job_path(path_value: str) -> Path:
    path = Path(path_value)
    return path if path.is_absolute() else ROOT / path


def has_ready_database(path_value: str) -> bool:
    database = job_path(path_value)
    return (
        database.joinpath("codeql-database.yml").is_file()
        and not database.joinpath("working").exists()
    )


def relocate_unfinished_database_dirs(paths: ExperimentPaths) -> None:
    """Point unfinished jobs at a new database root without losing SARIF results."""
    fields, rows = read_csv(paths.jobs)
    changed = 0
    reset_to_prepared = 0

    for job in rows:
        if job.get("status") == "completed":
            continue
        job_id = job.get("job_id", "")
        if not job_id:
            continue
        database_dir = arg_path(paths.databases / job_id)
        if job.get("database_dir") == database_dir:
            continue

        job["database_dir"] = database_dir
        if job.get("status") == "database_ready" and not has_ready_database(database_dir):
            job["status"] = "prepared"
            reset_to_prepared += 1

        if "create_command" in fields or "analyze_command" in fields:
            # Keep the human-readable manifest commands in sync with database_dir.
            from prepare_codeql_jobs import command_for_job

            create, analyze = command_for_job(job)
            job["create_command"] = create
            job["analyze_command"] = analyze
        changed += 1

    if not changed:
        return
    write_csv(paths.jobs, fields, rows)
    message = (
        f"已将 {changed} 个未完成作业的 CodeQL database 目录切换至: "
        f"{arg_path(paths.databases)}"
    )
    if reset_to_prepared:
        message += f"；其中 {reset_to_prepared} 个 database_ready 作业将在新目录重新建库"
    print(message)


def jobs_by_pair(rows: list[dict[str, str]]) -> dict[tuple[str, str], list[dict[str, str]]]:
    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[(row.get("repo_name", ""), row.get("pr_number", ""))].append(row)
    return groups


def reset_prepare_failures_for_retry(path: Path) -> int:
    """Make existing prepare failures eligible once for this orchestrator run."""
    fields, rows = read_csv(path)
    reset = 0
    for job in rows:
        if job.get("status") != "prepare_failed":
            continue
        if retry_excluded(job):
            continue
        job["status"] = "needs_ref"
        job["comparison_status"] = "pending"
        reset += 1
    if reset:
        write_csv(path, fields, rows)
    return reset


def retry_excluded(job: dict[str, str]) -> bool:
    return job.get("retry_excluded", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
    }


def count_excluded_codeql_failures(path: Path) -> int:
    _, rows = read_csv(path)
    return sum(
        1
        for job in rows
        if job.get("status") in {"database_failed", "analysis_failed"}
        and retry_excluded(job)
    )


def reset_codeql_failures_for_retry(path: Path) -> int:
    """Make existing CodeQL failures runnable once for this orchestrator run."""
    fields, rows = read_csv(path)
    reset = 0
    reset_pairs: set[tuple[str, str]] = set()
    for job in rows:
        status = job.get("status")
        if status not in {"database_failed", "analysis_failed"}:
            continue
        if retry_excluded(job):
            continue
        if status == "analysis_failed" and has_ready_database(
            job.get("database_dir", "")
        ):
            job["status"] = "database_ready"
        else:
            job["status"] = "prepared"
        reset_pairs.add((job.get("repo_name", ""), job.get("pr_number", "")))
        reset += 1
    for job in rows:
        key = (job.get("repo_name", ""), job.get("pr_number", ""))
        if key in reset_pairs and job.get("comparison_status") != "compared":
            job["comparison_status"] = "pending"
    if reset:
        write_csv(path, fields, rows)
    return reset


def count_state(paths: ExperimentPaths) -> dict[str, int | Counter]:
    _, rows = read_csv(paths.jobs)
    groups = jobs_by_pair(rows)
    runnable_statuses = {"prepared", "database_ready"}
    status_counts = Counter(row.get("status", "") for row in rows)
    comparison_counts = Counter(row.get("comparison_status", "") for row in rows)
    completed_pairs = sum(
        1
        for jobs in groups.values()
        if len(jobs) == 2 and all(job.get("status") == "completed" for job in jobs)
    )
    compared_pairs = sum(
        1
        for jobs in groups.values()
        if len(jobs) == 2
        and all(job.get("comparison_status") == "compared" for job in jobs)
    )
    failed_pairs = sum(
        1
        for jobs in groups.values()
        if any(
            job.get("comparison_status") == "failed"
            or job.get("status", "").endswith("failed")
            for job in jobs
        )
    )
    eligible_pairs = sum(
        1
        for jobs in groups.values()
        if not any(retry_excluded(job) for job in jobs)
        and any(job.get("status") in {"ready", "needs_ref"} for job in jobs)
    )
    runnable_jobs = sum(
        1
        for row in rows
        if row.get("status") in runnable_statuses and not retry_excluded(row)
    )
    analyzed_pairs = sum(
        1
        for jobs in groups.values()
        if len(jobs) == 2
        and all(job.get("comparison_status") == "analyzed" for job in jobs)
    )
    return {
        "status": status_counts,
        "comparison": comparison_counts,
        "completed_pairs": completed_pairs,
        "compared_pairs": compared_pairs,
        "failed_pairs": failed_pairs,
        "eligible_pairs": eligible_pairs,
        "runnable_jobs": runnable_jobs,
        "analyzed_pairs": analyzed_pairs,
        "total_pairs": len(groups),
    }


def build_prepare_args(
    args: argparse.Namespace,
    paths: ExperimentPaths,
    *,
    limit: int,
    jobs_path: Path | None = None,
) -> list[str]:
    prepare_args = [
        "--jobs",
        arg_path(jobs_path or paths.jobs),
        "--cache-dir",
        arg_path(paths.cache),
        "--status",
        "ready",
        "--status",
        "needs_ref",
        "--limit",
        str(limit),
        "--workers",
        str(args.prepare_workers),
        "--token-env",
        args.token_env,
        "--retries",
        str(args.prepare_retries),
    ]
    if args.require_token:
        prepare_args.append("--require-token")
    if args.verbose:
        prepare_args.append("--verbose")
    return prepare_args


def prepare_one(args: argparse.Namespace, paths: ExperimentPaths, *, limit: int = 1) -> int:
    prepare_args = build_prepare_args(args, paths, limit=limit)
    return run_script("prepare_repositories.py", prepare_args, allow_failure=True)


def start_background_prepare(
    args: argparse.Namespace,
    paths: ExperimentPaths,
    *,
    cycle: int,
    limit: int,
) -> BackgroundPrepare:
    pipeline_dir = paths.root / ".pipeline"
    pipeline_dir.mkdir(parents=True, exist_ok=True)
    base_jobs = pipeline_dir / f"cycle-{cycle}-prepare-base.csv"
    work_jobs = pipeline_dir / f"cycle-{cycle}-prepare-work.csv"
    shutil.copy2(paths.jobs, base_jobs)
    shutil.copy2(paths.jobs, work_jobs)
    process = start_script(
        "prepare_repositories.py",
        build_prepare_args(args, paths, limit=limit, jobs_path=work_jobs),
    )
    return BackgroundPrepare(process=process, base_jobs=base_jobs, work_jobs=work_jobs)


def rows_differ(
    left: dict[str, str],
    right: dict[str, str],
    fields: Iterable[str],
) -> bool:
    return any(left.get(field, "") != right.get(field, "") for field in fields)


def merge_changed_jobs(base_jobs: Path, work_jobs: Path, target_jobs: Path) -> int:
    base_fields, base_rows = read_csv(base_jobs)
    work_fields, work_rows = read_csv(work_jobs)
    target_fields, target_rows = read_csv(target_jobs)
    base_by_key = {job_key(row): row for row in base_rows}
    changed_by_key: dict[tuple[str, str, str, str], dict[str, str]] = {}

    for row in work_rows:
        key = job_key(row)
        base_row = base_by_key.get(key)
        if base_row is None or rows_differ(row, base_row, work_fields):
            changed_by_key[key] = row

    if not changed_by_key:
        return 0

    merged_fields = list(target_fields)
    for field in work_fields:
        if field not in merged_fields:
            merged_fields.append(field)

    merged = 0
    conflicts = 0
    for row in target_rows:
        key = job_key(row)
        changed = changed_by_key.get(key)
        if not changed:
            continue
        base_row = base_by_key.get(key)
        if base_row is not None and rows_differ(row, base_row, target_fields):
            conflicts += 1
            continue
        for field in work_fields:
            row[field] = changed.get(field, "")
        merged += 1

    write_csv(target_jobs, merged_fields, target_rows)
    if conflicts:
        print(f"后台 prepare 合并跳过冲突 job {conflicts} 个")
    return merged


def finish_background_prepare(background: BackgroundPrepare, paths: ExperimentPaths) -> int:
    returncode = background.process.wait()
    merged = 0
    if background.work_jobs.is_file():
        merged = merge_changed_jobs(background.base_jobs, background.work_jobs, paths.jobs)
    print(
        f"后台 prepare 完成: returncode={returncode} merged_jobs={merged}",
        flush=True,
    )
    for path in (background.base_jobs, background.work_jobs):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    return returncode


def run_codeql_cycle(
    args: argparse.Namespace,
    paths: ExperimentPaths,
    *,
    job_limit: int,
) -> int:
    codeql_args = [
        "--jobs",
        arg_path(paths.jobs),
        "--logs-dir",
        arg_path(paths.logs),
        "--codeql",
        args.codeql,
        "--workers",
        str(args.workers),
        "--threads",
        str(args.threads),
        "--ram",
        str(args.ram),
        "--timeout",
        str(args.timeout),
        "--limit",
        str(job_limit),
    ]
    if args.rebuild_database:
        codeql_args.append("--rebuild-database")
    if args.verbose:
        codeql_args.append("--verbose")
    return run_script("run_codeql_jobs.py", codeql_args, allow_failure=True)


def refresh_results(args: argparse.Namespace, paths: ExperimentPaths) -> None:
    run_script(
        "compare_sarif.py",
        [
            "--jobs",
            arg_path(paths.jobs),
            "--output-dir",
            arg_path(paths.results),
        ],
        allow_failure=True,
    )
    run_script(
        "create_review_sheet.py",
        [
            "--introduced",
            arg_path(paths.results / "introduced_alerts.csv"),
            "--output",
            arg_path(paths.results / "introduced_alert_review.csv"),
            "--preserve-existing",
        ],
    )
    run_script(
        "summarize_results.py",
        [
            "--results-dir",
            arg_path(paths.results),
            "--prs",
            arg_path(paths.prs),
            "--jobs",
            arg_path(paths.jobs),
            "--output",
            arg_path(paths.results / "summary.md"),
        ],
    )


def parse_int(value: str) -> int:
    try:
        return int(value or "0")
    except ValueError:
        return 0


def safe_remove_dir(
    path_value: str,
    allowed_roots: Iterable[Path],
    *,
    dry_run: bool,
) -> str:
    if not path_value:
        return "missing"
    path = Path(path_value)
    full_path = path if path.is_absolute() else ROOT / path
    resolved = full_path.resolve()
    resolved_roots = [root.resolve() for root in allowed_roots]
    if not any(resolved == root or resolved.is_relative_to(root) for root in resolved_roots):
        raise RuntimeError(f"拒绝删除实验目录外路径: {resolved}")
    if not resolved.exists():
        return "missing"
    if not resolved.is_dir():
        return "not_dir"
    if dry_run:
        return "dry_run"
    shutil.rmtree(resolved)
    return "deleted"


def existing_dir_action(path_value: str) -> str:
    if not path_value:
        return "missing"
    path = Path(path_value)
    full_path = path if path.is_absolute() else ROOT / path
    return "kept" if full_path.is_dir() else "missing"


def database_cleanup_roots(
    paths: ExperimentPaths,
    job_rows: Iterable[dict[str, str]],
) -> tuple[Path, ...]:
    roots: set[Path] = {paths.root.resolve(), paths.databases.resolve()}
    for job in job_rows:
        job_id = job.get("job_id", "")
        database_dir = job.get("database_dir", "")
        if not job_id or not database_dir:
            continue
        path = Path(database_dir)
        full_path = path if path.is_absolute() else ROOT / path
        resolved = full_path.resolve()
        if resolved.name == job_id:
            roots.add(resolved.parent)
    return tuple(roots)


def prune_clean_databases(args: argparse.Namespace, paths: ExperimentPaths) -> None:
    if args.keep_all_databases:
        print("数据库清理已禁用：--keep-all-databases")
        return
    summary_path = paths.results / "pr_security_summary.csv"
    if not summary_path.is_file():
        print("尚无 pr_security_summary.csv，跳过数据库清理")
        return

    _, summary_rows = read_csv(summary_path)
    _, job_rows = read_csv(paths.jobs)
    allowed_database_roots = database_cleanup_roots(paths, job_rows)
    groups = jobs_by_pair(job_rows)
    retention_fields = [
        "repo_name",
        "pr_number",
        "introduced_alerts",
        "fixed_alerts",
        "persistent_alerts",
        "comparison_status",
        "database_retention",
        "database_dirs",
        "database_actions",
        "source_retention",
        "source_dirs",
        "source_actions",
    ]
    retention_rows: list[dict[str, str]] = []
    deleted_databases = 0
    kept_database_pairs = 0
    deleted_source_dirs = 0

    for row in summary_rows:
        if row.get("comparison_status") != "compared":
            continue
        introduced = parse_int(row.get("introduced_alerts", ""))
        fixed = parse_int(row.get("fixed_alerts", ""))
        key = (row.get("repo_name", ""), row.get("pr_number", ""))
        jobs = groups.get(key, [])
        db_dirs = [job.get("database_dir", "") for job in jobs]
        source_dirs = [job.get("source_dir", "") for job in jobs]
        alert_delta = introduced > 0 or fixed > 0
        keep = alert_delta and not args.aggressive_cleanup

        if keep:
            db_actions = [existing_dir_action(directory) for directory in db_dirs]
            source_actions = [existing_dir_action(directory) for directory in source_dirs]
            kept_database_pairs += 1
            db_retention = "kept_alert_delta"
            source_retention = "kept_alert_delta"
        else:
            db_actions = [
                safe_remove_dir(
                    directory,
                    allowed_database_roots,
                    dry_run=args.dry_run_cleanup,
                )
                for directory in db_dirs
            ]
            deleted_databases += sum(action in {"deleted", "dry_run"} for action in db_actions)
            db_retention = (
                "deleted_alert_delta_pair"
                if alert_delta and args.aggressive_cleanup
                else "deleted_clean_pair"
            )
            if args.prune_source_dirs:
                source_actions = [
                    safe_remove_dir(
                        directory,
                        (paths.root,),
                        dry_run=args.dry_run_cleanup,
                    )
                    for directory in source_dirs
                ]
                deleted_source_dirs += sum(
                    action in {"deleted", "dry_run"} for action in source_actions
                )
                source_retention = (
                    "deleted_alert_delta_pair"
                    if alert_delta and args.aggressive_cleanup
                    else "deleted_clean_pair"
                )
            else:
                source_actions = [existing_dir_action(directory) for directory in source_dirs]
                source_retention = "kept"

        retention_rows.append(
            {
                "repo_name": key[0],
                "pr_number": key[1],
                "introduced_alerts": str(introduced),
                "fixed_alerts": str(fixed),
                "persistent_alerts": row.get("persistent_alerts", ""),
                "comparison_status": row.get("comparison_status", ""),
                "database_retention": db_retention,
                "database_dirs": "|".join(db_dirs),
                "database_actions": "|".join(db_actions),
                "source_retention": source_retention,
                "source_dirs": "|".join(source_dirs),
                "source_actions": "|".join(source_actions),
            }
        )

    write_csv(paths.retention, retention_fields, retention_rows)
    print(
        "数据库保留策略完成："
        f"保留有 introduced/fixed 的 PR {kept_database_pairs} 个；"
        f"清理数据库目录 {deleted_databases} 个；"
        f"清理源码目录 {deleted_source_dirs} 个；"
        f"记录 -> {arg_path(paths.retention)}"
    )


def format_progress_bar(done: int, total: int, *, width: int = 30) -> str:
    if total <= 0:
        return "[" + "-" * width + "] 0.0%"
    done = max(0, min(done, total))
    filled = int(width * done / total)
    percent = done * 100 / total
    return "[" + "#" * filled + "-" * (width - filled) + f"] {percent:.1f}%"


def print_state(label: str, state: dict[str, int | Counter]) -> None:
    total_pairs = int(state["total_pairs"])
    compared_pairs = int(state["compared_pairs"])
    failed_pairs = int(state["failed_pairs"])
    terminal_pairs = min(total_pairs, compared_pairs + failed_pairs)
    progress = format_progress_bar(terminal_pairs, total_pairs)
    print(
        f"{label}: progress={progress} terminal_pairs={terminal_pairs}/"
        f"{total_pairs} compared_pairs={compared_pairs} failed_pairs={failed_pairs} "
        f"completed_pairs={state['completed_pairs']} eligible_pairs={state['eligible_pairs']} "
        f"runnable_jobs={state['runnable_jobs']} "
        f"status={dict(state['status'])} comparison={dict(state['comparison'])}",
        flush=True,
    )


def work_left(state: dict[str, int | Counter]) -> bool:
    return bool(
        state["eligible_pairs"]
        or state["runnable_jobs"]
        or state["analyzed_pairs"]
    )


def cleanup_due(
    args: argparse.Namespace,
    state: dict[str, int | Counter],
    *,
    cycle: int,
    selected_prs: int,
) -> bool:
    if args.cleanup_every == 0:
        return False
    if cycle % args.cleanup_every == 0:
        return True
    if int(state["compared_pairs"]) >= selected_prs or not work_left(state):
        return True
    return bool(args.max_cycles and cycle >= args.max_cycles)


def main() -> None:
    args = parse_args()
    validate_args(args)
    paths = paths_for(args)
    job_limit = args.job_limit_per_cycle or args.prs_per_cycle * 2

    if args.cleanup_only:
        if args.databases_dir and paths.jobs.is_file():
            relocate_unfinished_database_dirs(paths)
        prune_clean_databases(args, paths)
        return

    prs_written = ensure_candidates(args, paths)
    ensure_jobs(args, paths, prs_written=prs_written)
    if args.retry_failed:
        reset_prepare_jobs = reset_prepare_failures_for_retry(paths.jobs)
        excluded_codeql_jobs = count_excluded_codeql_failures(paths.jobs)
        reset_codeql_jobs = reset_codeql_failures_for_retry(paths.jobs)
        if reset_prepare_jobs:
            print(f"已将 prepare_failed 作业重置为可重试: {reset_prepare_jobs} 个")
        if reset_codeql_jobs:
            print(
                "已将 database_failed/analysis_failed 作业重置为单次可重试: "
                f"{reset_codeql_jobs} 个"
            )
        if excluded_codeql_jobs:
            print(
                "按 retry_excluded 标记跳过低价值 CodeQL 重试: "
                f"{excluded_codeql_jobs} 个"
            )
    selected_prs = row_count(paths.prs)
    if not selected_prs:
        raise SystemExit("没有可测试的 PR")
    if args.setup_only:
        print(
            f"setup-only 完成：PR {selected_prs} 个，job 清单 -> {arg_path(paths.jobs)}"
        )
        return

    cycle = 0
    while True:
        cycle += 1
        if args.max_cycles and cycle > args.max_cycles:
            print(f"达到 --max-cycles={args.max_cycles}，停止")
            break

        state = count_state(paths)
        cycle_start_state = state
        print_state(f"cycle {cycle} start", state)
        if state["compared_pairs"] >= selected_prs:
            print("目标 PR 已全部比较完成")
            break

        while state["runnable_jobs"] < job_limit and state["eligible_pairs"] > 0:
            before = count_state(paths)
            # Prepare a whole batch in one parallel invocation. One PR yields two
            # runnable jobs, so aim for the shortfall in runnable jobs.
            shortfall = job_limit - int(state["runnable_jobs"])
            batch = max(args.prs_per_cycle, (shortfall + 1) // 2)
            prepare_one(args, paths, limit=batch)
            state = count_state(paths)
            if before == state:
                print("prepare 未改变作业状态，停止本轮准备")
                break

        state = count_state(paths)
        if state["runnable_jobs"]:
            background_prepare: BackgroundPrepare | None = None
            if (
                args.overlap_prepare
                and state["eligible_pairs"] > 0
                and state["runnable_jobs"] <= job_limit
            ):
                background_prepare = start_background_prepare(
                    args,
                    paths,
                    cycle=cycle,
                    limit=args.prs_per_cycle,
                )
            run_codeql_cycle(args, paths, job_limit=min(job_limit, state["runnable_jobs"]))
            if background_prepare is not None:
                finish_background_prepare(background_prepare, paths)

        refresh_results(args, paths)
        state = count_state(paths)
        if cleanup_due(args, state, cycle=cycle, selected_prs=selected_prs):
            prune_clean_databases(args, paths)
        elif args.cleanup_every == 0:
            print("本轮跳过数据库清理：--cleanup-every=0")
        else:
            next_cycle = cycle + (args.cleanup_every - cycle % args.cleanup_every)
            print(
                "本轮延后数据库清理："
                f"--cleanup-every={args.cleanup_every}，预计 cycle {next_cycle} 执行"
            )
        print_state(f"cycle {cycle} done", state)
        if state == cycle_start_state:
            print("本轮没有状态进展，停止；请检查网络、GitHub token 或失败日志")
            break
        if not work_left(state):
            print("没有剩余可准备或可执行的作业，停止")
            break


if __name__ == "__main__":
    main()
