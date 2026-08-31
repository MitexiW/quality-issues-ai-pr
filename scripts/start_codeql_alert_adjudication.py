#!/usr/bin/env python3
"""Start or resume the frozen full CodeQL alert adjudication in one command."""

from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUN_DIR = ROOT / (
    "data/experiments/security-and-quality/study_stars500/reports/"
    "codeql_alert_adjudication_20260804_v5/formal_run_20260804_v5"
)
PILOT_BATCH_IDS = (
    "adjbatch-4d174cbe3c7e506f7b47ace4",
    "adjbatch-1b3ea25854541b259374fb8a",
    "adjbatch-9b4479bd3f9b3963ce7f9cc1",
    "adjbatch-54009a0f9b85c2a0bbc5550f",
    "adjbatch-5f254b4977c864979c6d8dc4",
    "adjbatch-47f30c280e0ba0cf2d34bf0b",
    "adjbatch-fcc2f87af46f09c849fea1d8",
    "adjbatch-7fe7ee45f4939f25593f20f0",
    "adjbatch-e2ffd510a47d308c6236a6b2",
    "adjbatch-5f4fafad0f8fe7c82d5ce950",
)
HEARTBEAT_SECONDS = 30


def heartbeat_stage(run_dir: Path) -> str:
    """Describe externally visible child progress without changing the run."""

    if not run_dir.is_dir():
        return "initializing and validating the frozen frame"

    active_attempts: list[Path] = []
    invocations = run_dir / "invocations"
    if invocations.is_dir():
        for attempt in invocations.glob("*/attempt-*"):
            if not (attempt / "execution.json").exists() and not (
                attempt / "failure.json"
            ).exists():
                active_attempts.append(attempt)
    if active_attempts:
        with_preflight = sum((path / "preflight.json").is_file() for path in active_attempts)
        raw_bytes = sum(
            (path / "raw_sdk_messages.jsonl").stat().st_size
            for path in active_attempts
            if (path / "raw_sdk_messages.jsonl").is_file()
        )
        return (
            f"model/SDK stage: active_attempts={len(active_attempts)} "
            f"preflight_ready={with_preflight} raw_message_bytes={raw_bytes}"
        )

    scratch = run_dir / "scratch"
    scratch_cases = sum(path.is_dir() for path in scratch.iterdir()) if scratch.is_dir() else 0
    if scratch_cases:
        return f"preparing or auditing worktrees: active_cases={scratch_cases}"
    return "loading job indexes or scheduling the next batch"


def run_with_heartbeat(
    values: list[str], *, run_dir: Path, label: str
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(values, cwd=ROOT, text=True, start_new_session=True)
    started = time.monotonic()
    print(f"{label} child started: pid={process.pid}", flush=True)
    try:
        while True:
            try:
                returncode = process.wait(timeout=HEARTBEAT_SECONDS)
                return subprocess.CompletedProcess(values, returncode)
            except subprocess.TimeoutExpired:
                elapsed = round(time.monotonic() - started)
                timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
                print(
                    f"{timestamp} {label} still running: elapsed={elapsed}s; "
                    f"{heartbeat_stage(run_dir)}",
                    flush=True,
                )
    except KeyboardInterrupt:
        print(f"interrupt received; stopping the complete {label} process group", flush=True)
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=HEARTBEAT_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        return subprocess.CompletedProcess(values, 130)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN_DIR)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--provider",
        choices=("compatible", "anthropic", "deepseek"),
        default="compatible",
    )
    parser.add_argument(
        "--base-url",
        required=True,
        help="Anthropic-compatible API base URL.",
    )
    parser.add_argument("--model", required=True)
    parser.add_argument("--api-key-env", default="MODEL_API_KEY")
    parser.add_argument(
        "--effort",
        choices=("low", "medium", "high", "xhigh", "max"),
        default="max",
    )
    parser.add_argument("--max-budget-usd", type=float, default=10.0)
    parser.add_argument("--max-turns", type=int, default=20)
    parser.add_argument(
        "--max-tool-calls",
        type=int,
        help=(
            "Optional read-only tool-call cap. Omit it for the formal unbounded "
            "protocol; max-turns and read-only enforcement remain active."
        ),
    )
    parser.add_argument(
        "--skip-existing-failures",
        action="store_true",
        help=(
            "During the pending sweep, leave existing failed/worktree_failed "
            "batches unchanged and select only nonfailed unfinished batches."
        ),
    )
    parser.add_argument(
        "--failure-limit",
        type=int,
        default=10,
        help=(
            "Pause the full run after this many independent PR cases fail in "
            "one invocation. Multiple failed batches from one PR count once."
        ),
    )
    return parser.parse_args()


def command(
    run_dir: Path,
    workers: int,
    *,
    provider: str,
    base_url: str,
    model: str,
    api_key_env: str,
    effort: str,
    max_budget_usd: float,
    max_turns: int,
    max_tool_calls: int | None,
    failure_limit: int | None,
    resume: bool,
    pilot: bool = False,
    batch_ids: list[str] | None = None,
) -> list[str]:
    if pilot and batch_ids:
        raise ValueError("pilot and explicit batch IDs cannot be combined")
    values = [
        sys.executable,
        str(ROOT / "scripts/run_codeql_alert_adjudication.py"),
        "--output-dir",
        str(run_dir),
        "--workers",
        str(workers),
        "--provider",
        provider,
        "--base-url",
        base_url,
        "--model",
        model,
        "--api-key-env",
        api_key_env,
        "--effort",
        effort,
        "--max-budget-usd",
        str(max_budget_usd),
        "--max-turns",
        str(max_turns),
        "--execute",
    ]
    if max_tool_calls is not None:
        values.extend(["--max-tool-calls", str(max_tool_calls)])
    else:
        values.append("--allow-bounded-to-unbounded-amendment")
    if failure_limit is not None:
        values.extend(["--failure-limit", str(failure_limit)])
    if resume:
        values.append("--resume")
    if pilot:
        for batch_id in PILOT_BATCH_IDS:
            values.extend(["--batch-id", batch_id])
        values.extend(["--limit-batches", str(len(PILOT_BATCH_IDS))])
    elif batch_ids:
        for batch_id in batch_ids:
            values.extend(["--batch-id", batch_id])
    return values


def pilot_completed(run_dir: Path) -> bool:
    path = run_dir / "batch_status.csv"
    if not path.is_file():
        return False
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        statuses = {
            row.get("batch_id", ""): row.get("status", "")
            for row in csv.DictReader(handle)
        }
    return all(statuses.get(batch_id) == "completed" for batch_id in PILOT_BATCH_IDS)


def unfinished_batch_partition(run_dir: Path) -> tuple[list[str], list[str]]:
    """Return retryable unfinished IDs and explicitly deferred failure IDs."""

    path = run_dir / "batch_status.csv"
    if not path.is_file():
        return [], []
    retryable: list[str] = []
    deferred: list[str] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            batch_id = row.get("batch_id", "")
            status = row.get("status", "")
            if not batch_id or status == "completed":
                continue
            if status in {"failed", "worktree_failed"}:
                deferred.append(batch_id)
            else:
                retryable.append(batch_id)
    return retryable, deferred


def main() -> None:
    args = parse_args()
    run_dir = args.run_dir.expanduser().resolve()
    if args.workers < 1 or args.workers > 16:
        raise SystemExit("--workers must be between 1 and 16")
    command_options = {
        "provider": args.provider,
        "base_url": args.base_url,
        "model": args.model,
        "api_key_env": args.api_key_env,
        "effort": args.effort,
        "max_budget_usd": args.max_budget_usd,
        "max_turns": args.max_turns,
        "max_tool_calls": args.max_tool_calls,
    }
    if not pilot_completed(run_dir):
        pilot_command = command(
            run_dir,
            args.workers,
            resume=run_dir.exists(),
            pilot=True,
            failure_limit=args.failure_limit,
            **command_options,
        )
        print("+ " + " ".join(pilot_command), flush=True)
        pilot_result = run_with_heartbeat(
            pilot_command, run_dir=run_dir, label="pilot"
        )
        if pilot_result.returncode:
            raise SystemExit(pilot_result.returncode)
        if not pilot_completed(run_dir):
            print(
                "正式 pilot suite 未全部通过严格输出/证据校验；"
                "未启动剩余批次。检查失败 batch 的 failure.json 后重跑同一命令。",
                file=sys.stderr,
            )
            raise SystemExit(2)

    explicit_batch_ids: list[str] | None = None
    deferred_batch_ids: list[str] = []
    if args.skip_existing_failures:
        explicit_batch_ids, deferred_batch_ids = unfinished_batch_partition(run_dir)
        print(
            "pending sweep selection: "
            f"retryable={len(explicit_batch_ids)} "
            f"deferred_existing_failures={len(deferred_batch_ids)}",
            flush=True,
        )
        if not explicit_batch_ids and deferred_batch_ids:
            print(
                "没有剩余 pending batches；既有失败仍被保留，"
                "请修复后不带 --skip-existing-failures 单独重试。",
                file=sys.stderr,
            )
            raise SystemExit(2)

    if explicit_batch_ids is None or explicit_batch_ids:
        run_command = command(
            run_dir,
            args.workers,
            resume=True,
            failure_limit=args.failure_limit,
            batch_ids=explicit_batch_ids,
            **command_options,
        )
        if explicit_batch_ids is None:
            print("+ " + " ".join(run_command), flush=True)
        else:
            print(
                "+ run_codeql_alert_adjudication.py "
                f"[explicit retryable batches: {len(explicit_batch_ids)}; "
                f"existing failures deferred: {len(deferred_batch_ids)}]",
                flush=True,
            )
        result = run_with_heartbeat(run_command, run_dir=run_dir, label="formal run")
        if result.returncode:
            raise SystemExit(result.returncode)

    manifest_path = run_dir / "run_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise SystemExit(f"run manifest is missing or invalid: {exc}") from None
    if not manifest.get("complete"):
        print(
            "本轮仍有 pending/failed batches；检查 batch_status.csv 后重跑同一命令。",
            file=sys.stderr,
        )
        raise SystemExit(2)

    results = run_dir / "results"
    if not results.exists():
        summary_command = [
            sys.executable,
            str(ROOT / "scripts/summarize_codeql_alert_adjudication.py"),
            "--run-dir",
            str(run_dir),
        ]
        print("+ " + " ".join(summary_command), flush=True)
        summary = subprocess.run(summary_command, cwd=ROOT, check=False)
        if summary.returncode:
            raise SystemExit(summary.returncode)
    print(f"全量模型辅助判定完成：{results}")


if __name__ == "__main__":
    main()
