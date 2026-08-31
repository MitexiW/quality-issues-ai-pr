#!/usr/bin/env python3
# RQ3 review experiment entry point.
"""Preflight and execute the frozen whole-worktree RQ3 benchmark.

The command is safe by default: without ``--execute`` it performs all local
review preflights and never reads the API key.  A formal execution is
sequential, append-only, resumable, and permits at most one model attempt per
case.  DeepSeek's SDK budget is not treated as a provider-side hard cap.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import run_claude_code_review as review_runner


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STUDY_ROOT = (
    ROOT / "data/experiments/security-and-quality/study_stars500"
)
DEFAULT_PLAN_ROOT = DEFAULT_STUDY_ROOT / "reports/rq3_formal_plan_20260727_v1"
SCHEMA_VERSION = "1.0.0"
EXPECTED_CASE_N = 267
EXPECTED_POSITIVE_N = 187
EXPECTED_CONTROL_N = 80
PLAN_FIELDS = [
    "invocation_order",
    "invocation_id",
    "case_id",
    "group",
    "case_control",
    "repo_name",
    "pr_number",
    "task_type",
    "output_relpath",
]


class FormalReviewError(ValueError):
    """Raised when a formal run would violate the frozen protocol."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="离线预检或顺序执行冻结的 267-case RQ3 正式实验"
    )
    parser.add_argument(
        "--cases",
        default=str(DEFAULT_PLAN_ROOT / "formal_cases.csv"),
    )
    parser.add_argument(
        "--references",
        default=str(DEFAULT_PLAN_ROOT / "all_case_reference_alerts.csv"),
    )
    parser.add_argument("--worktree-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--provider", choices=("deepseek", "anthropic"), default="deepseek")
    parser.add_argument("--base-url", default="https://api.deepseek.com/anthropic")
    parser.add_argument("--api-key-env", default="ANTHROPIC_AUTH_TOKEN")
    parser.add_argument("--model", default="deepseek-v4-pro[1m]")
    parser.add_argument(
        "--effort",
        choices=("low", "medium", "high", "xhigh", "max"),
        default="max",
    )
    parser.add_argument("--max-budget-usd", type=float, required=True)
    parser.add_argument("--max-turns", type=int, required=True)
    parser.add_argument(
        "--prompt",
        default="config/study/claude_code_review_prompt.txt",
    )
    parser.add_argument(
        "--output-schema",
        default="config/study/llm_review_output_schema.json",
    )
    parser.add_argument(
        "--planning-cost-per-review-usd",
        type=float,
        help="预算门禁使用的每次调用保守成本，不是模型实际费用",
    )
    parser.add_argument(
        "--authorized-run-budget-usd",
        type=float,
        help="用户明确授权给本次 267-case run 的总预算",
    )
    parser.add_argument(
        "--provider-side-remaining-budget-usd",
        type=float,
        help="启动时已核验的 provider 可用余额/支出额度（USD 等值）",
    )
    parser.add_argument(
        "--provider-balance-record",
        help="scripts/rq3/check_deepseek_balance.py 生成的只读余额审计记录",
    )
    parser.add_argument(
        "--order-seed",
        default="rq3-formal-267-v1-20260727",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="继续同一冻结 run；已经 started 的 case 不会再次调用",
    )
    parser.add_argument(
        "--provider-budget-confirmed",
        action="store_true",
        help="确认已核验 provider 可用余额/支出额度；正式执行必需",
    )
    parser.add_argument(
        "--user-waived-budget-gate",
        action="store_true",
        help=(
            "记录用户明确决定不使用预算/余额门禁；与所有预算参数互斥，"
            "且每次执行仍最多启动 10 个 case"
        ),
    )
    parser.add_argument(
        "--execution-case-limit",
        type=int,
        default=10,
        help=(
            "每次 --execute 最多新启动的正式 case 数，默认 10；"
            "已 started 的 case 不会重试"
        ),
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="实际顺序调用模型；省略时仅做全部 case 的免费离线 preflight",
    )
    return parser.parse_args(argv)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except FileNotFoundError:
        raise FormalReviewError(f"required input does not exist: {path}") from None
    return digest.hexdigest()


def read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FormalReviewError(f"{label} does not exist: {path}") from None
    except json.JSONDecodeError as exc:
        raise FormalReviewError(
            f"{label} is invalid JSON: {path}:{exc.lineno}"
        ) from None
    if not isinstance(value, dict):
        raise FormalReviewError(f"{label} must be a JSON object")
    return value


def read_cases(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
    except FileNotFoundError:
        raise FormalReviewError(f"cases do not exist: {path}") from None
    if len(rows) != EXPECTED_CASE_N:
        raise FormalReviewError(
            f"formal cases must contain {EXPECTED_CASE_N} rows, found {len(rows)}"
        )
    case_ids = [row.get("case_id", "").strip() for row in rows]
    if any(not case_id for case_id in case_ids):
        raise FormalReviewError("every formal case must have a case_id")
    if len(set(case_ids)) != len(case_ids):
        raise FormalReviewError("formal case_id values must be unique")
    pr_keys = [
        (
            row.get("group", "").strip().lower(),
            row.get("repo_name", "").strip().lower(),
            row.get("pr_number", "").strip(),
        )
        for row in rows
    ]
    if len(set(pr_keys)) != len(pr_keys):
        raise FormalReviewError("formal cases must contain unique PRs")
    counts: dict[str, int] = {}
    for row in rows:
        kind = row.get("case_control", "").strip().lower()
        counts[kind] = counts.get(kind, 0) + 1
    if counts != {"positive": EXPECTED_POSITIVE_N, "control": EXPECTED_CONTROL_N}:
        raise FormalReviewError(
            "formal cases must contain exactly "
            f"{EXPECTED_POSITIVE_N} positives and {EXPECTED_CONTROL_N} controls; "
            f"found {counts}"
        )
    return rows


def validate_money(name: str, value: float) -> float:
    if not math.isfinite(value) or value <= 0:
        raise FormalReviewError(f"{name} must be finite and > 0")
    return value


def build_plan(rows: list[dict[str, str]], seed: str) -> list[dict[str, str]]:
    ordered = sorted(
        rows,
        key=lambda row: hashlib.sha256(
            f"{seed}\0{row['case_id'].strip()}".encode("utf-8")
        ).hexdigest(),
    )
    plan: list[dict[str, str]] = []
    for index, row in enumerate(ordered, start=1):
        case_id = row["case_id"].strip()
        invocation_id = f"rq3-{index:03d}-{case_id}"
        plan.append(
            {
                "invocation_order": str(index),
                "invocation_id": invocation_id,
                "case_id": case_id,
                "group": row.get("group", "").strip().lower(),
                "case_control": row.get("case_control", "").strip().lower(),
                "repo_name": row.get("repo_name", "").strip(),
                "pr_number": row.get("pr_number", "").strip(),
                "task_type": row.get("task_type", "").strip(),
                "output_relpath": f"invocations/{invocation_id}",
            }
        )
    return plan


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=PLAN_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def append_event(path: Path, value: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
        stream.flush()


def read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise FormalReviewError(
                    f"ledger is invalid JSONL at line {line_number}: {exc}"
                ) from None
            if not isinstance(value, dict):
                raise FormalReviewError(
                    f"ledger line {line_number} must be a JSON object"
                )
            events.append(value)
    return events


def load_worktree_inventory(worktree_root: Path) -> set[str]:
    manifest = read_json_object(worktree_root / "manifest.json", "worktree manifest")
    if (
        manifest.get("status") != "passed"
        or manifest.get("built_case_n") != EXPECTED_CASE_N
        or manifest.get("failed_case_n") != 0
    ):
        raise FormalReviewError(
            "worktree manifest must be passed with 267 built and 0 failed cases"
        )
    key_path = worktree_root / "worktree_key.csv"
    try:
        with key_path.open(newline="", encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
    except FileNotFoundError:
        raise FormalReviewError(f"worktree key does not exist: {key_path}") from None
    case_ids = {row.get("case_id", "").strip() for row in rows}
    if len(rows) != EXPECTED_CASE_N or len(case_ids) != EXPECTED_CASE_N:
        raise FormalReviewError("worktree key must contain 267 unique cases")
    return case_ids


def child_command(
    *,
    args: argparse.Namespace,
    worktree_root: Path,
    case_id: str,
    output_dir: Path,
    execute: bool,
) -> list[str]:
    command = [
        sys.executable,
        str(ROOT / "scripts/run_claude_code_review.py"),
        "--worktree-root",
        str(worktree_root),
        "--case-id",
        case_id,
        "--provider",
        args.provider,
        "--base-url",
        args.base_url,
        "--api-key-env",
        args.api_key_env,
        "--model",
        args.model,
        "--effort",
        args.effort,
        "--max-budget-usd",
        str(args.max_budget_usd),
        "--max-turns",
        str(args.max_turns),
        "--prompt",
        str(Path(args.prompt).expanduser().resolve()),
        "--output-schema",
        str(Path(args.output_schema).expanduser().resolve()),
        "--output-dir",
        str(output_dir),
    ]
    if execute:
        command.append("--execute")
    return command


def frozen_configuration(
    args: argparse.Namespace,
    cases_path: Path,
    references_path: Path,
    worktree_root: Path,
) -> dict[str, Any]:
    budget_values = (
        args.planning_cost_per_review_usd,
        args.authorized_run_budget_usd,
        args.provider_side_remaining_budget_usd,
    )
    if args.user_waived_budget_gate:
        if any(value is not None for value in budget_values):
            raise FormalReviewError(
                "--user-waived-budget-gate is mutually exclusive with budget fields"
            )
        if args.provider_balance_record is not None:
            raise FormalReviewError(
                "--user-waived-budget-gate is mutually exclusive with "
                "--provider-balance-record"
            )
        planned_total = None
        balance_record = None
        budget_policy = "user_explicitly_waived"
    elif any(value is None for value in budget_values):
        if not all(value is None for value in budget_values):
            raise FormalReviewError(
                "budget fields must either all be provided or all be omitted"
            )
        planned_total = None
        if args.provider_balance_record is not None:
            raise FormalReviewError(
                "provider balance record requires all three frozen budget fields"
            )
        balance_record = None
        budget_policy = "technical_preflight_only"
    else:
        planning_cost = float(args.planning_cost_per_review_usd)
        authorized_budget = float(args.authorized_run_budget_usd)
        provider_budget = float(args.provider_side_remaining_budget_usd)
        planned_total = EXPECTED_CASE_N * planning_cost
        if authorized_budget + 1e-9 < planned_total:
            raise FormalReviewError(
                "authorized run budget is below the conservative planned total: "
                f"{authorized_budget:.6f} < {planned_total:.6f}"
            )
        if provider_budget + 1e-9 < planned_total:
            raise FormalReviewError(
                "provider-side remaining budget is below the conservative planned total: "
                f"{provider_budget:.6f} < {planned_total:.6f}"
            )
        if args.provider_balance_record is None:
            raise FormalReviewError(
                "frozen budget fields require --provider-balance-record"
            )
        balance_path = Path(args.provider_balance_record).expanduser().resolve()
        balance_value = read_json_object(balance_path, "provider balance record")
        if (
            balance_value.get("endpoint")
            != "https://api.deepseek.com/user/balance"
            or balance_value.get("request_type") != "read_only_balance_check"
            or balance_value.get("model_invocation") is not False
            or balance_value.get("api_key_persisted") is not False
            or balance_value.get("is_available") is not True
        ):
            raise FormalReviewError(
                "provider balance record is not an available sanitized DeepSeek record"
            )
        balance_record = {
            "path": str(balance_path),
            "sha256": sha256_file(balance_path),
            "checked_at_utc": balance_value.get("checked_at_utc"),
            "is_available": True,
            "balance_infos": balance_value.get("balance_infos"),
        }
        budget_policy = "enforced"
    prompt_path = Path(args.prompt).expanduser().resolve()
    schema_path = Path(args.output_schema).expanduser().resolve()
    review_runner_path = ROOT / "scripts/run_claude_code_review.py"
    formal_runner_path = Path(__file__).resolve()
    return {
        "cases": {
            "path": str(cases_path),
            "sha256": sha256_file(cases_path),
        },
        "references": {
            "path": str(references_path),
            "sha256": sha256_file(references_path),
        },
        "worktrees": {
            "path": str(worktree_root),
            "manifest_sha256": sha256_file(worktree_root / "manifest.json"),
            "key_sha256": sha256_file(worktree_root / "worktree_key.csv"),
        },
        "prompt": {
            "path": str(prompt_path),
            "sha256": sha256_file(prompt_path),
        },
        "output_schema": {
            "path": str(schema_path),
            "sha256": sha256_file(schema_path),
        },
        "implementation": {
            "review_runner_sha256": sha256_file(review_runner_path),
            "formal_runner_sha256": sha256_file(formal_runner_path),
        },
        "provider": args.provider,
        "base_url": args.base_url,
        "api_key_env": args.api_key_env,
        "model": args.model,
        "effort": args.effort,
        "sdk_max_budget_usd": args.max_budget_usd,
        "max_turns": args.max_turns,
        "budget_fields_frozen": planned_total is not None,
        "budget_policy": budget_policy,
        "planning_cost_per_review_usd": args.planning_cost_per_review_usd,
        "planned_total_cost_envelope_usd": planned_total,
        "authorized_run_budget_usd": args.authorized_run_budget_usd,
        "provider_side_remaining_budget_usd_at_freeze": (
            args.provider_side_remaining_budget_usd
        ),
        "provider_balance_record": balance_record,
        "order_seed": args.order_seed,
        "repetitions": 1,
        "automatic_retries": 0,
        "finding_dependent_retry": False,
    }


def validate_resume(
    output_dir: Path,
    configuration: dict[str, Any],
    plan: list[dict[str, str]],
) -> dict[str, Any]:
    manifest = read_json_object(output_dir / "run_manifest.json", "run manifest")
    if manifest.get("frozen_configuration") != configuration:
        raise FormalReviewError("resume configuration differs from frozen run")
    if manifest.get("invocation_plan_sha256") != sha256_bytes(canonical_bytes(plan)):
        raise FormalReviewError("resume invocation plan differs from frozen run")
    return manifest


def run_preflights(
    *,
    args: argparse.Namespace,
    output_dir: Path,
    worktree_root: Path,
    plan: list[dict[str, str]],
) -> None:
    preflight_root = output_dir / "preflight"
    preflight_root.mkdir(exist_ok=True)
    for index, row in enumerate(plan, start=1):
        destination = preflight_root / row["invocation_id"]
        if destination.exists():
            value = read_json_object(destination / "preflight.json", "case preflight")
            if value.get("status") != "dry_run_preflight_passed":
                raise FormalReviewError(
                    f"existing preflight is not passed: {row['case_id']}"
                )
            continue
        result = subprocess.run(
            child_command(
                args=args,
                worktree_root=worktree_root,
                case_id=row["case_id"],
                output_dir=destination,
                execute=False,
            ),
            check=False,
        )
        if result.returncode != 0:
            raise FormalReviewError(
                f"offline review preflight failed for {row['case_id']}"
            )
        print(f"[preflight {index}/{len(plan)}] {row['case_id']}: passed", flush=True)


def terminal_case_ids(events: list[dict[str, Any]]) -> set[str]:
    # A started event is intentionally terminal for automatic resume: after a
    # crash we cannot prove whether the provider billed or returned a response.
    return {
        str(event.get("case_id", ""))
        for event in events
        if event.get("event") == "started" and event.get("case_id")
    }


def is_invalid_model_output_failure(failure: dict[str, Any]) -> bool:
    error_type = str(failure.get("error_type", ""))
    message = str(failure.get("error_message", ""))
    if error_type == "InvalidModelOutputError":
        return True
    # Compatibility for invocation 27, produced immediately before the runner
    # introduced the dedicated exception type.
    return (
        error_type == "ClaudeReviewError"
        and message
        == (
            "DeepSeek inline fallback must contain exactly one fenced JSON "
            "block and no other fenced blocks; no repair was applied"
        )
    )


def promote_invalid_model_output(
    *,
    destination: Path,
    worktree_root: Path,
    case_id: str,
) -> dict[str, Any]:
    """Record a successful call with an invalid response without parsing prose."""
    failure_path = destination / "failure.json"
    preflight_path = destination / "preflight.json"
    metadata_path = destination / "result_metadata.json"
    failure = read_json_object(failure_path, "invalid-output failure")
    preflight = read_json_object(preflight_path, "invalid-output preflight")
    metadata = read_json_object(metadata_path, "invalid-output metadata")
    if not is_invalid_model_output_failure(failure):
        raise FormalReviewError("failure is not an invalid model output")
    if (
        preflight.get("case_id") != case_id
        or failure.get("preflight_sha256") != preflight.get("preflight_sha256")
        or metadata.get("preflight_sha256") != preflight.get("preflight_sha256")
    ):
        raise FormalReviewError("invalid-output artifact provenance differs")
    if metadata.get("is_error") is not False or metadata.get("result_subtype") != "success":
        raise FormalReviewError("invalid output did not come from a successful model call")
    retained = failure.get("retained_artifacts", {})
    for name, record in retained.items():
        if (
            not isinstance(record, dict)
            or record.get("path") != name
            or sha256_file(destination / name) != record.get("sha256")
        ):
            raise FormalReviewError(f"invalid-output retained hash differs: {name}")

    worktree_row, repo = review_runner.load_case(worktree_root, case_id)
    post_audit = review_runner.audit_repo(repo, worktree_row)
    if review_runner.worktree_identity_projection(
        post_audit
    ) != review_runner.worktree_identity_projection(preflight["worktree"]):
        raise FormalReviewError("invalid-output review worktree changed")

    invalid_record = {
        "schema_version": SCHEMA_VERSION,
        "status": "invalid_model_output",
        "recorded_at_utc": now_utc(),
        "case_id": case_id,
        "response_parsed": False,
        "prose_semantics_interpreted": False,
        "automatic_retry": False,
        "scoring_policy": "zero_recovery_and_report_invalid_output_separately",
        "error_type": failure.get("error_type"),
        "error_message": failure.get("error_message"),
        "result_text_sha256": metadata.get("result_text_sha256"),
        "source_failure": {
            "path": failure_path.name,
            "sha256": sha256_file(failure_path),
        },
    }
    invalid_path = destination / "invalid_model_output.json"
    if invalid_path.exists():
        raise FormalReviewError("invalid model output was already promoted")
    write_json(invalid_path, invalid_record)

    execution = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "model_output_valid": False,
        "result_use": "formal_rq3",
        "eligible_for_rq3_performance_estimates": True,
        "completed_at_utc": now_utc(),
        "preflight_sha256": preflight["preflight_sha256"],
        "latency_ms": metadata.get("latency_ms"),
        "result_subtype": metadata.get("result_subtype"),
        "num_turns": metadata.get("num_turns"),
        "total_cost_usd": metadata.get("total_cost_usd"),
        "usage": metadata.get("usage"),
        "model_usage": metadata.get("model_usage"),
        "response_source": "invalid_model_output",
        "scoring_policy": "zero_recovery_and_report_invalid_output_separately",
        "invalid_model_output": {
            "path": invalid_path.name,
            "sha256": sha256_file(invalid_path),
        },
        "raw_sdk_messages": {
            "path": "raw_sdk_messages.jsonl",
            "sha256": sha256_file(destination / "raw_sdk_messages.jsonl"),
        },
        "raw_sdk_transcript": {
            "path": "raw_sdk_transcript.json",
            "sha256": sha256_file(destination / "raw_sdk_transcript.json"),
        },
        "result_metadata": {
            "path": metadata_path.name,
            "sha256": sha256_file(metadata_path),
        },
        "post_review_worktree_audit": post_audit,
    }
    execution["execution_sha256"] = sha256_bytes(canonical_bytes(execution))
    write_json(destination / "execution.json", execution)
    return execution


def execute_reviews(
    *,
    args: argparse.Namespace,
    output_dir: Path,
    worktree_root: Path,
    plan: list[dict[str, str]],
    manifest: dict[str, Any],
) -> None:
    if not args.user_waived_budget_gate and not args.provider_budget_confirmed:
        raise FormalReviewError(
            "--execute requires --provider-budget-confirmed"
        )
    if not (output_dir / "preflight_complete.json").is_file():
        raise FormalReviewError("all-case offline preflight is not complete")
    ledger_path = output_dir / "attempts.jsonl"
    events = read_events(ledger_path)
    attempted = terminal_case_ids(events)
    completed = {
        str(event["case_id"])
        for event in events
        if event.get("event") == "completed"
    }
    failed_events = {
        str(event["case_id"])
        for event in events
        if event.get("event") == "failed"
    }
    failed = failed_events - completed
    new_attempt_n = 0
    invocations_root = output_dir / "invocations"
    invocations_root.mkdir(exist_ok=True)
    for row in plan:
        case_id = row["case_id"]
        if case_id in attempted:
            continue
        next_attempt_n = len(attempted) + 1
        if args.user_waived_budget_gate:
            reserved = None
        else:
            reserved = next_attempt_n * args.planning_cost_per_review_usd
            if reserved > args.authorized_run_budget_usd + 1e-9:
                manifest["status"] = "stopped_by_run_budget"
                manifest["updated_at_utc"] = now_utc()
                manifest["attempted_case_n"] = len(attempted)
                write_json(output_dir / "run_manifest.json", manifest)
                raise FormalReviewError(
                    "run-level conservative budget gate stopped execution"
                )
        destination = output_dir / row["output_relpath"]
        if destination.exists():
            raise FormalReviewError(
                f"untracked invocation output already exists: {destination}"
            )
        started = {
            "schema_version": SCHEMA_VERSION,
            "event": "started",
            "created_at_utc": now_utc(),
            "invocation_id": row["invocation_id"],
            "case_id": case_id,
            "reserved_run_budget_usd": reserved,
            "budget_policy": (
                "user_explicitly_waived"
                if args.user_waived_budget_gate
                else "enforced"
            ),
        }
        append_event(ledger_path, started)
        attempted.add(case_id)
        result = subprocess.run(
            child_command(
                args=args,
                worktree_root=worktree_root,
                case_id=case_id,
                output_dir=destination,
                execute=True,
            ),
            check=False,
        )
        execution_path = destination / "execution.json"
        failure_path = destination / "failure.json"
        model_output_valid = True
        if result.returncode == 0 and execution_path.is_file():
            execution = read_json_object(execution_path, "case execution")
            event = "completed"
            cost = execution.get("total_cost_usd", execution.get("cost_usd"))
        elif failure_path.is_file() and is_invalid_model_output_failure(
            read_json_object(failure_path, "case failure")
        ):
            execution = promote_invalid_model_output(
                destination=destination,
                worktree_root=worktree_root,
                case_id=case_id,
            )
            event = "completed"
            model_output_valid = False
            cost = execution.get("total_cost_usd")
        else:
            event = "failed"
            cost = None
        append_event(
            ledger_path,
            {
                "schema_version": SCHEMA_VERSION,
                "event": event,
                "created_at_utc": now_utc(),
                "invocation_id": row["invocation_id"],
                "case_id": case_id,
                "returncode": result.returncode,
                "sdk_reported_cost_usd": cost,
                "provider_invoice_cost_available": False,
                "execution_present": execution_path.is_file(),
                "failure_present": failure_path.is_file(),
                "model_output_valid": model_output_valid if event == "completed" else None,
            },
        )
        if event == "completed":
            completed.add(case_id)
        else:
            failed.add(case_id)
        new_attempt_n += 1
        display_event = (
            "completed_invalid_model_output"
            if event == "completed" and not model_output_valid
            else event
        )
        print(
            f"[execute {len(attempted)}/{len(plan)}] {case_id}: {display_event}",
            flush=True,
        )
        if event == "failed":
            manifest.update(
                {
                    "status": "paused_after_case_failure",
                    "updated_at_utc": now_utc(),
                    "attempted_case_n": len(attempted),
                    "completed_case_n": len(completed),
                    "failed_case_n": len(failed),
                    "last_failed_case_id": case_id,
                    "execution_case_limit_for_last_resume": (
                        args.execution_case_limit
                    ),
                }
            )
            write_json(output_dir / "run_manifest.json", manifest)
            return
        if (
            new_attempt_n >= args.execution_case_limit
            and len(attempted) < len(plan)
        ):
            manifest.update(
                {
                    "status": "paused_at_operator_checkpoint",
                    "updated_at_utc": now_utc(),
                    "attempted_case_n": len(attempted),
                    "completed_case_n": len(completed),
                    "failed_case_n": len(failed),
                    "execution_case_limit_for_last_resume": (
                        args.execution_case_limit
                    ),
                }
            )
            write_json(output_dir / "run_manifest.json", manifest)
            return
    final_events = read_events(ledger_path)
    completed = {
        str(event["case_id"])
        for event in final_events
        if event.get("event") == "completed"
    }
    failed_events = {
        str(event["case_id"])
        for event in final_events
        if event.get("event") == "failed"
    }
    failed = failed_events - completed
    started = terminal_case_ids(final_events)
    indeterminate = started - completed - failed
    manifest.update(
        {
            "status": (
                "execution_complete"
                if len(started) == len(plan) and not indeterminate
                else "execution_incomplete"
            ),
            "updated_at_utc": now_utc(),
            "attempted_case_n": len(started),
            "completed_case_n": len(completed),
            "failed_case_n": len(failed),
            "indeterminate_case_n": len(indeterminate),
            "indeterminate_case_ids": sorted(indeterminate),
        }
    )
    write_json(output_dir / "run_manifest.json", manifest)


def orchestrate(args: argparse.Namespace) -> dict[str, Any]:
    validate_money("max-budget-usd", float(args.max_budget_usd))
    for name in (
        "planning_cost_per_review_usd",
        "authorized_run_budget_usd",
        "provider_side_remaining_budget_usd",
    ):
        value = getattr(args, name)
        if value is not None:
            validate_money(name.replace("_", "-"), float(value))
    if args.max_turns < 1:
        raise FormalReviewError("max-turns must be >= 1")
    if not (1 <= args.execution_case_limit <= EXPECTED_CASE_N):
        raise FormalReviewError(
            f"execution-case-limit must be between 1 and {EXPECTED_CASE_N}"
        )
    if args.execute and not args.resume:
        raise FormalReviewError(
            "formal execution must resume a completed frozen preflight run"
        )
    if (
        args.execute
        and not args.user_waived_budget_gate
        and not args.provider_budget_confirmed
    ):
        raise FormalReviewError("--execute requires --provider-budget-confirmed")
    if args.execute and not os.environ.get(args.api_key_env, ""):
        raise FormalReviewError(
            f"--execute requires non-empty environment variable {args.api_key_env}"
        )
    if (
        args.execute
        and not args.user_waived_budget_gate
        and any(
            getattr(args, name) is None
            for name in (
                "planning_cost_per_review_usd",
                "authorized_run_budget_usd",
                "provider_side_remaining_budget_usd",
            )
        )
    ):
        raise FormalReviewError(
            "formal execution requires all three frozen budget fields"
        )
    if args.user_waived_budget_gate and args.execution_case_limit > 10:
        raise FormalReviewError(
            "waived budget mode limits each --execute command to at most 10 cases"
        )
    cases_path = Path(args.cases).expanduser().resolve()
    references_path = Path(args.references).expanduser().resolve()
    worktree_root = Path(args.worktree_root).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    rows = read_cases(cases_path)
    inventory = load_worktree_inventory(worktree_root)
    if inventory != {row["case_id"].strip() for row in rows}:
        raise FormalReviewError("formal case inventory differs from worktree inventory")
    plan = build_plan(rows, args.order_seed)
    configuration = frozen_configuration(
        args, cases_path, references_path, worktree_root
    )
    if args.resume:
        if not output_dir.is_dir():
            raise FormalReviewError(f"resume output does not exist: {output_dir}")
        manifest = validate_resume(output_dir, configuration, plan)
    else:
        if output_dir.exists():
            raise FormalReviewError(f"output directory already exists: {output_dir}")
        output_dir.mkdir(parents=True)
        write_csv(output_dir / "invocation_plan.csv", plan)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "status": "preflight_in_progress",
            "created_at_utc": now_utc(),
            "updated_at_utc": now_utc(),
            "case_n": EXPECTED_CASE_N,
            "positive_case_n": EXPECTED_POSITIVE_N,
            "control_case_n": EXPECTED_CONTROL_N,
            "frozen_configuration": configuration,
            "invocation_plan_sha256": sha256_bytes(canonical_bytes(plan)),
            "provider_budget_confirmed_at_execution": False,
            "user_waived_budget_gate": bool(args.user_waived_budget_gate),
        }
        write_json(output_dir / "run_manifest.json", manifest)
    if not args.execute:
        run_preflights(
            args=args,
            output_dir=output_dir,
            worktree_root=worktree_root,
            plan=plan,
        )
        marker = {
            "schema_version": SCHEMA_VERSION,
            "status": "passed",
            "created_at_utc": now_utc(),
            "case_n": EXPECTED_CASE_N,
        }
        marker["sha256"] = sha256_bytes(canonical_bytes(marker))
        write_json(output_dir / "preflight_complete.json", marker)
        manifest.update(
            {
                "status": "preflight_passed",
                "updated_at_utc": now_utc(),
                "preflight_case_n": EXPECTED_CASE_N,
            }
        )
        write_json(output_dir / "run_manifest.json", manifest)
        return manifest
    manifest["provider_budget_confirmed_at_execution"] = bool(
        args.provider_budget_confirmed
    )
    if args.provider_budget_confirmed:
        manifest["provider_budget_confirmed_at_utc"] = now_utc()
    manifest["user_waived_budget_gate"] = bool(args.user_waived_budget_gate)
    if args.user_waived_budget_gate:
        manifest["budget_gate_waived_at_utc"] = now_utc()
    manifest["status"] = "execution_in_progress"
    manifest["updated_at_utc"] = now_utc()
    write_json(output_dir / "run_manifest.json", manifest)
    execute_reviews(
        args=args,
        output_dir=output_dir,
        worktree_root=worktree_root,
        plan=plan,
        manifest=manifest,
    )
    return manifest


def main() -> None:
    args = parse_args()
    try:
        result = orchestrate(args)
    except (FormalReviewError, OSError) as exc:
        raise SystemExit(f"RQ3 formal review error: {exc}") from None
    if args.execute:
        print(
            "RQ3 formal execution finished: "
            f"status={result.get('status')}, output={Path(args.output_dir).resolve()}"
        )
    else:
        print(
            "RQ3 formal offline preflight passed for 267 cases; "
            "no API key was read and no model call was made"
        )


if __name__ == "__main__":
    main()
