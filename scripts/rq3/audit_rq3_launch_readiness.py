#!/usr/bin/env python3
# RQ3 review experiment entry point.
"""Fail-closed launch audit for the frozen 267-case RQ3 experiment."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "data/experiments/security-and-quality/study_stars500/reports"
DEFAULT_PLAN = REPORTS / "rq3_formal_plan_20260727_v1"
DEFAULT_WORKTREES = REPORTS / "rq3_formal_worktrees_20260727_v1"
DEFAULT_PREFLIGHT = REPORTS / "rq3_formal_run_20260727_v1"
EXPECTED_CASE_N = 267
EXPECTED_POSITIVE_N = 187
EXPECTED_CONTROL_N = 80
EXPECTED_PRIMARY_REFERENCE_N = 420


class ReadinessError(RuntimeError):
    """Raised when frozen local evidence is incomplete or inconsistent."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="只读审计 RQ3 正式实验是否可以启动；不会调用模型"
    )
    parser.add_argument(
        "--cases", type=Path, default=DEFAULT_PLAN / "formal_cases.csv"
    )
    parser.add_argument(
        "--references",
        type=Path,
        default=DEFAULT_PLAN / "all_case_reference_alerts.csv",
    )
    parser.add_argument("--worktree-root", type=Path, default=DEFAULT_WORKTREES)
    parser.add_argument("--technical-preflight", type=Path, default=DEFAULT_PREFLIGHT)
    parser.add_argument(
        "--execution-config",
        type=Path,
        default=ROOT / "config/study/claude_code_review_execution.json",
    )
    parser.add_argument("--api-key-env", default="ANTHROPIC_AUTH_TOKEN")
    parser.add_argument("--planning-cost-per-review-usd", type=float, default=1.0)
    parser.add_argument("--authorized-run-budget-usd", type=float, default=267.0)
    parser.add_argument("--provider-side-remaining-budget-usd", type=float)
    parser.add_argument("--provider-balance-record", type=Path)
    parser.add_argument(
        "--budget-authorized",
        action="store_true",
        help="用户已明确授权 --authorized-run-budget-usd",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--require-launch-ready",
        action="store_true",
        help="外部门禁未满足时以退出码 2 结束",
    )
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except FileNotFoundError:
        raise ReadinessError(f"required file does not exist: {path}") from None
    return digest.hexdigest()


def read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ReadinessError(f"{label} does not exist: {path}") from None
    except json.JSONDecodeError as exc:
        raise ReadinessError(f"{label} is invalid JSON: {path}:{exc.lineno}") from None
    if not isinstance(value, dict):
        raise ReadinessError(f"{label} must be a JSON object: {path}")
    return value


def read_csv(path: Path, label: str) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            return list(csv.DictReader(stream))
    except FileNotFoundError:
        raise ReadinessError(f"{label} does not exist: {path}") from None


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReadinessError(message)


def audit_local_evidence(args: argparse.Namespace) -> dict[str, Any]:
    cases_path = args.cases.expanduser().resolve()
    references_path = args.references.expanduser().resolve()
    worktree_root = args.worktree_root.expanduser().resolve()
    preflight_root = args.technical_preflight.expanduser().resolve()
    config_path = args.execution_config.expanduser().resolve()

    cases = read_csv(cases_path, "formal cases")
    case_ids = [row.get("case_id", "").strip() for row in cases]
    require(len(cases) == EXPECTED_CASE_N, "formal cases must contain 267 rows")
    require(len(set(case_ids)) == EXPECTED_CASE_N, "formal case IDs must be unique")
    controls = Counter(row.get("case_control", "").strip().lower() for row in cases)
    require(
        controls == Counter({"positive": 187, "control": 80}),
        f"unexpected positive/control composition: {dict(controls)}",
    )
    cells = Counter(
        (
            row.get("case_control", "").strip().lower(),
            row.get("group", "").strip().lower(),
        )
        for row in cases
    )
    require(
        cells
        == Counter(
            {
                ("positive", "ai"): 95,
                ("positive", "human"): 92,
                ("control", "ai"): 40,
                ("control", "human"): 40,
            }
        ),
        f"unexpected formal benchmark cells: {dict(cells)}",
    )

    references = read_csv(references_path, "all-case references")
    primary_n = sum(
        row.get("quality_primary_reference", "").strip().lower() == "true"
        for row in references
    )
    require(
        primary_n == EXPECTED_PRIMARY_REFERENCE_N,
        f"expected 420 primary Quality references, found {primary_n}",
    )
    require(
        {row.get("case_id", "").strip() for row in references}.issubset(set(case_ids)),
        "reference table contains a case outside the formal benchmark",
    )

    worktree_manifest = read_json(worktree_root / "manifest.json", "worktree manifest")
    require(worktree_manifest.get("status") == "passed", "worktree build is not passed")
    require(
        worktree_manifest.get("built_case_n") == EXPECTED_CASE_N
        and worktree_manifest.get("failed_case_n") == 0,
        "worktree manifest must report 267 built and 0 failed",
    )
    require(
        worktree_manifest.get("inputs", {}).get("cases", {}).get("sha256")
        == sha256_file(cases_path),
        "worktree manifest case hash differs from frozen cases",
    )
    worktree_key_path = worktree_root / "worktree_key.csv"
    require(
        worktree_manifest.get("outputs", {}).get("worktree_key", {}).get("sha256")
        == sha256_file(worktree_key_path),
        "worktree key hash differs from worktree manifest",
    )
    worktree_rows = read_csv(worktree_key_path, "worktree key")
    require(
        {row.get("case_id", "").strip() for row in worktree_rows} == set(case_ids)
        and len(worktree_rows) == EXPECTED_CASE_N,
        "worktree inventory differs from formal cases",
    )

    run_manifest_path = preflight_root / "run_manifest.json"
    run_manifest = read_json(run_manifest_path, "technical preflight manifest")
    require(
        run_manifest.get("preflight_case_n") == EXPECTED_CASE_N,
        "technical preflight manifest is not 267/267 passed",
    )
    frozen = run_manifest.get("frozen_configuration", {})
    require(frozen.get("budget_fields_frozen") is False, "technical preflight spent budget")
    require(
        frozen.get("budget_policy")
        in {"technical_preflight_only", "user_explicitly_waived"},
        "technical preflight has an unknown budget policy",
    )
    require(
        frozen.get("cases", {}).get("sha256") == sha256_file(cases_path),
        "technical preflight case hash differs",
    )
    require(
        frozen.get("references", {}).get("sha256") == sha256_file(references_path),
        "technical preflight reference hash differs",
    )
    require(
        frozen.get("worktrees", {}).get("manifest_sha256")
        == sha256_file(worktree_root / "manifest.json")
        and frozen.get("worktrees", {}).get("key_sha256")
        == sha256_file(worktree_key_path),
        "technical preflight worktree hashes differ",
    )
    implementation = frozen.get("implementation", {})
    require(
        implementation.get("formal_runner_sha256")
        == sha256_file(ROOT / "scripts/rq3/run_rq3_formal_reviews.py"),
        "technical preflight used a different formal runner",
    )
    require(
        implementation.get("review_runner_sha256")
        == sha256_file(ROOT / "scripts/run_claude_code_review.py"),
        "technical preflight used a different review runner",
    )
    require(
        frozen.get("provider") == "deepseek"
        and frozen.get("base_url") == "https://api.deepseek.com/anthropic"
        and frozen.get("model") == "deepseek-v4-pro[1m]"
        and frozen.get("effort") == "max"
        and frozen.get("max_turns") == 10
        and frozen.get("repetitions") == 1
        and frozen.get("automatic_retries") == 0,
        "technical preflight reviewer configuration differs from the frozen protocol",
    )
    marker = read_json(preflight_root / "preflight_complete.json", "preflight marker")
    require(
        marker.get("status") == "passed" and marker.get("case_n") == EXPECTED_CASE_N,
        "technical preflight completion marker is invalid",
    )
    invocation_plan = read_csv(preflight_root / "invocation_plan.csv", "invocation plan")
    invocation_ids = {row.get("case_id", "").strip() for row in invocation_plan}
    require(
        len(invocation_plan) == EXPECTED_CASE_N and invocation_ids == set(case_ids),
        "technical invocation plan differs from formal cases",
    )
    preflight_dirs = {
        path.name
        for path in (preflight_root / "preflight").iterdir()
        if path.is_dir()
    }
    require(
        preflight_dirs
        == {row.get("invocation_id", "").strip() for row in invocation_plan},
        "per-case preflight directory inventory differs from invocation plan",
    )
    for row in invocation_plan:
        value = read_json(
            preflight_root
            / "preflight"
            / row["invocation_id"]
            / "preflight.json",
            f"preflight {row['case_id']}",
        )
        require(
            value.get("status") == "dry_run_preflight_passed",
            f"case preflight is not passed: {row['case_id']}",
        )

    config = read_json(config_path, "execution configuration")
    require(
        config.get("formal_benchmark", {}).get("quality_positive_case_n")
        == EXPECTED_POSITIVE_N
        and config.get("formal_benchmark", {}).get("quality_control_case_n")
        == EXPECTED_CONTROL_N
        and config.get("formal_benchmark", {}).get("repetitions") == 1,
        "machine-readable execution configuration differs from the formal benchmark",
    )
    return {
        "status": "passed",
        "case_n": EXPECTED_CASE_N,
        "positive_case_n": EXPECTED_POSITIVE_N,
        "control_case_n": EXPECTED_CONTROL_N,
        "primary_quality_reference_n": EXPECTED_PRIMARY_REFERENCE_N,
        "worktree_built_case_n": EXPECTED_CASE_N,
        "technical_preflight_case_n": EXPECTED_CASE_N,
        "technical_preflight_manifest_sha256": sha256_file(run_manifest_path),
        "formal_runner_sha256": implementation["formal_runner_sha256"],
        "review_runner_sha256": implementation["review_runner_sha256"],
        "budget_policy": frozen["budget_policy"],
    }


def evaluate_external_gates(args: argparse.Namespace) -> dict[str, Any]:
    planning = args.planning_cost_per_review_usd
    authorized = args.authorized_run_budget_usd
    provider_remaining = args.provider_side_remaining_budget_usd
    planned_total = planning * EXPECTED_CASE_N
    valid_numbers = (
        planning > 0
        and authorized > 0
        and (
            provider_remaining is None
            or provider_remaining > 0
        )
    )
    balance_record_ok = False
    balance_record_sha256 = None
    if args.provider_balance_record is not None:
        path = args.provider_balance_record.expanduser().resolve()
        record = read_json(path, "provider balance record")
        balance_record_ok = (
            record.get("endpoint") == "https://api.deepseek.com/user/balance"
            and record.get("request_type") == "read_only_balance_check"
            and record.get("model_invocation") is False
            and record.get("api_key_persisted") is False
            and record.get("is_available") is True
        )
        balance_record_sha256 = sha256_file(path)
    gates = {
        "api_key_set": bool(os.environ.get(args.api_key_env, "")),
        "budget_authorized": bool(args.budget_authorized),
        "budget_numbers_valid": valid_numbers,
        "planned_total_usd": planned_total,
        "authorized_budget_sufficient": authorized + 1e-9 >= planned_total,
        "provider_remaining_budget_supplied": provider_remaining is not None,
        "provider_remaining_budget_sufficient": (
            provider_remaining is not None
            and provider_remaining + 1e-9 >= planned_total
        ),
        "provider_balance_record_passed": balance_record_ok,
        "provider_balance_record_sha256": balance_record_sha256,
    }
    gates["passed"] = all(
        gates[key]
        for key in (
            "api_key_set",
            "budget_authorized",
            "budget_numbers_valid",
            "authorized_budget_sufficient",
            "provider_remaining_budget_supplied",
            "provider_remaining_budget_sufficient",
            "provider_balance_record_passed",
        )
    )
    return gates


def main() -> None:
    args = parse_args()
    try:
        local = audit_local_evidence(args)
        if local["budget_policy"] == "user_explicitly_waived":
            api_key_set = bool(os.environ.get(args.api_key_env, ""))
            external = {
                "api_key_set": api_key_set,
                "budget_policy": "user_explicitly_waived",
                "budget_gate_required": False,
                "passed": api_key_set,
            }
        else:
            external = evaluate_external_gates(args)
    except (ReadinessError, OSError) as exc:
        raise SystemExit(f"RQ3 launch readiness audit failed: {exc}") from None
    result = {
        "schema_version": "1.0.0",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": (
            "ready_for_formal_execution"
            if external["passed"]
            else "technical_ready_external_gates_pending"
        ),
        "model_invocation": False,
        "local_evidence": local,
        "external_gates": external,
    }
    rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        output = args.output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            raise SystemExit(f"refusing to overwrite readiness record: {output}")
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if args.require_launch_ready and not external["passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
