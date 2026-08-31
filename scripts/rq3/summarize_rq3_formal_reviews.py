#!/usr/bin/env python3
# RQ3 review experiment entry point.
"""Match completed formal RQ3 reviews to hidden CodeQL references.

The same model output is evaluated against Quality primary, strict, and broad
reference tiers and against secondary Security references.  No model call is
made and no semantic repair or post-hoc rematching is performed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .summarize_claude_review_example import (
        ACCEPTED_RESPONSE_SOURCES,
        ExampleSummaryError,
        match_findings,
        read_json,
        reference_id,
        sha256_file,
    )
except ImportError:  # Direct CLI execution loads sibling modules by name.
    from summarize_claude_review_example import (
        ACCEPTED_RESPONSE_SOURCES,
        ExampleSummaryError,
        match_findings,
        read_json,
        reference_id,
        sha256_file,
    )


SCHEMA_VERSION = "1.0.0"
MATCHED_STATUSES = {
    "compatible_location_recovery",
    "off_target_reference_recovery",
}
UNMATCHED_STATUSES = {
    "unmatched_to_codeql",
    "ambiguous_location_candidate",
    "invalid_or_unlocalized_report",
}
CASE_FIELDS = [
    "case_id",
    "group",
    "case_control",
    "task_type",
    "language",
    "repo_name",
    "pr_number",
    "execution_status",
    "model_output_valid",
    "invalid_model_output_reason",
    "review_finding_n",
    "matched_finding_n",
    "unmatched_report_n",
    "outside_pending_diff_n",
    "nonexistent_file_n",
    "quality_primary_reference_n",
    "quality_primary_recovered_n",
    "quality_primary_recovery_rate",
    "quality_primary_pr_hit",
    "quality_strict_reference_n",
    "quality_strict_recovered_n",
    "quality_strict_recovery_rate",
    "quality_broad_reference_n",
    "quality_broad_recovered_n",
    "quality_broad_recovery_rate",
    "security_reference_n",
    "security_recovered_n",
    "security_recovery_rate",
    "security_pr_hit",
    "latency_ms",
    "total_cost_usd",
]
REFERENCE_FIELDS = [
    "case_id",
    "reference_id",
    "reference_family",
    "reference_role",
    "quality_primary_reference",
    "quality_strict_reference",
    "quality_broad_reference",
    "rule_id",
    "quality_category",
    "cwe",
    "file_path",
    "start_line",
    "recovered",
]


class FormalSummaryError(ValueError):
    """Raised when formal outputs are incomplete or inconsistent."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="汇总正式 RQ3 whole-worktree review 并匹配隐藏 CodeQL references"
    )
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--references", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="仅用于技术失败审计；正式主结果应要求全部 case 完成",
    )
    return parser.parse_args(argv)


def read_csv(path: Path, label: str) -> list[dict[str, str]]:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            break
        except OverflowError:
            limit //= 10
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            return list(csv.DictReader(stream))
    except FileNotFoundError:
        raise FormalSummaryError(f"{label} does not exist: {path}") from None


def truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def safe_float(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed


def safe_ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def validate_review_artifacts(
    invocation_dir: Path,
    case_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    execution_path = invocation_dir / "execution.json"
    preflight_path = invocation_dir / "preflight.json"
    execution = read_json(execution_path, "execution")
    preflight = read_json(preflight_path, "preflight")
    if execution.get("status") != "completed":
        raise FormalSummaryError(f"{case_id}: execution status is not completed")
    if preflight.get("case_id") != case_id:
        raise FormalSummaryError(f"{case_id}: preflight case mismatch")
    if execution.get("model_output_valid") is False:
        if execution.get("response_source") != "invalid_model_output":
            raise FormalSummaryError(
                f"{case_id}: invalid output has an unexpected response source"
            )
        recorded = execution.get("invalid_model_output", {})
        invalid_path = invocation_dir / str(recorded.get("path", ""))
        if (
            recorded.get("path") != "invalid_model_output.json"
            or recorded.get("sha256") != sha256_file(invalid_path)
        ):
            raise FormalSummaryError(
                f"{case_id}: invalid-output provenance hash mismatch"
            )
        invalid = read_json(invalid_path, "invalid model output")
        if (
            invalid.get("status") != "invalid_model_output"
            or invalid.get("response_parsed") is not False
            or invalid.get("prose_semantics_interpreted") is not False
        ):
            raise FormalSummaryError(
                f"{case_id}: invalid-output classification is inconsistent"
            )
        return execution, []

    response_path = invocation_dir / "review_response.json"
    response = read_json(response_path, "review response")
    if execution.get("response_source") not in ACCEPTED_RESPONSE_SOURCES:
        raise FormalSummaryError(f"{case_id}: response source is not frozen")
    recorded = execution.get("review_response", {})
    if recorded.get("sha256") != sha256_file(response_path):
        raise FormalSummaryError(f"{case_id}: response hash mismatch")
    if set(response) != {"level", "findings"} or not isinstance(
        response.get("findings"), list
    ):
        raise FormalSummaryError(f"{case_id}: native response schema is invalid")
    return execution, response["findings"]


def reference_tiers(row: dict[str, str]) -> set[str]:
    tiers: set[str] = set()
    family = row.get("reference_family", "").strip().lower()
    if family == "quality":
        if truthy(row.get("quality_primary_reference")):
            tiers.add("quality_primary")
        if truthy(row.get("quality_strict_reference")):
            tiers.add("quality_strict")
        if truthy(row.get("quality_broad_reference")):
            tiers.add("quality_broad")
    elif family == "security":
        tiers.add("security")
    return tiers


def summarize_completed_case(
    *,
    case: dict[str, str],
    references: list[dict[str, str]],
    findings: list[dict[str, Any]],
    execution: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    case_id = case["case_id"]
    ids = {reference_id(row): row for row in references}
    if len(ids) != len(references):
        raise FormalSummaryError(f"{case_id}: duplicate hidden reference identity")
    matches = match_findings(case_id, findings, references)
    recovered_ids = {
        row["silver_finding_id"]
        for row in matches
        if row["match_status"] in MATCHED_STATUSES
        and row["silver_finding_id"] in ids
    }
    tier_ids: dict[str, set[str]] = defaultdict(set)
    for identity, reference in ids.items():
        for tier in reference_tiers(reference):
            tier_ids[tier].add(identity)
    case_row: dict[str, Any] = {
        "case_id": case_id,
        "group": case.get("group", ""),
        "case_control": case.get("case_control", ""),
        "task_type": case.get("task_type", ""),
        "language": case.get("language", ""),
        "repo_name": case.get("repo_name", ""),
        "pr_number": case.get("pr_number", ""),
        "execution_status": "completed",
        "model_output_valid": int(execution.get("model_output_valid") is not False),
        "invalid_model_output_reason": (
            ""
            if execution.get("model_output_valid") is not False
            else "response_contract_violation"
        ),
        "review_finding_n": len(matches),
        "matched_finding_n": sum(
            row["match_status"] in MATCHED_STATUSES for row in matches
        ),
        "unmatched_report_n": sum(
            row["match_status"] in UNMATCHED_STATUSES for row in matches
        ),
        "outside_pending_diff_n": execution.get(
            "finding_scope_audit", {}
        ).get("outside_pending_diff_n", 0),
        "nonexistent_file_n": execution.get(
            "finding_scope_audit", {}
        ).get("nonexistent_file_n", 0),
        "latency_ms": execution.get("latency_ms", ""),
        "total_cost_usd": execution.get("total_cost_usd", ""),
    }
    for tier in (
        "quality_primary",
        "quality_strict",
        "quality_broad",
        "security",
    ):
        denominator = tier_ids[tier]
        recovered = denominator & recovered_ids
        case_row[f"{tier}_reference_n"] = len(denominator)
        case_row[f"{tier}_recovered_n"] = len(recovered)
        case_row[f"{tier}_recovery_rate"] = safe_ratio(
            len(recovered), len(denominator)
        )
        if tier in {"quality_primary", "security"}:
            case_row[f"{tier}_pr_hit"] = int(bool(recovered))
    reference_rows = []
    for identity, reference in sorted(ids.items()):
        reference_rows.append(
            {
                "case_id": case_id,
                "reference_id": identity,
                "reference_family": reference.get("reference_family", ""),
                "reference_role": reference.get("reference_role", ""),
                "quality_primary_reference": reference.get(
                    "quality_primary_reference", ""
                ),
                "quality_strict_reference": reference.get(
                    "quality_strict_reference", ""
                ),
                "quality_broad_reference": reference.get(
                    "quality_broad_reference", ""
                ),
                "rule_id": reference.get("rule_id", ""),
                "quality_category": reference.get("quality_category", ""),
                "cwe": reference.get("cwe", ""),
                "file_path": reference.get("file_path", ""),
                "start_line": reference.get("start_line", ""),
                "recovered": int(identity in recovered_ids),
            }
        )
    return case_row, matches, reference_rows


def aggregate(case_rows: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    completed = [row for row in case_rows if row["execution_status"] == "completed"]
    for group in ("ai", "human"):
        positive = [
            row
            for row in completed
            if row["group"] == group
            and row["case_control"] == "positive"
            and row["quality_primary_reference_n"]
        ]
        controls = [
            row
            for row in completed
            if row["group"] == group and row["case_control"] == "control"
        ]
        recovery_rates = [
            float(row["quality_primary_recovery_rate"]) for row in positive
        ]
        result[group] = {
            "completed_case_n": sum(row["group"] == group for row in completed),
            "invalid_model_output_n": sum(
                row["group"] == group and not int(row["model_output_valid"])
                for row in completed
            ),
            "invalid_model_output_rate": (
                statistics.fmean(
                    float(not int(row["model_output_valid"]))
                    for row in completed
                    if row["group"] == group
                )
                if any(row["group"] == group for row in completed)
                else None
            ),
            "positive_case_n": len(positive),
            "quality_primary_macro_recovery": (
                statistics.fmean(recovery_rates) if recovery_rates else None
            ),
            "quality_primary_pr_hit_rate": (
                statistics.fmean(
                    float(row["quality_primary_pr_hit"]) for row in positive
                )
                if positive
                else None
            ),
            "control_case_n": len(controls),
            "control_finding_positive_rate": (
                statistics.fmean(
                    float(int(int(row["review_finding_n"]) > 0)) for row in controls
                )
                if controls
                else None
            ),
            "control_mean_unmatched_reports": (
                statistics.fmean(
                    float(row["unmatched_report_n"]) for row in controls
                )
                if controls
                else None
            ),
            "mean_outside_pending_diff_reports": (
                statistics.fmean(
                    float(row["outside_pending_diff_n"])
                    for row in completed
                    if row["group"] == group
                )
                if any(row["group"] == group for row in completed)
                else None
            ),
            "mean_nonexistent_file_reports": (
                statistics.fmean(
                    float(row["nonexistent_file_n"])
                    for row in completed
                    if row["group"] == group
                )
                if any(row["group"] == group for row in completed)
                else None
            ),
        }
    ai = result["ai"]["quality_primary_macro_recovery"]
    human = result["human"]["quality_primary_macro_recovery"]
    result["ai_minus_human_quality_primary_macro_recovery"] = (
        ai - human if ai is not None and human is not None else None
    )
    return result


def summarize(
    *,
    run_dir: Path,
    cases_path: Path,
    references_path: Path,
    output_dir: Path,
    allow_incomplete: bool,
) -> dict[str, Any]:
    if output_dir.exists():
        raise FormalSummaryError(f"output directory already exists: {output_dir}")
    run_manifest = read_json(run_dir / "run_manifest.json", "run manifest")
    if run_manifest.get("status") != "execution_complete" and not allow_incomplete:
        raise FormalSummaryError("formal run must be execution_complete")
    cases = read_csv(cases_path, "cases")
    plan = read_csv(run_dir / "invocation_plan.csv", "invocation plan")
    if len(cases) != 267 or len(plan) != 267:
        raise FormalSummaryError("formal cases and invocation plan must contain 267 rows")
    if run_manifest.get("frozen_configuration", {}).get("cases", {}).get(
        "sha256"
    ) != sha256_file(cases_path):
        raise FormalSummaryError("cases hash differs from frozen run")
    if run_manifest.get("frozen_configuration", {}).get("references", {}).get(
        "sha256"
    ) != sha256_file(references_path):
        raise FormalSummaryError("references hash differs from frozen run")
    case_by_id = {row["case_id"]: row for row in cases}
    refs_by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in read_csv(references_path, "references"):
        refs_by_case[row.get("case_id", "")].append(row)
    plan_by_case = {row["case_id"]: row for row in plan}
    case_rows: list[dict[str, Any]] = []
    all_matches: list[dict[str, Any]] = []
    all_reference_rows: list[dict[str, Any]] = []
    for case_id, case in case_by_id.items():
        plan_row = plan_by_case.get(case_id)
        if plan_row is None:
            raise FormalSummaryError(f"case missing from invocation plan: {case_id}")
        invocation_dir = run_dir / plan_row["output_relpath"]
        try:
            execution, findings = validate_review_artifacts(invocation_dir, case_id)
        except (FormalSummaryError, ExampleSummaryError):
            if not allow_incomplete:
                raise
            case_rows.append(
                {
                    **{field: case.get(field, "") for field in CASE_FIELDS},
                    "execution_status": "failed_or_missing",
                }
            )
            continue
        case_row, matches, reference_rows = summarize_completed_case(
            case=case,
            references=refs_by_case.get(case_id, []),
            findings=findings,
            execution=execution,
        )
        case_rows.append(case_row)
        all_matches.extend(matches)
        all_reference_rows.extend(reference_rows)
    output_dir.mkdir(parents=True)
    write_csv(output_dir / "case_metrics.csv", case_rows, CASE_FIELDS)
    match_fields = list(all_matches[0]) if all_matches else [
        "case_id",
        "model_finding_id",
        "match_status",
    ]
    write_csv(output_dir / "finding_matches.csv", all_matches, match_fields)
    write_csv(
        output_dir / "reference_recovery.csv",
        all_reference_rows,
        REFERENCE_FIELDS,
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": (
            "completed"
            if all(row["execution_status"] == "completed" for row in case_rows)
            else "incomplete"
        ),
        "result_use": "formal_rq3",
        "case_n": len(case_rows),
        "completed_case_n": sum(
            row["execution_status"] == "completed" for row in case_rows
        ),
        "aggregate": aggregate(case_rows),
        "total_sdk_reported_cost_usd": sum(
            value
            for row in case_rows
            if (value := safe_float(row.get("total_cost_usd"))) is not None
        ),
        "provider_invoice_cost_available": False,
        "inputs": {
            "run_manifest_sha256": sha256_file(run_dir / "run_manifest.json"),
            "cases_sha256": sha256_file(cases_path),
            "references_sha256": sha256_file(references_path),
        },
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": summary["status"],
        "outputs": {
            name: sha256_file(output_dir / name)
            for name in (
                "summary.json",
                "case_metrics.csv",
                "finding_matches.csv",
                "reference_recovery.csv",
            )
        },
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> None:
    args = parse_args()
    try:
        result = summarize(
            run_dir=Path(args.run_dir).expanduser().resolve(),
            cases_path=Path(args.cases).expanduser().resolve(),
            references_path=Path(args.references).expanduser().resolve(),
            output_dir=Path(args.output_dir).expanduser().resolve(),
            allow_incomplete=args.allow_incomplete,
        )
    except (FormalSummaryError, ExampleSummaryError, OSError) as exc:
        raise SystemExit(f"RQ3 formal summary error: {exc}") from None
    print(
        "RQ3 formal summary finished: "
        f"status={result['status']}, completed={result['completed_case_n']}/"
        f"{result['case_n']}"
    )


if __name__ == "__main__":
    main()
