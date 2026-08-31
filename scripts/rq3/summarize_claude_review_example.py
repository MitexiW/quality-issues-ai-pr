#!/usr/bin/env python3
# RQ3 review experiment entry point.
"""Summarize one infrastructure-only Claude Code review example.

This adapter consumes either the preferred native ReportFindings response or a
separately recovered, strictly validated DeepSeek fenced finding array. It
matches reports to hidden all-family CodeQL references by exact repo-relative
path and head-side line. It is intentionally small and strict so a one-case
Flash smoke can exercise the complete local recording and matching path without
being mistaken for an RQ3 estimate.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0.0"
NATIVE_RESPONSE_SOURCE = "claude_code_report_findings_tool"
RECOVERED_RESPONSE_SOURCE = "result_text_single_fenced_native_json_array"
ACCEPTED_RESPONSE_SOURCES = {
    NATIVE_RESPONSE_SOURCE,
    RECOVERED_RESPONSE_SOURCE,
}


class ExampleSummaryError(ValueError):
    """Raised when the one-case review artifacts are incomplete or inconsistent."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="汇总一个 infrastructure-only Claude Code review 示例"
    )
    parser.add_argument("--review-dir", required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--references", required=True)
    parser.add_argument("--expected-model", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ExampleSummaryError(f"{label} does not exist: {path}") from None
    except json.JSONDecodeError as exc:
        raise ExampleSummaryError(
            f"{label} is invalid JSON: {path}:{exc.lineno}"
        ) from None
    if not isinstance(value, dict):
        raise ExampleSummaryError(f"{label} must be a JSON object")
    return value


def read_csv(path: Path, label: str) -> list[dict[str, str]]:
    csv.field_size_limit(sys.maxsize)
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
    except FileNotFoundError:
        raise ExampleSummaryError(f"{label} does not exist: {path}") from None
    except csv.Error as exc:
        raise ExampleSummaryError(f"{label} is invalid CSV: {exc}") from None
    if not rows:
        raise ExampleSummaryError(f"{label} must not be empty")
    return rows


def normalize_path(value: str) -> str:
    normalized = (value or "").replace("\\", "/").removeprefix("./")
    if normalized.startswith(("a/", "b/")):
        normalized = normalized[2:]
    return normalized.casefold()


def reference_id(row: dict[str, str]) -> str:
    identity = [
        row.get("case_id", ""),
        row.get("rule_id", ""),
        normalize_path(row.get("file_path", "")),
        row.get("start_line", ""),
        row.get("fingerprint", ""),
    ]
    return "sf-" + hashlib.sha256(canonical_bytes(identity)).hexdigest()[:20]


def finding_id(case_id: str, index: int, finding: dict[str, Any]) -> str:
    return "mf-" + hashlib.sha256(
        canonical_bytes([case_id, index, finding])
    ).hexdigest()[:20]


def line_matches(finding_line: Any, reference: dict[str, str]) -> bool:
    if isinstance(finding_line, bool) or not isinstance(finding_line, int):
        return False
    try:
        start = int(reference["start_line"])
        end = int(reference.get("end_line") or start)
    except (KeyError, TypeError, ValueError):
        return False
    return start <= finding_line <= end


def match_findings(
    case_id: str,
    findings: list[dict[str, Any]],
    references: list[dict[str, str]],
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        model_id = finding_id(case_id, index, finding)
        path = normalize_path(str(finding.get("file", "")))
        line = finding.get("line")
        candidates = [
            reference
            for reference in references
            if path == normalize_path(reference.get("file_path", ""))
            and line_matches(line, reference)
        ]
        if len(candidates) == 1:
            linked = candidates[0]
            status = (
                "compatible_location_recovery"
                if linked.get("reference_role") == "target_reference"
                else "off_target_reference_recovery"
            )
            linked_id = reference_id(linked)
            linked_family = linked.get("reference_family", "")
            linked_rule = linked.get("rule_id", "")
        elif len(candidates) > 1:
            status = "ambiguous_location_candidate"
            linked_id = ""
            linked_family = ""
            linked_rule = ""
        elif not isinstance(line, int) or isinstance(line, bool):
            status = "invalid_or_unlocalized_report"
            linked_id = ""
            linked_family = ""
            linked_rule = ""
        else:
            status = "unmatched_to_codeql"
            linked_id = ""
            linked_family = ""
            linked_rule = ""
        matches.append(
            {
                "case_id": case_id,
                "model_finding_id": model_id,
                "file": finding.get("file", ""),
                "line": line if line is not None else "",
                "summary": finding.get("summary", ""),
                "failure_scenario": finding.get("failure_scenario", ""),
                "match_status": status,
                "candidate_reference_n": len(candidates),
                "silver_finding_id": linked_id,
                "matched_reference_family": linked_family,
                "matched_rule_id": linked_rule,
            }
        )
    return matches


def safe_ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def summarize_example(
    *,
    review_dir: Path,
    case_id: str,
    cases_path: Path,
    references_path: Path,
    expected_model: str,
    output_dir: Path,
) -> dict[str, Any]:
    if output_dir.exists():
        raise ExampleSummaryError(f"output directory already exists: {output_dir}")
    execution_path = review_dir / "execution.json"
    response_path = review_dir / "review_response.json"
    preflight_path = review_dir / "preflight.json"
    execution = read_json(execution_path, "execution")
    response = read_json(response_path, "review response")
    preflight = read_json(preflight_path, "preflight")
    if execution.get("status") != "completed":
        raise ExampleSummaryError("execution status must be completed")
    response_source = execution.get("response_source")
    if response_source not in ACCEPTED_RESPONSE_SOURCES:
        raise ExampleSummaryError(
            "review response source is not an accepted native response"
        )
    if response_source == RECOVERED_RESPONSE_SOURCE:
        if execution.get("recovered_from_retained_failed_attempt") is True:
            if (
                execution.get("result_use") != "infrastructure_only"
                or execution.get("eligible_for_rq3_performance_estimates") is not False
            ):
                raise ExampleSummaryError(
                    "recovered inline response lacks infrastructure-only provenance"
                )
            recovery_contract = execution.get("recovery_contract")
            if not isinstance(recovery_contract, dict) or (
                recovery_contract.get("json_block_n") != 1
                or recovery_contract.get("json_repair") is not False
                or recovery_contract.get("field_synthesis") is not False
            ):
                raise ExampleSummaryError(
                    "recovered inline response contract is incomplete"
                )
        else:
            response_contract = execution.get("response_contract")
            if not isinstance(response_contract, dict) or (
                response_contract.get("inline_fallback")
                != "one_fenced_json_array_locally_validated"
                or response_contract.get("json_repair") is not False
                or response_contract.get("field_synthesis") is not False
            ):
                raise ExampleSummaryError(
                    "direct inline response lacks the frozen strict contract"
                )
    recorded_response = execution.get("review_response", {})
    if recorded_response.get("sha256") != sha256_file(response_path):
        raise ExampleSummaryError("review_response hash does not match execution")
    if preflight.get("case_id") != case_id:
        raise ExampleSummaryError("preflight case_id does not match")
    if preflight.get("model") != expected_model:
        raise ExampleSummaryError(
            f"expected model {expected_model}, found {preflight.get('model')}"
        )
    if set(response) != {"level", "findings"} or not isinstance(
        response["findings"], list
    ):
        raise ExampleSummaryError("native review response schema is invalid")
    cases = [row for row in read_csv(cases_path, "cases") if row["case_id"] == case_id]
    if len(cases) != 1:
        raise ExampleSummaryError("case_id must resolve exactly once")
    case = cases[0]
    references = [
        row
        for row in read_csv(references_path, "references")
        if row.get("case_id") == case_id
    ]
    if case.get("case_control") == "positive" and not references:
        raise ExampleSummaryError("positive case has no hidden references")
    matches = match_findings(case_id, response["findings"], references)
    target_reference_ids = {
        reference_id(row)
        for row in references
        if row.get("reference_role") == "target_reference"
    }
    recovered_target_ids = {
        row["silver_finding_id"]
        for row in matches
        if row["match_status"] == "compatible_location_recovery"
    }
    recovered_off_target_ids = {
        row["silver_finding_id"]
        for row in matches
        if row["match_status"] == "off_target_reference_recovery"
    }
    unmatched_statuses = {
        "unmatched_to_codeql",
        "ambiguous_location_candidate",
        "invalid_or_unlocalized_report",
    }
    summary = {
        "schema_version": SCHEMA_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "result_use": "infrastructure_only",
        "eligible_for_rq3_performance_estimates": False,
        "case_id": case_id,
        "case_control": case.get("case_control", ""),
        "target_family": case.get("target_family", ""),
        "group": case.get("group", ""),
        "repo_name": case.get("repo_name", ""),
        "pr_number": case.get("pr_number", ""),
        "requested_model": expected_model,
        "response_source": execution["response_source"],
        "review_finding_n": len(matches),
        "target_reference_n": len(target_reference_ids),
        "recovered_target_reference_n": len(recovered_target_ids),
        "target_reference_recovery_rate": safe_ratio(
            len(recovered_target_ids), len(target_reference_ids)
        ),
        "positive_pr_hit": int(bool(recovered_target_ids)),
        "off_target_reference_recovery_n": len(recovered_off_target_ids),
        "unmatched_report_n": sum(
            row["match_status"] in unmatched_statuses for row in matches
        ),
        "latency_ms": execution.get("latency_ms"),
        "total_cost_usd": execution.get("total_cost_usd"),
        "model_usage": execution.get("model_usage"),
    }
    output_dir.mkdir(parents=True)
    matches_path = output_dir / "matches.csv"
    references_output = output_dir / "case_references.csv"
    summary_path = output_dir / "summary.json"
    write_csv(
        matches_path,
        matches,
        [
            "case_id",
            "model_finding_id",
            "file",
            "line",
            "summary",
            "failure_scenario",
            "match_status",
            "candidate_reference_n",
            "silver_finding_id",
            "matched_reference_family",
            "matched_rule_id",
        ],
    )
    write_csv(
        references_output,
        references,
        list(references[0]) if references else ["case_id"],
    )
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "result_use": "infrastructure_only",
        "inputs": {
            "execution": {
                "path": str(execution_path.resolve()),
                "sha256": sha256_file(execution_path),
            },
            "review_response": {
                "path": str(response_path.resolve()),
                "sha256": sha256_file(response_path),
            },
            "preflight": {
                "path": str(preflight_path.resolve()),
                "sha256": sha256_file(preflight_path),
            },
            "cases": {
                "path": str(cases_path.resolve()),
                "sha256": sha256_file(cases_path),
            },
            "references": {
                "path": str(references_path.resolve()),
                "sha256": sha256_file(references_path),
            },
        },
        "outputs": {
            "summary": {"path": "summary.json", "sha256": sha256_file(summary_path)},
            "matches": {"path": "matches.csv", "sha256": sha256_file(matches_path)},
            "case_references": {
                "path": "case_references.csv",
                "sha256": sha256_file(references_output),
            },
        },
    }
    manifest["manifest_sha256"] = hashlib.sha256(
        canonical_bytes(manifest)
    ).hexdigest()
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> None:
    args = parse_args()
    try:
        summary = summarize_example(
            review_dir=Path(args.review_dir).expanduser().resolve(),
            case_id=args.case_id,
            cases_path=Path(args.cases).expanduser().resolve(),
            references_path=Path(args.references).expanduser().resolve(),
            expected_model=args.expected_model,
            output_dir=Path(args.output_dir).expanduser().resolve(),
        )
    except (ExampleSummaryError, OSError) as exc:
        raise SystemExit(str(exc)) from None
    rate = summary["target_reference_recovery_rate"]
    print(
        "RQ3 one-case infrastructure example 完成："
        f"findings={summary['review_finding_n']}，"
        f"target_recovered={summary['recovered_target_reference_n']}/"
        f"{summary['target_reference_n']}，"
        f"recovery_rate={rate if rate is not None else math.nan}，"
        f"cost_usd={summary['total_cost_usd']}"
    )


if __name__ == "__main__":
    main()
