#!/usr/bin/env python3
"""Summarize one frozen, provider-neutral RQ3 review run offline.

The invocation plan is the coverage truth.  The append-only attempts file may
be incomplete, but it may not contain an unknown invocation or silently change
any frozen identity.  Primary benchmark estimates give every frozen case equal
weight; selection probabilities and sampling weights are deliberately ignored.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import shutil
import statistics
import sys
import tempfile
from collections import defaultdict
from decimal import Decimal
from pathlib import Path
from typing import Any

import evaluate_llm_reviews as evaluator


SCHEMA_VERSION = "1.0.0"
CONTRAST_METRICS = (
    "case_equal_reference_recovery_rate",
    "positive_pr_hit_rate",
    "unmatched_reports_per_case",
    "control_pr_unmatched_report_rate",
    "off_target_reports_per_case",
)
OUTPUT_SCHEMAS = {
    "job_completeness.csv": (
        "invocation_id",
        "run_id",
        "model_id",
        "packet_id",
        "packet_sha256",
        "repetition",
        "chunk_index",
        "chunk_count",
        "attempt_n",
        "valid_attempt_n",
        "final_status",
        "selected_attempt_line",
    ),
    "attempt_summary.csv": (
        "attempt_line",
        "invocation_id",
        "attempt_index",
        "status",
        "selected_final",
        "input_tokens",
        "output_tokens",
        "latency_ms",
        "error",
    ),
    "matches.csv": (
        "run_id",
        "model_id",
        "repetition",
        "chunk_index",
        "packet_id",
        "case_id",
        "case_control",
        "target_family",
        "group",
        "repo_name",
        "pr_number",
        "model_finding_id",
        "silver_finding_id",
        "matched_reference_family",
        "reference_role",
        "match_status",
        "automatic_exact_candidate_n",
        "issue_family",
        "file_path",
        "line_start",
        "line_end",
        "weakness_category",
        "severity",
        "is_target_family_report",
        "target_reference_file_candidate_n",
        "target_reference_location_candidate_n",
        "adjudication_decision",
        "adjudication_reference_id",
        "requires_adjudication",
    ),
    "case_metrics.csv": (
        "run_id",
        "model_id",
        "repetition",
        "case_id",
        "packet_id",
        "group",
        "target_family",
        "case_control",
        "repo_name",
        "pr_number",
        "case_complete",
        "expected_chunk_n",
        "valid_chunk_n",
        "target_reference_n",
        "recovered_target_reference_n",
        "recovered_reference_ids",
        "case_reference_recovery_rate",
        "positive_pr_hit",
        "target_report_n",
        "unmatched_target_report_n",
        "control_has_unmatched_report",
        "off_target_report_n",
    ),
    "stratum_metrics.csv": (
        "run_id",
        "model_id",
        "repetition",
        "group",
        "target_family",
        "metrics_status",
        "case_n",
        "complete_case_n",
        "missing_or_invalid_case_n",
        "positive_case_n",
        "control_case_n",
        "target_reference_n",
        "recovered_target_reference_n",
        "alert_weighted_reference_recovery_rate_descriptive",
        "case_equal_reference_recovery_rate",
        "positive_pr_hit_rate",
        "unmatched_reports_per_case",
        "control_pr_unmatched_report_rate",
        "off_target_reports_per_case",
    ),
    "ai_human_contrasts.csv": (
        "run_id",
        "model_id",
        "repetition",
        "target_family",
        "metric",
        "contrast",
        "status",
        "ai_estimate",
        "human_estimate",
        "difference",
        "bootstrap_ci_low",
        "bootstrap_ci_high",
        "bootstrap_draws",
        "bootstrap_seed",
        "cluster_unit",
    ),
    "repeat_stability.csv": (
        "run_id",
        "model_id",
        "group",
        "target_family",
        "repetition_a",
        "repetition_b",
        "status",
        "case_n",
        "complete_case_n",
        "mean_recovered_reference_jaccard",
        "positive_pr_hit_agreement",
    ),
    "usage_cost.csv": (
        "run_id",
        "model_id",
        "usage_status",
        "planned_invocation_n",
        "valid_invocation_n",
        "missing_invocation_n",
        "attempted_no_valid_invocation_n",
        "billable_attempt_n",
        "attempt_with_complete_usage_n",
        "input_tokens",
        "output_tokens",
        "total_latency_ms",
        "median_attempt_latency_ms",
        "observed_cost",
        "currency",
        "input_per_million_tokens",
        "output_per_million_tokens",
    ),
}


class SummaryError(ValueError):
    """Raised when run evidence is inconsistent with the frozen plan."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="离线汇总一个已冻结的 RQ3 LLM review run"
    )
    parser.add_argument("--run-manifest", required=True)
    parser.add_argument("--attempts", required=True)
    parser.add_argument("--silver-findings", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--bootstrap-draws", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260623)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def raise_csv_field_size_limit() -> int:
    """Raise csv's parser limit to the largest platform-supported integer."""

    candidate = sys.maxsize
    while candidate > 0:
        try:
            csv.field_size_limit(candidate)
            return candidate
        except OverflowError:
            candidate //= 10
    raise SummaryError("platform exposes no usable CSV field-size limit")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SummaryError(f"missing JSON file: {path}") from None
    except json.JSONDecodeError as exc:
        raise SummaryError(f"invalid JSON: {path}:{exc.lineno}") from None
    if not isinstance(value, dict):
        raise SummaryError(f"JSON root must be an object: {path}")
    return value


def read_jsonl(path: Path, allow_empty: bool = False) -> list[dict[str, Any]]:
    try:
        stream = path.open(encoding="utf-8")
    except FileNotFoundError:
        raise SummaryError(f"missing JSONL file: {path}") from None
    rows: list[dict[str, Any]] = []
    with stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                raise SummaryError(
                    f"invalid JSONL at {path}:{line_number}"
                ) from None
            if not isinstance(row, dict):
                raise SummaryError(
                    f"JSONL row must be an object: {path}:{line_number}"
                )
            rows.append({**row, "_attempt_line": line_number})
    if not rows and not allow_empty:
        raise SummaryError(f"JSONL file must not be empty: {path}")
    return rows


def read_csv(path: Path) -> list[dict[str, str]]:
    raise_csv_field_size_limit()
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
    except FileNotFoundError:
        raise SummaryError(f"missing CSV file: {path}") from None
    except csv.Error as exc:
        raise SummaryError(f"invalid CSV file {path}: {exc}") from None
    if not rows:
        raise SummaryError(f"CSV file must not be empty: {path}")
    return rows


def resolve_frozen_path(raw: str, run_dir: Path) -> Path:
    path = Path(raw).expanduser()
    if path.is_absolute():
        return path.resolve()
    cwd_path = (Path.cwd() / path).resolve()
    if cwd_path.exists():
        return cwd_path
    return (run_dir / path).resolve()


def validate_run_manifest(
    manifest_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, str]], Path]:
    manifest = read_json(manifest_path)
    stored_content_hash = manifest.get("manifest_content_sha256")
    unhashed = {
        key: value
        for key, value in manifest.items()
        if key != "manifest_content_sha256"
    }
    if not isinstance(stored_content_hash, str) or canonical_hash(unhashed) != stored_content_hash:
        raise SummaryError("run manifest content hash mismatch")
    if manifest.get("status") != "frozen_preflight_passed":
        raise SummaryError("run manifest is not a passed frozen preflight")
    plan_meta = manifest.get("invocation_plan")
    if not isinstance(plan_meta, dict):
        raise SummaryError("run manifest has no invocation_plan")
    plan_path = manifest_path.parent / str(plan_meta.get("path", ""))
    if sha256_file(plan_path) != plan_meta.get("sha256"):
        raise SummaryError("invocation plan hash mismatch")
    plan = read_jsonl(plan_path)
    if len(plan) != int(plan_meta.get("row_n", -1)):
        raise SummaryError("invocation plan row count mismatch")
    invocation_ids = [str(row.get("invocation_id", "")) for row in plan]
    if not all(invocation_ids) or len(set(invocation_ids)) != len(invocation_ids):
        raise SummaryError("invocation plan has missing or duplicate invocation_id")

    artifact = manifest.get("validated_artifacts", {}).get("case_key", {})
    case_path = resolve_frozen_path(str(artifact.get("path", "")), manifest_path.parent)
    if sha256_file(case_path) != artifact.get("sha256"):
        raise SummaryError("frozen case-key hash mismatch")
    case_key = read_csv(case_path)
    required = {
        "case_id",
        "packet_id",
        "packet_sha256",
        "chunk_count",
        "case_control",
        "target_family",
        "group",
        "repo_name",
        "pr_number",
    }
    missing = required - set(case_key[0])
    if missing:
        raise SummaryError(f"case key missing fields: {sorted(missing)}")
    packets = {row["packet_id"] for row in case_key}
    if packets != {str(row["packet_id"]) for row in plan}:
        raise SummaryError("case-key packet inventory differs from invocation plan")
    return manifest, plan, case_key, plan_path


def require_nonnegative_int_or_none(value: Any, label: str) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise SummaryError(f"{label} must be a non-negative integer or null")
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise SummaryError(f"{label} must be a non-negative integer or null") from None
    if result < 0 or str(result) != str(value):
        raise SummaryError(f"{label} must be a non-negative integer or null")
    return result


def validate_and_collapse_attempts(
    plan: list[dict[str, Any]],
    attempts: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    plan_by_id = {row["invocation_id"]: row for row in plan}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    normalized_attempts: list[dict[str, Any]] = []
    identity_fields = (
        "run_id",
        "model_id",
        "packet_id",
        "packet_sha256",
        "repetition",
        "chunk_index",
        "chunk_count",
    )
    for attempt in attempts:
        line = int(attempt["_attempt_line"])
        invocation_id = str(attempt.get("invocation_id", ""))
        planned = plan_by_id.get(invocation_id)
        if planned is None:
            raise SummaryError(
                f"attempt line {line} references unknown invocation_id: {invocation_id!r}"
            )
        for field in identity_fields:
            if str(attempt.get(field, "")) != str(planned.get(field, "")):
                raise SummaryError(
                    f"attempt line {line} changes frozen {field} for {invocation_id}"
                )
        if attempt.get("chunk_sha256") != planned.get("chunk_sha256"):
            raise SummaryError(
                f"attempt line {line} changes frozen chunk_sha256 for {invocation_id}"
            )
        status = str(attempt.get("status", ""))
        if not status or status == "missing":
            raise SummaryError(f"attempt line {line} has invalid status")
        if status == "valid" and not isinstance(attempt.get("findings"), list):
            raise SummaryError(
                f"attempt line {line} has valid status but no findings array"
            )
        token_values = {
            field: require_nonnegative_int_or_none(attempt.get(field), f"line {line} {field}")
            for field in ("input_tokens", "output_tokens", "latency_ms")
        }
        normalized = {
            **attempt,
            **token_values,
            "invocation_id": invocation_id,
            "attempt_index": len(grouped[invocation_id]) + 1,
        }
        grouped[invocation_id].append(normalized)
        normalized_attempts.append(normalized)
    for invocation_id, rows in grouped.items():
        planned_max = int(plan_by_id[invocation_id].get("max_attempts", 1))
        if len(rows) > planned_max:
            raise SummaryError(
                f"{invocation_id} has {len(rows)} attempts, exceeding max_attempts={planned_max}"
            )
        valid = [row for row in rows if row["status"] == "valid"]
        if len(valid) > 1:
            raise SummaryError(f"{invocation_id} has multiple valid responses")

    final_outputs: list[dict[str, Any]] = []
    job_rows: list[dict[str, Any]] = []
    selected_lines: set[int] = set()
    for planned in plan:
        rows = grouped.get(planned["invocation_id"], [])
        valid = [row for row in rows if row["status"] == "valid"]
        selected = valid[0] if valid else (rows[-1] if rows else None)
        if selected is not None:
            selected_lines.add(int(selected["_attempt_line"]))
            final_outputs.append(
                {
                    key: value
                    for key, value in selected.items()
                    if not key.startswith("_") and key != "attempt_index"
                }
            )
        state = (
            "valid"
            if valid
            else ("missing" if not rows else "attempted_no_valid_response")
        )
        job_rows.append(
            {
                "invocation_id": planned["invocation_id"],
                "run_id": planned["run_id"],
                "model_id": planned["model_id"],
                "packet_id": planned["packet_id"],
                "packet_sha256": planned["packet_sha256"],
                "repetition": planned["repetition"],
                "chunk_index": planned["chunk_index"],
                "chunk_count": planned["chunk_count"],
                "attempt_n": len(rows),
                "valid_attempt_n": len(valid),
                "final_status": state,
                "selected_attempt_line": (
                    selected["_attempt_line"] if selected is not None else ""
                ),
            }
        )
    attempt_rows = []
    for row in normalized_attempts:
        attempt_rows.append(
            {
                "attempt_line": row["_attempt_line"],
                "invocation_id": row["invocation_id"],
                "attempt_index": row["attempt_index"],
                "status": row["status"],
                "selected_final": int(row["_attempt_line"] in selected_lines),
                "input_tokens": "" if row["input_tokens"] is None else row["input_tokens"],
                "output_tokens": "" if row["output_tokens"] is None else row["output_tokens"],
                "latency_ms": "" if row["latency_ms"] is None else row["latency_ms"],
                "error": row.get("error", ""),
            }
        )
    return final_outputs, job_rows, attempt_rows


def complete_output_grid(
    plan: list[dict[str, Any]],
    final_outputs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    output_by_invocation = {
        row["invocation_id"]: row for row in final_outputs
    }
    rows = []
    for planned in plan:
        output = output_by_invocation.get(planned["invocation_id"])
        if output is None:
            output = {
                **planned,
                "status": "missing",
                "findings": [],
            }
        rows.append(output)
    return rows


def build_case_results(
    case_key: list[dict[str, str]],
    truths: list[dict[str, str]],
    matches: list[dict[str, Any]],
    outputs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    truths_by_case: dict[str, set[str]] = defaultdict(set)
    case_by_id = {row["case_id"]: row for row in case_key}
    for truth in truths:
        case = case_by_id.get(truth.get("case_id", ""))
        if case is None:
            raise SummaryError(f"reference cites unknown case_id: {truth.get('case_id')}")
        if evaluator.alert_family(truth) == case["target_family"]:
            truths_by_case[case["case_id"]].add(evaluator.silver_finding_id(truth))
    matches_by_job: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in matches:
        matches_by_job[(row["case_id"], int(row["repetition"]))].append(row)
    output_by_packet_rep: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for output in outputs:
        output_by_packet_rep[
            (str(output["packet_id"]), int(output["repetition"]))
        ].append(output)
    repetitions = sorted({int(row["repetition"]) for row in outputs})
    result = []
    for repetition in repetitions:
        for case in case_key:
            packet_outputs = output_by_packet_rep[(case["packet_id"], repetition)]
            expected_chunks = int(case["chunk_count"])
            valid_chunks = {
                int(row["chunk_index"])
                for row in packet_outputs
                if row.get("status") == "valid"
            }
            complete = valid_chunks == set(range(1, expected_chunks + 1))
            case_matches = matches_by_job[(case["case_id"], repetition)]
            target_rows = [
                row for row in case_matches
                if int(row.get("is_target_family_report", 0)) == 1
            ]
            recovered = {
                row["silver_finding_id"]
                for row in target_rows
                if row["match_status"] == "compatible_location_recovery"
                and row.get("silver_finding_id")
            }
            reference_ids = truths_by_case.get(case["case_id"], set())
            unmatched_statuses = {
                "unmatched_to_codeql",
                "invalid_or_unlocalized_report",
            }
            unmatched_n = sum(
                row["match_status"] in unmatched_statuses for row in target_rows
            )
            off_target_n = sum(
                row["match_status"] in {
                    "off_target_family_report",
                    "off_target_reference_recovery",
                }
                for row in case_matches
            )
            result.append(
                {
                    "run_id": outputs[0]["run_id"],
                    "model_id": outputs[0]["model_id"],
                    "repetition": repetition,
                    "case_id": case["case_id"],
                    "packet_id": case["packet_id"],
                    "group": case["group"],
                    "target_family": case["target_family"],
                    "case_control": case["case_control"],
                    "repo_name": case["repo_name"],
                    "pr_number": case["pr_number"],
                    "case_complete": int(complete),
                    "expected_chunk_n": expected_chunks,
                    "valid_chunk_n": len(valid_chunks),
                    "target_reference_n": len(reference_ids),
                    "recovered_target_reference_n": len(recovered & reference_ids),
                    "recovered_reference_ids": "|".join(sorted(recovered & reference_ids)),
                    "case_reference_recovery_rate": (
                        len(recovered & reference_ids) / len(reference_ids)
                        if reference_ids else ""
                    ),
                    "positive_pr_hit": (
                        int(bool(recovered & reference_ids))
                        if case["case_control"] == "positive"
                        else ""
                    ),
                    "target_report_n": len(target_rows),
                    "unmatched_target_report_n": unmatched_n,
                    "control_has_unmatched_report": (
                        int(unmatched_n > 0)
                        if case["case_control"] == "control"
                        else ""
                    ),
                    "off_target_report_n": off_target_n,
                }
            )
    return result


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else math.nan


def metric_values(rows: list[dict[str, Any]], metric: str) -> list[float]:
    if metric == "case_equal_reference_recovery_rate":
        return [
            float(row["case_reference_recovery_rate"])
            for row in rows
            if row["case_control"] == "positive"
            and row["case_reference_recovery_rate"] != ""
        ]
    if metric == "positive_pr_hit_rate":
        return [
            float(row["positive_pr_hit"])
            for row in rows
            if row["case_control"] == "positive"
        ]
    if metric == "unmatched_reports_per_case":
        return [float(row["unmatched_target_report_n"]) for row in rows]
    if metric == "control_pr_unmatched_report_rate":
        return [
            float(row["control_has_unmatched_report"])
            for row in rows
            if row["case_control"] == "control"
        ]
    if metric == "off_target_reports_per_case":
        return [float(row["off_target_report_n"]) for row in rows]
    raise SummaryError(f"unknown contrast metric: {metric}")


def build_stratum_metrics(case_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in case_results:
        grouped[
            (
                row["run_id"],
                row["model_id"],
                int(row["repetition"]),
                row["group"],
                row["target_family"],
            )
        ].append(row)
    result = []
    for key, rows in sorted(grouped.items()):
        complete = all(int(row["case_complete"]) for row in rows)
        recovered = sum(int(row["recovered_target_reference_n"]) for row in rows)
        references = sum(int(row["target_reference_n"]) for row in rows)
        values = {
            metric: mean(metric_values(rows, metric))
            for metric in CONTRAST_METRICS
        }
        if not complete:
            values = {metric: "" for metric in CONTRAST_METRICS}
        result.append(
            {
                "run_id": key[0],
                "model_id": key[1],
                "repetition": key[2],
                "group": key[3],
                "target_family": key[4],
                "metrics_status": "complete" if complete else "incomplete",
                "case_n": len(rows),
                "complete_case_n": sum(int(row["case_complete"]) for row in rows),
                "missing_or_invalid_case_n": sum(
                    not int(row["case_complete"]) for row in rows
                ),
                "positive_case_n": sum(
                    row["case_control"] == "positive" for row in rows
                ),
                "control_case_n": sum(
                    row["case_control"] == "control" for row in rows
                ),
                "target_reference_n": references,
                "recovered_target_reference_n": recovered,
                "alert_weighted_reference_recovery_rate_descriptive": (
                    recovered / references if complete and references else ""
                ),
                **values,
            }
        )
    return result


def percentile(values: list[float], probability: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def resample_repositories(
    rows: list[dict[str, Any]], rng: random.Random
) -> list[dict[str, Any]]:
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_repo[row["repo_name"]].append(row)
    repositories = sorted(by_repo)
    sampled: list[dict[str, Any]] = []
    for _ in repositories:
        sampled.extend(by_repo[rng.choice(repositories)])
    return sampled


def build_contrasts(
    case_results: list[dict[str, Any]],
    draws: int,
    seed: int,
) -> list[dict[str, Any]]:
    if draws < 1:
        raise SummaryError("bootstrap_draws must be >= 1")
    grouped: dict[tuple[Any, ...], dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in case_results:
        grouped[
            (
                row["run_id"],
                row["model_id"],
                int(row["repetition"]),
                row["target_family"],
            )
        ][row["group"]].append(row)
    result = []
    for key, groups in sorted(grouped.items()):
        ai = groups.get("AI", []) or groups.get("ai", [])
        human = groups.get("Human", []) or groups.get("human", [])
        complete = bool(ai and human) and all(
            int(row["case_complete"]) for row in ai + human
        )
        for metric in CONTRAST_METRICS:
            ai_values = metric_values(ai, metric)
            human_values = metric_values(human, metric)
            if not complete or not ai_values or not human_values:
                result.append(
                    {
                        "run_id": key[0],
                        "model_id": key[1],
                        "repetition": key[2],
                        "target_family": key[3],
                        "metric": metric,
                        "contrast": "AI_minus_Human",
                        "status": "incomplete",
                        "ai_estimate": "",
                        "human_estimate": "",
                        "difference": "",
                        "bootstrap_ci_low": "",
                        "bootstrap_ci_high": "",
                        "bootstrap_draws": draws,
                        "bootstrap_seed": seed,
                        "cluster_unit": "repo_name",
                    }
                )
                continue
            observed_ai = mean(ai_values)
            observed_human = mean(human_values)
            stratum_digest = hashlib.sha256(
                "|".join(map(str, key + (metric,))).encode()
            ).hexdigest()
            rng = random.Random(seed + int(stratum_digest[:12], 16))
            sampled_differences = []
            for _ in range(draws):
                sampled_ai = resample_repositories(ai, rng)
                sampled_human = resample_repositories(human, rng)
                sampled_differences.append(
                    mean(metric_values(sampled_ai, metric))
                    - mean(metric_values(sampled_human, metric))
                )
            result.append(
                {
                    "run_id": key[0],
                    "model_id": key[1],
                    "repetition": key[2],
                    "target_family": key[3],
                    "metric": metric,
                    "contrast": "AI_minus_Human",
                    "status": "complete",
                    "ai_estimate": observed_ai,
                    "human_estimate": observed_human,
                    "difference": observed_ai - observed_human,
                    "bootstrap_ci_low": percentile(sampled_differences, 0.025),
                    "bootstrap_ci_high": percentile(sampled_differences, 0.975),
                    "bootstrap_draws": draws,
                    "bootstrap_seed": seed,
                    "cluster_unit": "repo_name",
                }
            )
    return result


def build_repeat_stability(
    case_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_stratum: dict[tuple[str, str, str, str], dict[int, dict[str, dict[str, Any]]]] = (
        defaultdict(lambda: defaultdict(dict))
    )
    for row in case_results:
        by_stratum[
            (row["run_id"], row["model_id"], row["group"], row["target_family"])
        ][int(row["repetition"])][row["case_id"]] = row
    result = []
    for key, repetitions in sorted(by_stratum.items()):
        rep_ids = sorted(repetitions)
        for left_index, left_rep in enumerate(rep_ids):
            for right_rep in rep_ids[left_index + 1 :]:
                left = repetitions[left_rep]
                right = repetitions[right_rep]
                common = sorted(set(left) & set(right))
                complete_cases = [
                    case_id for case_id in common
                    if int(left[case_id]["case_complete"])
                    and int(right[case_id]["case_complete"])
                ]
                jaccards = []
                hit_agreement = []
                for case_id in complete_cases:
                    a = set(filter(None, left[case_id]["recovered_reference_ids"].split("|")))
                    b = set(filter(None, right[case_id]["recovered_reference_ids"].split("|")))
                    if a or b:
                        jaccards.append(len(a & b) / len(a | b))
                    else:
                        jaccards.append(1.0)
                    if left[case_id]["positive_pr_hit"] != "":
                        hit_agreement.append(
                            int(
                                left[case_id]["positive_pr_hit"]
                                == right[case_id]["positive_pr_hit"]
                            )
                        )
                status = (
                    "complete" if len(complete_cases) == len(common) else "incomplete"
                )
                result.append(
                    {
                        "run_id": key[0],
                        "model_id": key[1],
                        "group": key[2],
                        "target_family": key[3],
                        "repetition_a": left_rep,
                        "repetition_b": right_rep,
                        "status": status,
                        "case_n": len(common),
                        "complete_case_n": len(complete_cases),
                        "mean_recovered_reference_jaccard": (
                            mean(jaccards) if complete_cases else ""
                        ),
                        "positive_pr_hit_agreement": (
                            mean(hit_agreement) if hit_agreement else ""
                        ),
                    }
                )
    return result


def build_usage_cost(
    manifest: dict[str, Any],
    attempt_rows: list[dict[str, Any]],
    job_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    pricing = manifest["model_configuration"]["pricing_snapshot"]
    input_rate = Decimal(str(pricing["input_per_million_tokens"]))
    output_rate = Decimal(str(pricing["output_per_million_tokens"]))
    input_values = [
        int(row["input_tokens"]) for row in attempt_rows if row["input_tokens"] != ""
    ]
    output_values = [
        int(row["output_tokens"]) for row in attempt_rows if row["output_tokens"] != ""
    ]
    latency_values = [
        int(row["latency_ms"]) for row in attempt_rows if row["latency_ms"] != ""
    ]
    usage_complete = bool(attempt_rows) and all(
        row[field] != ""
        for row in attempt_rows
        for field in ("input_tokens", "output_tokens", "latency_ms")
    ) and all(row["final_status"] == "valid" for row in job_rows)
    cost = (
        Decimal(sum(input_values)) * input_rate
        + Decimal(sum(output_values)) * output_rate
    ) / Decimal(1_000_000)
    return [
        {
            "run_id": manifest["run_id"],
            "model_id": manifest["model_configuration"]["model_id"],
            "usage_status": "complete" if usage_complete else "incomplete",
            "planned_invocation_n": len(job_rows),
            "valid_invocation_n": sum(row["final_status"] == "valid" for row in job_rows),
            "missing_invocation_n": sum(row["final_status"] == "missing" for row in job_rows),
            "attempted_no_valid_invocation_n": sum(
                row["final_status"] == "attempted_no_valid_response" for row in job_rows
            ),
            "billable_attempt_n": len(attempt_rows),
            "attempt_with_complete_usage_n": sum(
                all(row[field] != "" for field in ("input_tokens", "output_tokens", "latency_ms"))
                for row in attempt_rows
            ),
            "input_tokens": sum(input_values),
            "output_tokens": sum(output_values),
            "total_latency_ms": sum(latency_values),
            "median_attempt_latency_ms": (
                statistics.median(latency_values) if latency_values else ""
            ),
            "observed_cost": format(cost, "f"),
            "currency": pricing["currency"],
            "input_per_million_tokens": str(input_rate),
            "output_per_million_tokens": str(output_rate),
        }
    ]


def csv_text(
    rows: list[dict[str, Any]],
    fieldnames: tuple[str, ...],
) -> str:
    if not fieldnames:
        raise SummaryError("CSV schema must contain at least one field")
    import io

    stream = io.StringIO(newline="")
    expected = set(fieldnames)
    for index, row in enumerate(rows, start=1):
        actual = set(row)
        if actual != expected:
            raise SummaryError(
                f"CSV row {index} does not match frozen schema: "
                f"missing={sorted(expected - actual)} "
                f"extra={sorted(actual - expected)}"
            )
    writer = csv.DictWriter(stream, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def summarize(
    run_manifest_path: Path,
    attempts_path: Path,
    silver_path: Path,
    output_dir: Path,
    bootstrap_draws: int = 2000,
    bootstrap_seed: int = 20260623,
) -> dict[str, Any]:
    if output_dir.exists() or output_dir.is_symlink():
        raise SummaryError(f"refusing to overwrite output directory: {output_dir}")
    csv_field_size_limit = raise_csv_field_size_limit()
    manifest, plan, case_key, plan_path = validate_run_manifest(run_manifest_path)
    attempts = read_jsonl(attempts_path, allow_empty=True)
    truths = evaluator.attach_truths_to_cases(case_key, read_csv(silver_path))
    final_outputs, job_rows, attempt_rows = validate_and_collapse_attempts(plan, attempts)
    grid_outputs = complete_output_grid(plan, final_outputs)
    matches = evaluator.build_matches(case_key, truths, final_outputs, [])
    case_results = build_case_results(case_key, truths, matches, grid_outputs)
    stratum_metrics = build_stratum_metrics(case_results)
    contrasts = build_contrasts(case_results, bootstrap_draws, bootstrap_seed)
    repeat_stability = build_repeat_stability(case_results)
    usage = build_usage_cost(manifest, attempt_rows, job_rows)
    outputs = {
        "job_completeness.csv": job_rows,
        "attempt_summary.csv": attempt_rows,
        "matches.csv": matches,
        "case_metrics.csv": case_results,
        "stratum_metrics.csv": stratum_metrics,
        "ai_human_contrasts.csv": contrasts,
        "repeat_stability.csv": repeat_stability,
        "usage_cost.csv": usage,
    }
    basis = {
        "schema_version": SCHEMA_VERSION,
        "estimand": {
            "population": "frozen benchmark",
            "case_weighting": "equal",
            "selection_probability_used": False,
            "sampling_weight_used": False,
            "off_target_family_handling": "reported separately",
        },
        "inputs": {
            "run_manifest": {
                "path": str(run_manifest_path),
                "sha256": sha256_file(run_manifest_path),
            },
            "invocation_plan": {
                "path": str(plan_path),
                "sha256": sha256_file(plan_path),
            },
            "attempts": {
                "path": str(attempts_path),
                "sha256": sha256_file(attempts_path),
            },
            "silver_findings": {
                "path": str(silver_path),
                "sha256": sha256_file(silver_path),
            },
            "implementation": {
                "summarizer_sha256": sha256_file(Path(__file__).resolve()),
                "matcher_sha256": sha256_file(
                    Path(str(evaluator.__file__)).resolve()
                ),
            },
        },
        "configuration": {
            "bootstrap_draws": bootstrap_draws,
            "bootstrap_seed": bootstrap_seed,
            "bootstrap_cluster": "repo_name",
            "contrast": "AI_minus_Human",
            "csv_compatibility": {
                "field_size_limit": csv_field_size_limit,
                "strategy": (
                    "sys.maxsize with decimal fallback on OverflowError"
                ),
            },
        },
    }
    analysis_id = "rq3results-" + canonical_hash(basis)[:24]
    if set(outputs) != set(OUTPUT_SCHEMAS):
        raise SummaryError("result table inventory differs from frozen schemas")
    output_text = {
        name: csv_text(rows, OUTPUT_SCHEMAS[name])
        for name, rows in outputs.items()
    }
    result_manifest = {
        **basis,
        "analysis_id": analysis_id,
        "coverage": {
            "planned_invocation_n": len(plan),
            "valid_invocation_n": sum(row["final_status"] == "valid" for row in job_rows),
            "missing_invocation_n": sum(row["final_status"] == "missing" for row in job_rows),
            "attempted_no_valid_invocation_n": sum(
                row["final_status"] == "attempted_no_valid_response" for row in job_rows
            ),
        },
        "outputs": {
            name: {
                "row_n": len(outputs[name]),
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            }
            for name, text in output_text.items()
        },
    }
    result_manifest["manifest_content_sha256"] = canonical_hash(result_manifest)
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.tmp-", dir=output_dir.parent)
    )
    try:
        for name, text in output_text.items():
            (temporary / name).write_text(text, encoding="utf-8")
        (temporary / "result_manifest.json").write_text(
            json.dumps(result_manifest, ensure_ascii=False, sort_keys=True, indent=2)
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(output_dir)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return result_manifest


def main() -> None:
    args = parse_args()
    result = summarize(
        Path(args.run_manifest),
        Path(args.attempts),
        Path(args.silver_findings),
        Path(args.output_dir),
        args.bootstrap_draws,
        args.bootstrap_seed,
    )
    print(
        json.dumps(
            {
                "analysis_id": result["analysis_id"],
                **result["coverage"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
