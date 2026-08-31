#!/usr/bin/env python3
# RQ3 review experiment entry point.
"""Validate and compile auditable RQ3 semantic-adjudication decisions."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VALIDITIES = {
    "valid_introduced",
    "valid_pre_existing",
    "plausible_uncertain",
    "invalid",
    "unassessable",
}
RELATIONS = {
    "same_issue",
    "related_distinct",
    "no_match",
    "no_reference",
    "uncertain",
}
CONFIDENCES = {"high", "medium", "low"}
ADJUDICATOR_TYPES = {"LLM_assistant", "deterministic_rule", "human"}
FINDING_LABEL_FIELDS = [
    "case_id",
    "model_finding_id",
    "adjudicator",
    "adjudicator_type",
    "finding_validity",
    "codeql_relation",
    "matched_reference_ids",
    "confidence",
    "rationale",
    "evidence_paths",
    "adjudicated_at_utc",
]
CASE_LABEL_FIELDS = [
    "case_id",
    "adjudicator",
    "adjudicator_type",
    "case_review_status",
    "any_semantic_codeql_match",
    "valid_introduced_finding_n",
    "pre_existing_or_out_of_scope_n",
    "invalid_finding_n",
    "uncertain_finding_n",
    "notes",
    "adjudicated_at_utc",
]


class CompilationError(RuntimeError):
    """Raised when a decision violates the adjudication schema."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="校验并汇总 RQ3 逐 finding 语义复核决定"
    )
    parser.add_argument("--workspace", required=True)
    parser.add_argument(
        "--decisions-dir",
        help="JSONL decision files; defaults to WORKSPACE/decisions",
    )
    return parser.parse_args()


def set_csv_field_limit() -> None:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


def read_csv(path: Path) -> list[dict[str, str]]:
    set_csv_field_limit()
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_csv_atomic(
    path: Path, rows: list[dict[str, Any]], fields: list[str]
) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=fields, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def write_json_atomic(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def string_list(value: Any, field: str, location: str) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [item for item in value.split("|") if item]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise CompilationError(f"{location}: {field} must be a string list")


def load_decisions(directory: Path) -> tuple[dict[str, dict[str, Any]], list[Path]]:
    decisions: dict[str, dict[str, Any]] = {}
    paths = sorted(directory.glob("*.jsonl")) if directory.is_dir() else []
    for path in paths:
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            location = f"{path}:{number}"
            try:
                decision = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CompilationError(
                    f"{location}: invalid JSON: {exc.msg}"
                ) from None
            if not isinstance(decision, dict):
                raise CompilationError(f"{location}: decision must be an object")
            finding_id = str(decision.get("model_finding_id", ""))
            if not finding_id:
                raise CompilationError(
                    f"{location}: model_finding_id is required"
                )
            if finding_id in decisions:
                raise CompilationError(
                    f"{location}: duplicate decision for {finding_id}"
                )
            decision["_source"] = location
            decisions[finding_id] = decision
    return decisions, paths


def validate_decision(
    decision: dict[str, Any],
    finding: dict[str, str],
    references_by_case: dict[str, set[str]],
) -> dict[str, str]:
    location = decision["_source"]
    if decision.get("case_id", finding["case_id"]) != finding["case_id"]:
        raise CompilationError(f"{location}: case_id does not match finding")

    validity = str(decision.get("finding_validity", ""))
    relation = str(decision.get("codeql_relation", ""))
    confidence = str(decision.get("confidence", ""))
    rationale = str(decision.get("rationale", "")).strip()
    evidence = string_list(decision.get("evidence_paths"), "evidence_paths", location)
    matched = string_list(
        decision.get("matched_reference_ids"),
        "matched_reference_ids",
        location,
    )

    if validity and validity not in VALIDITIES:
        raise CompilationError(
            f"{location}: invalid finding_validity {validity!r}"
        )
    if relation and relation not in RELATIONS:
        raise CompilationError(
            f"{location}: invalid codeql_relation {relation!r}"
        )
    if confidence and confidence not in CONFIDENCES:
        raise CompilationError(f"{location}: invalid confidence {confidence!r}")
    if (validity or relation) and not confidence:
        raise CompilationError(
            f"{location}: confidence is required for a substantive label"
        )
    if (validity or relation) and not rationale:
        raise CompilationError(
            f"{location}: rationale is required for a substantive label"
        )

    case_refs = references_by_case[finding["case_id"]]
    unknown = set(matched) - case_refs
    if unknown:
        raise CompilationError(
            f"{location}: references are not in this case: {sorted(unknown)}"
        )
    if relation == "same_issue" and not matched:
        raise CompilationError(
            f"{location}: same_issue requires matched_reference_ids"
        )
    if relation != "same_issue" and matched:
        raise CompilationError(
            f"{location}: matched_reference_ids only apply to same_issue"
        )
    if relation == "no_reference" and case_refs:
        raise CompilationError(
            f"{location}: no_reference is invalid because the case has references"
        )
    if relation and relation != "no_reference" and not case_refs:
        raise CompilationError(
            f"{location}: a case without references must use no_reference"
        )

    adjudicator_type = str(
        decision.get("adjudicator_type", "LLM_assistant")
    )
    if adjudicator_type not in ADJUDICATOR_TYPES:
        raise CompilationError(
            f"{location}: invalid adjudicator_type {adjudicator_type!r}"
        )
    if adjudicator_type == "deterministic_rule" and (
        validity or relation != "no_reference"
    ):
        raise CompilationError(
            f"{location}: deterministic_rule is restricted to an objective "
            "no_reference relation without a validity judgment"
        )

    timestamp = str(decision.get("adjudicated_at_utc", "")).strip()
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "case_id": finding["case_id"],
        "model_finding_id": finding["model_finding_id"],
        "adjudicator": str(
            decision.get(
                "adjudicator",
                (
                    "reference_inventory_check"
                    if adjudicator_type == "deterministic_rule"
                    else "Codex"
                ),
            )
        ),
        "adjudicator_type": adjudicator_type,
        "finding_validity": validity,
        "codeql_relation": relation,
        "matched_reference_ids": "|".join(matched),
        "confidence": confidence,
        "rationale": rationale,
        "evidence_paths": "|".join(evidence),
        "adjudicated_at_utc": timestamp,
    }


def compile_workspace(workspace: Path, decisions_dir: Path) -> dict[str, Any]:
    cases_path = workspace / "cases.csv"
    findings_path = workspace / "findings_for_adjudication.csv"
    references_path = workspace / "references_for_adjudication.csv"
    for path in (cases_path, findings_path, references_path):
        if not path.is_file():
            raise CompilationError(f"missing workspace input: {path}")

    cases = read_csv(cases_path)
    findings = read_csv(findings_path)
    references = read_csv(references_path)
    decisions, decision_paths = load_decisions(decisions_dir)

    findings_by_id = {row["model_finding_id"]: row for row in findings}
    if len(findings_by_id) != len(findings):
        raise CompilationError("workspace contains duplicate model_finding_id")
    unknown = set(decisions) - set(findings_by_id)
    if unknown:
        raise CompilationError(
            f"decisions refer to unknown findings: {sorted(unknown)[:10]}"
        )

    references_by_case: dict[str, set[str]] = defaultdict(set)
    for row in references:
        references_by_case[row["case_id"]].add(row["reference_id"])

    labels_by_id: dict[str, dict[str, str]] = {}
    for finding_id, decision in decisions.items():
        labels_by_id[finding_id] = validate_decision(
            decision,
            findings_by_id[finding_id],
            references_by_case,
        )

    blank = {field: "" for field in FINDING_LABEL_FIELDS}
    finding_labels = [
        labels_by_id.get(
            row["model_finding_id"],
            {
                **blank,
                "case_id": row["case_id"],
                "model_finding_id": row["model_finding_id"],
            },
        )
        for row in findings
    ]

    findings_by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in findings:
        findings_by_case[row["case_id"]].append(row)
    labels_by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in finding_labels:
        if row["finding_validity"] or row["codeql_relation"]:
            labels_by_case[row["case_id"]].append(row)

    now = datetime.now(timezone.utc).isoformat()
    case_labels: list[dict[str, Any]] = []
    for case in cases:
        case_id = case["case_id"]
        case_findings = findings_by_case[case_id]
        case_decisions = labels_by_case[case_id]
        if not case_findings:
            status = "complete_no_findings"
        elif len(case_decisions) == len(case_findings) and all(
            row["finding_validity"]
            and row["codeql_relation"]
            and row["confidence"]
            for row in case_decisions
        ):
            status = "complete"
        elif case_decisions:
            status = "partial"
        else:
            status = "not_started"
        validities = Counter(row["finding_validity"] for row in case_decisions)
        adjudicator_types = {
            row["adjudicator_type"] for row in case_decisions
        }
        case_adjudicator_type = (
            next(iter(adjudicator_types))
            if len(adjudicator_types) == 1
            else ("mixed" if adjudicator_types else "")
        )
        case_adjudicators = sorted(
            {row["adjudicator"] for row in case_decisions}
        )
        case_labels.append(
            {
                "case_id": case_id,
                "adjudicator": "|".join(case_adjudicators),
                "adjudicator_type": case_adjudicator_type,
                "case_review_status": status,
                "any_semantic_codeql_match": (
                    int(
                        any(
                            row["codeql_relation"] == "same_issue"
                            for row in case_decisions
                        )
                    )
                    if case_decisions
                    else ""
                ),
                "valid_introduced_finding_n": validities["valid_introduced"],
                "pre_existing_or_out_of_scope_n": (
                    validities["valid_pre_existing"]
                ),
                "invalid_finding_n": validities["invalid"],
                "uncertain_finding_n": (
                    validities["plausible_uncertain"]
                    + validities["unassessable"]
                ),
                "notes": (
                    f"{len(case_decisions)}/{len(case_findings)} findings "
                    "have substantive labels"
                ),
                "adjudicated_at_utc": now if case_decisions else "",
            }
        )

    write_csv_atomic(
        workspace / "finding_labels.csv",
        finding_labels,
        FINDING_LABEL_FIELDS,
    )
    write_csv_atomic(
        workspace / "case_labels.csv",
        case_labels,
        CASE_LABEL_FIELDS,
    )

    relation_counts = Counter(
        row["codeql_relation"]
        for row in finding_labels
        if row["codeql_relation"]
    )
    validity_counts = Counter(
        row["finding_validity"]
        for row in finding_labels
        if row["finding_validity"]
    )
    case_status_counts = Counter(row["case_review_status"] for row in case_labels)
    manifest = {
        "schema_version": "1.0.0",
        "compiled_at_utc": now,
        "workspace": str(workspace),
        "finding_n": len(findings),
        "decision_n": len(decisions),
        "fully_labeled_finding_n": sum(
            bool(row["finding_validity"] and row["codeql_relation"])
            for row in finding_labels
        ),
        "relation_counts": dict(sorted(relation_counts.items())),
        "validity_counts": dict(sorted(validity_counts.items())),
        "case_status_counts": dict(sorted(case_status_counts.items())),
        "decision_files": {
            str(path): sha256_file(path) for path in decision_paths
        },
        "outputs": {
            "finding_labels.csv": sha256_file(workspace / "finding_labels.csv"),
            "case_labels.csv": sha256_file(workspace / "case_labels.csv"),
        },
        "adjudicator_disclosure": (
            "Codex decisions are LLM-assisted semantic adjudication and are "
            "not independent human annotation."
        ),
    }
    write_json_atomic(workspace / "adjudication_progress.json", manifest)
    return manifest


def main() -> None:
    args = parse_args()
    workspace = Path(args.workspace).resolve()
    decisions_dir = (
        Path(args.decisions_dir).resolve()
        if args.decisions_dir
        else workspace / "decisions"
    )
    try:
        manifest = compile_workspace(workspace, decisions_dir)
    except (CompilationError, OSError) as exc:
        raise SystemExit(f"RQ3 adjudication compilation failed: {exc}") from None
    print(
        "RQ3 adjudication compiled: "
        f"decisions={manifest['decision_n']}/{manifest['finding_n']}, "
        f"fully_labeled={manifest['fully_labeled_finding_n']}"
    )


if __name__ == "__main__":
    main()
