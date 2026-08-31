#!/usr/bin/env python3
"""Freeze final human dispositions for all 7,124 differential CodeQL alerts.

Reviewer A labeled the complete model-retained census, Reviewer B labeled the
complete model-excluded census, and Reviewer C independently re-reviewed the
union of alerts that A or B had marked ``confirmed_valid``.  Disagreements
between the source reviewer and Reviewer C are resolved by a separate,
explicit consensus file.  This command verifies those relationships and
writes one deterministic final disposition for every raw differential alert.

The command never edits any reviewer database or source export.  It also omits
review timestamps from its outputs because time-to-label is not an analysis
variable in this study.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[2]
REPORTS = (
    ROOT
    / "data"
    / "experiments"
    / "security-and-quality"
    / "study_stars500"
    / "reports"
)
MANUAL = REPORTS / "manual_validation"

DEFAULT_RETAINED = MANUAL / "full_validated_2495_v1/human_labels.csv"
DEFAULT_EXCLUDED = (
    MANUAL / "model_excluded_full_census_4629_v1/review/human_labels.csv"
)
DEFAULT_REREVIEW = (
    MANUAL / "independent_full_rereview_2379_v1/review/human_labels.csv"
)
DEFAULT_REFERENCE = (
    MANUAL
    / "independent_full_rereview_2379_v1/admin/source_reviewer_reference.csv"
)
DEFAULT_DISAGREEMENTS = (
    MANUAL
    / "independent_full_rereview_2379_v1/analysis/disagreements_for_consensus.csv"
)
DEFAULT_CONSENSUS = (
    MANUAL
    / "independent_full_rereview_2379_v1/analysis/disagreements_for_consensus_final.csv"
)
DEFAULT_OUTPUT = REPORTS / "final_human_consensus_20260817_v1"

DISPOSITIONS = (
    "confirmed_valid",
    "condition_absent",
    "not_pr_introduced",
    "not_valid_issue",
)
DISPOSITION_COMPONENTS = {
    "confirmed_valid": ("yes", "yes", "yes"),
    "condition_absent": ("no", "not_assessed", "not_assessed"),
    "not_pr_introduced": ("yes", "no", "not_assessed"),
    "not_valid_issue": ("yes", "yes", "no"),
}
EXPECTED = {
    "raw_alert_n": 7_124,
    "retained_n": 2_495,
    "excluded_n": 4_629,
    "source_confirmed_n": 2_379,
    "rereview_confirmed_n": 2_319,
    "disagreement_n": 60,
    "final_confirmed_n": 2_322,
    "quality_confirmed_n": 2_194,
    "security_confirmed_n": 128,
    "ai_confirmed_n": 854,
    "human_confirmed_n": 1_468,
}


class ConsensusError(RuntimeError):
    """Raised when a source, re-review, or consensus invariant is violated."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retained-labels", type=Path, default=DEFAULT_RETAINED)
    parser.add_argument("--excluded-labels", type=Path, default=DEFAULT_EXCLUDED)
    parser.add_argument("--rereview-labels", type=Path, default=DEFAULT_REREVIEW)
    parser.add_argument("--source-reference", type=Path, default=DEFAULT_REFERENCE)
    parser.add_argument("--disagreements", type=Path, default=DEFAULT_DISAGREEMENTS)
    parser.add_argument("--consensus", type=Path, default=DEFAULT_CONSENSUS)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def maximize_csv_field_limit() -> None:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


def clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.casefold() in {"nan", "none", "null", "<na>"} else text


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    maximize_csv_field_limit()
    if not path.is_file():
        raise ConsensusError(f"missing CSV input: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), [
            {key: clean(value) for key, value in row.items()} for row in reader
        ]


def write_csv(
    path: Path, fields: Sequence[str], rows: Iterable[dict[str, Any]]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def keyed(rows: Sequence[dict[str, str]], name: str) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = {}
    for row in rows:
        alert_id = clean(row.get("alert_id"))
        if not alert_id or alert_id in output:
            raise ConsensusError(f"{name} has a missing or duplicate alert_id: {alert_id!r}")
        output[alert_id] = row
    return output


def validate_labels(
    rows: Sequence[dict[str, str]], *, name: str, expected_n: int
) -> None:
    if len(rows) != expected_n:
        raise ConsensusError(f"{name}: expected {expected_n} labels, found {len(rows)}")
    for row in rows:
        alert_id = clean(row.get("alert_id"))
        if row.get("status") != "completed":
            raise ConsensusError(f"{name}: incomplete label {alert_id}")
        if row.get("disposition") not in DISPOSITIONS:
            raise ConsensusError(
                f"{name}: invalid disposition {row.get('disposition')!r} for {alert_id}"
            )
        if clean(row.get("flagged")) not in {"", "0", "false"}:
            raise ConsensusError(f"{name}: unresolved flag for {alert_id}")


def compare_metadata(
    left: dict[str, str], right: dict[str, str], *, name: str
) -> None:
    for field in (
        "group",
        "issue_domain",
        "repo_name",
        "pr_number",
        "rule_id",
        "file_path",
        "start_line",
    ):
        if clean(left.get(field)) != clean(right.get(field)):
            raise ConsensusError(
                f"{name}: metadata mismatch for {left.get('alert_id')} field {field}"
            )


def output_record(path: Path, root: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        row_n = sum(1 for _ in handle) - 1
    return {
        "path": str(path.relative_to(root)),
        "rows": row_n,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def run(args: argparse.Namespace) -> None:
    paths = {
        "retained_labels": resolve(args.retained_labels),
        "excluded_labels": resolve(args.excluded_labels),
        "rereview_labels": resolve(args.rereview_labels),
        "source_reference": resolve(args.source_reference),
        "disagreements": resolve(args.disagreements),
        "consensus": resolve(args.consensus),
    }
    output_dir = resolve(args.output_dir)

    _, retained_rows = read_csv(paths["retained_labels"])
    _, excluded_rows = read_csv(paths["excluded_labels"])
    _, rereview_rows = read_csv(paths["rereview_labels"])
    _, reference_rows = read_csv(paths["source_reference"])
    original_fields, disagreement_rows = read_csv(paths["disagreements"])
    consensus_fields, consensus_rows = read_csv(paths["consensus"])

    validate_labels(
        retained_rows,
        name="Reviewer A retained census",
        expected_n=EXPECTED["retained_n"],
    )
    validate_labels(
        excluded_rows,
        name="Reviewer B excluded census",
        expected_n=EXPECTED["excluded_n"],
    )
    validate_labels(
        rereview_rows,
        name="Reviewer C full re-review",
        expected_n=EXPECTED["source_confirmed_n"],
    )

    retained = keyed(retained_rows, "Reviewer A retained census")
    excluded = keyed(excluded_rows, "Reviewer B excluded census")
    rereview = keyed(rereview_rows, "Reviewer C full re-review")
    references = keyed(reference_rows, "sealed source reference")
    original_disagreements = keyed(disagreement_rows, "original disagreements")
    consensus = keyed(consensus_rows, "final consensus")

    if set(retained) & set(excluded):
        raise ConsensusError("retained and excluded censuses overlap")
    source = {**retained, **excluded}
    if len(source) != EXPECTED["raw_alert_n"]:
        raise ConsensusError("source censuses do not cover all 7,124 raw alerts")

    source_positive_ids = {
        alert_id
        for alert_id, row in source.items()
        if row["disposition"] == "confirmed_valid"
    }
    if len(source_positive_ids) != EXPECTED["source_confirmed_n"]:
        raise ConsensusError(
            f"expected 2,379 source-confirmed alerts, found {len(source_positive_ids)}"
        )
    if set(rereview) != source_positive_ids or set(references) != source_positive_ids:
        raise ConsensusError("Reviewer C and sealed-reference IDs must equal source positives")
    for alert_id in source_positive_ids:
        compare_metadata(source[alert_id], rereview[alert_id], name="Reviewer C join")
        compare_metadata(source[alert_id], references[alert_id], name="sealed-reference join")

    c_confirmed = {
        alert_id
        for alert_id, row in rereview.items()
        if row["disposition"] == "confirmed_valid"
    }
    if len(c_confirmed) != EXPECTED["rereview_confirmed_n"]:
        raise ConsensusError(
            f"expected 2,319 Reviewer-C confirmations, found {len(c_confirmed)}"
        )
    c_disagreements = source_positive_ids - c_confirmed
    if len(c_disagreements) != EXPECTED["disagreement_n"]:
        raise ConsensusError(
            f"expected 60 Reviewer-C disagreements, found {len(c_disagreements)}"
        )
    if set(original_disagreements) != c_disagreements or set(consensus) != c_disagreements:
        raise ConsensusError("original and final consensus ID sets must equal C disagreements")

    immutable_fields = [
        field
        for field in original_fields
        if field not in {"consensus_disposition", "consensus_notes"}
    ]
    if set(original_fields) != set(consensus_fields):
        raise ConsensusError("final consensus schema changed from the frozen disagreement export")
    for alert_id in sorted(c_disagreements):
        original = original_disagreements[alert_id]
        final = consensus[alert_id]
        for field in immutable_fields:
            if original.get(field, "") != final.get(field, ""):
                raise ConsensusError(
                    f"consensus changed immutable field {field} for {alert_id}"
                )
        if final.get("consensus_disposition") not in DISPOSITIONS:
            raise ConsensusError(f"missing/invalid consensus disposition for {alert_id}")
        if not clean(final.get("consensus_notes")):
            raise ConsensusError(f"missing consensus rationale for {alert_id}")

    final_rows: list[dict[str, str]] = []
    for alert_id in sorted(source):
        source_row = source[alert_id]
        source_set = "model_retained" if alert_id in retained else "model_excluded"
        source_role = (
            "reviewer_a_retained_census"
            if source_set == "model_retained"
            else "reviewer_b_excluded_census"
        )
        source_disposition = source_row["disposition"]
        c_row = rereview.get(alert_id)
        consensus_row = consensus.get(alert_id)
        if source_disposition != "confirmed_valid":
            final_disposition = source_disposition
            basis = "source_census_negative"
            notes = clean(source_row.get("notes"))
        elif c_row and c_row["disposition"] == "confirmed_valid":
            final_disposition = "confirmed_valid"
            basis = "source_and_independent_rereview_agreement"
            notes = clean(c_row.get("notes"))
        else:
            if consensus_row is None:
                raise ConsensusError(f"missing consensus row for {alert_id}")
            final_disposition = consensus_row["consensus_disposition"]
            basis = "consensus_after_independent_rereview"
            notes = consensus_row["consensus_notes"]

        condition, introduced, valid = DISPOSITION_COMPONENTS[final_disposition]
        final_rows.append(
            {
                "alert_id": alert_id,
                "group": clean(source_row.get("group")),
                "repo_name": clean(source_row.get("repo_name")),
                "pr_number": clean(source_row.get("pr_number")),
                "rule_id": clean(source_row.get("rule_id")),
                "file_path": clean(source_row.get("file_path")),
                "start_line": clean(source_row.get("start_line")),
                "issue_domain": clean(source_row.get("issue_domain")),
                "source_set": source_set,
                "source_reviewer_role": source_role,
                "source_disposition": source_disposition,
                "independent_rereview_disposition": (
                    c_row["disposition"] if c_row else "not_in_positive_rereview_frame"
                ),
                "consensus_disposition": (
                    consensus_row["consensus_disposition"] if consensus_row else ""
                ),
                "status": "completed",
                "disposition": final_disposition,
                "human_condition_present": condition,
                "human_introduced_by_pr": introduced,
                "human_valid_issue": valid,
                "resolution_basis": basis,
                "notes": notes,
            }
        )

    final_counts = Counter(row["disposition"] for row in final_rows)
    if final_counts["confirmed_valid"] != EXPECTED["final_confirmed_n"]:
        raise ConsensusError(
            f"expected 2,322 final confirmed alerts, found {final_counts['confirmed_valid']}"
        )
    positives = [row for row in final_rows if row["disposition"] == "confirmed_valid"]
    domain_counts = Counter(row["issue_domain"] for row in positives)
    group_counts = Counter(row["group"] for row in positives)
    if domain_counts != Counter(
        quality=EXPECTED["quality_confirmed_n"],
        security=EXPECTED["security_confirmed_n"],
    ):
        raise ConsensusError(f"final domain counts changed: {dict(domain_counts)}")
    if group_counts != Counter(
        ai=EXPECTED["ai_confirmed_n"], human=EXPECTED["human_confirmed_n"]
    ):
        raise ConsensusError(f"final group counts changed: {dict(group_counts)}")

    summary_rows: list[dict[str, Any]] = []
    dimensions = {
        "overall": lambda row: "all",
        "source_set": lambda row: row["source_set"],
        "group": lambda row: row["group"],
        "issue_domain": lambda row: row["issue_domain"],
        "group_by_domain": lambda row: f"{row['group']}__{row['issue_domain']}",
        "resolution_basis": lambda row: row["resolution_basis"],
    }
    for dimension, value_fn in dimensions.items():
        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in final_rows:
            grouped[value_fn(row)].append(row)
        for value, rows in sorted(grouped.items()):
            counts = Counter(row["disposition"] for row in rows)
            summary_rows.append(
                {
                    "dimension": dimension,
                    "value": value,
                    "reviewed_alert_n": len(rows),
                    "confirmed_valid_n": counts["confirmed_valid"],
                    "condition_absent_n": counts["condition_absent"],
                    "not_pr_introduced_n": counts["not_pr_introduced"],
                    "not_valid_issue_n": counts["not_valid_issue"],
                    "confirmed_valid_rate": f"{counts['confirmed_valid'] / len(rows):.12f}",
                }
            )

    output_dir.mkdir(parents=True, exist_ok=True)
    labels_path = output_dir / "final_alert_labels.csv"
    summary_path = output_dir / "final_disposition_summary.csv"
    resolution_path = output_dir / "consensus_resolutions.csv"
    write_csv(labels_path, list(final_rows[0]), final_rows)
    write_csv(summary_path, list(summary_rows[0]), summary_rows)
    write_csv(resolution_path, consensus_fields, consensus_rows)

    manifest = {
        "schema_version": "1.0.0",
        "status": "final_ready",
        "dataset_id": "final_human_consensus_20260817_v1",
        "review_design": {
            "reviewer_a": "complete model-retained census (2,495 alerts)",
            "reviewer_b": "complete model-excluded census (4,629 alerts)",
            "reviewer_c": "independent re-review of 2,379 source-confirmed alerts",
            "consensus": "explicit resolution of all 60 source-versus-C disagreements",
        },
        "counts": {
            **EXPECTED,
            "consensus_confirmed_n": sum(
                row["consensus_disposition"] == "confirmed_valid"
                for row in consensus_rows
            ),
            "consensus_rejected_n": sum(
                row["consensus_disposition"] != "confirmed_valid"
                for row in consensus_rows
            ),
            "final_dispositions": dict(final_counts),
            "final_confirmed_by_group": dict(group_counts),
            "final_confirmed_by_domain": dict(domain_counts),
        },
        "inputs": {
            name: {"path": str(path.resolve()), "sha256": sha256_file(path)}
            for name, path in paths.items()
        },
        "outputs": {},
    }
    for name, path in {
        "final_alert_labels": labels_path,
        "final_disposition_summary": summary_path,
        "consensus_resolutions": resolution_path,
    }.items():
        manifest["outputs"][name] = output_record(path, output_dir)
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Final human consensus frozen: "
        f"alerts={len(final_rows):,}, confirmed={len(positives):,}, "
        f"Quality={domain_counts['quality']:,}, Security={domain_counts['security']:,}, "
        f"output={output_dir}"
    )


def main() -> None:
    run(parse_args())


if __name__ == "__main__":
    main()
