#!/usr/bin/env python3
"""Freeze the author's completed review of all RQ3 semantic relations.

The historical semantic table retains how each candidate relation was first
constructed (LLM-assisted or deterministic).  This script adds a separate,
retrospective author-confirmation layer without rewriting that provenance or
inventing review timestamps and item-level edit histories.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path


OUTPUT_FIELDS = (
    "case_id",
    "model_finding_id",
    "initial_adjudicator_type",
    "initial_codeql_relation",
    "initial_matched_reference_ids",
    "initial_relation_confidence",
    "initial_relation_rationale",
    "final_codeql_relation",
    "final_matched_reference_ids",
    "human_review_status",
    "final_decision_source",
    "reviewer_role",
    "source_row_sha256",
)

REQUIRED_SOURCE_FIELDS = {
    "case_id",
    "model_finding_id",
    "adjudicator_type",
    "codeql_relation",
    "matched_reference_ids",
    "relation_confidence",
    "relation_rationale",
}

EXPECTED_RELATION_COUNTS = {
    "same_issue": 45,
    "related_distinct": 187,
    "no_match": 544,
    "no_reference": 240,
}

EXPECTED_INITIAL_PROVENANCE = {
    "LLM_assistant": 776,
    "deterministic_rule": 240,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_row_sha256(row: dict[str, str]) -> str:
    payload = json.dumps(
        row,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def display_source_path(path: Path) -> str:
    """Record a stable report-relative identifier instead of a host path."""

    return f"{path.parent.name}/{path.name}"


def freeze(relations: Path, output_dir: Path) -> None:
    if not relations.is_file():
        raise FileNotFoundError(relations)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite frozen output: {output_dir}")

    with relations.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        missing = sorted(REQUIRED_SOURCE_FIELDS - fields)
        if missing:
            raise ValueError(f"source relation fields missing: {missing}")
        source_rows = list(reader)

    keys = [(row["case_id"], row["model_finding_id"]) for row in source_rows]
    if len(keys) != 1016:
        raise ValueError(f"expected 1,016 relation rows, found {len(keys)}")
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate (case_id, model_finding_id) relation key")

    relation_counts = Counter(row["codeql_relation"] for row in source_rows)
    provenance_counts = Counter(row["adjudicator_type"] for row in source_rows)
    if dict(relation_counts) != EXPECTED_RELATION_COUNTS:
        raise ValueError(
            f"unexpected relation counts: {dict(relation_counts)}; "
            f"expected {EXPECTED_RELATION_COUNTS}"
        )
    if dict(provenance_counts) != EXPECTED_INITIAL_PROVENANCE:
        raise ValueError(
            f"unexpected initial provenance: {dict(provenance_counts)}; "
            f"expected {EXPECTED_INITIAL_PROVENANCE}"
        )

    output_dir.mkdir(parents=True)
    review_path = output_dir / "author_relation_review.csv"
    with review_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        for row in source_rows:
            writer.writerow(
                {
                    "case_id": row["case_id"],
                    "model_finding_id": row["model_finding_id"],
                    "initial_adjudicator_type": row["adjudicator_type"],
                    "initial_codeql_relation": row["codeql_relation"],
                    "initial_matched_reference_ids": row["matched_reference_ids"],
                    "initial_relation_confidence": row["relation_confidence"],
                    "initial_relation_rationale": row["relation_rationale"],
                    "final_codeql_relation": row["codeql_relation"],
                    "final_matched_reference_ids": row["matched_reference_ids"],
                    "human_review_status": "author_confirmed",
                    "final_decision_source": "author_manual_review",
                    "reviewer_role": "author",
                    "source_row_sha256": source_row_sha256(row),
                }
            )

    summary = {
        "schema_version": "1.0.0",
        "status": "author_confirmation_complete",
        "relation_n": len(source_rows),
        "unique_relation_key_n": len(set(keys)),
        "human_review_status": {"author_confirmed": len(source_rows)},
        "final_decision_source": {"author_manual_review": len(source_rows)},
        "reviewer_role": {"author": len(source_rows)},
        "initial_adjudicator_type_counts": dict(provenance_counts),
        "final_relation_counts": dict(relation_counts),
        "attestation": (
            "One author manually examined every frozen reviewer finding against "
            "the within-PR CodeQL references and confirmed the released relation "
            "and matched-reference identifiers as the final study decisions."
        ),
        "recording_limitation": (
            "This retrospective confirmation layer preserves the initial decision "
            "provenance but does not reconstruct review timestamps, intermediate "
            "edits, or an independent duplicate annotation."
        ),
        "labels_changed_by_freeze_n": 0,
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    manifest = {
        "schema_version": "1.0.0",
        "status": "frozen",
        "source_relations": {
            "path": display_source_path(relations),
            "sha256": sha256_file(relations),
        },
        "outputs": {
            "author_relation_review.csv": {
                "sha256": sha256_file(review_path),
                "size": review_path.stat().st_size,
            },
            "summary.json": {
                "sha256": sha256_file(summary_path),
                "size": summary_path.stat().st_size,
            },
        },
        "row_n": len(source_rows),
        "unique_key": ["case_id", "model_finding_id"],
        "contains_review_timestamps": False,
        "contains_item_edit_history": False,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        "RQ3 author relation review frozen: "
        f"relations={len(source_rows)} output={output_dir}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relations", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    freeze(args.relations.resolve(), args.output_dir.resolve())


if __name__ == "__main__":
    main()
