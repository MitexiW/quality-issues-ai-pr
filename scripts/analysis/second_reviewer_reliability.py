#!/usr/bin/env python3
"""Prepare and analyze independent second-reviewer audits.

``prepare`` freezes a 200-alert, outcome-stratified sample drawn from the
complete retained-alert census and the 400-alert excluded probability audit.
The reviewer-facing CSV contains CodeQL and repository context but blanks all
model judgments and never contains the first reviewer's labels.

``analyze`` joins the independently exported labels to the sealed reference
key, reports raw and design-weighted agreement and Cohen's kappa, and exports
all disagreements for consensus adjudication.  It refuses incomplete,
flagged, or uncertain second-reviewer data.

``prepare-full`` freezes all 2,379 alerts confirmed by two source reviewers:
Reviewer A confirmed 2,246 model-retained alerts and Reviewer B confirmed 133
model-excluded alerts. A third person, Reviewer C, receives a blinded file for
the independent full re-review. ``analyze-full`` reports Reviewer C's
confirmation rate and exports disagreements for later consensus. Because both
source-reviewer labels are constant in this full re-review set, Cohen's kappa
is not an appropriate estimand for the full set; the 200-alert audit remains
the source of four-way and binary kappa estimates.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


# Some repository-context fields contain large patches or source excerpts.
# Lift the stdlib CSV parser's platform-dependent 128 KiB default while
# retaining a bounded fallback for platforms whose C long is smaller.
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2**31 - 1)


ROOT = Path(__file__).resolve().parents[2]
REPORT_ROOT = ROOT / "data/experiments/security-and-quality/study_stars500/reports"
DEFAULT_OUTPUT = REPORT_ROOT / "manual_validation/second_reviewer_reliability_200_v2"
DEFAULT_FULL_OUTPUT = (
    REPORT_ROOT / "manual_validation/independent_full_rereview_2379_v1"
)

DEFAULT_RETAINED_PAYLOAD = (
    REPORT_ROOT / "validated_issue_analysis_20260808_v1/validated_alerts.csv"
)
DEFAULT_RETAINED_LABELS = (
    REPORT_ROOT / "manual_validation/full_validated_2495_v1/human_labels.csv"
)
DEFAULT_EXCLUDED_PAYLOAD = (
    REPORT_ROOT / "manual_validation/model_excluded_probability_audit_400_v1/sample.csv"
)
DEFAULT_EXCLUDED_LABELS = (
    REPORT_ROOT
    / "manual_validation/model_excluded_probability_audit_400_v1/review/human_labels.csv"
)
DEFAULT_RETAINED_DATABASE = (
    REPORT_ROOT / "manual_validation/full_validated_2495_v1/review.sqlite3"
)
DEFAULT_EXCLUDED_DATABASE = (
    REPORT_ROOT
    / "manual_validation/model_excluded_full_census_4629_v1/review/review.sqlite3"
)

SELECTION_SEED = 2026081401
UI_ORDER_SEED = 2026081402
DISPOSITIONS = (
    "confirmed_valid",
    "condition_absent",
    "not_pr_introduced",
    "not_valid_issue",
)
QUOTAS: dict[str, dict[str, int]] = {
    "retained": {
        "confirmed_valid": 80,
        "not_valid_issue": 40,
        "not_pr_introduced": 27,
        "condition_absent": 13,
    },
    "excluded_audit": {
        "confirmed_valid": 15,
        "not_valid_issue": 10,
        "not_pr_introduced": 10,
        "condition_absent": 5,
    },
}
MODEL_FIELDS = {
    "condition_present",
    "valid_issue",
    "introduced_by_pr",
    "actionability",
    "confidence",
    "evidence_json",
    "rationale",
    "model_supported_introduced_issue",
    "model_supported_actionable_issue",
}
PRIMARY_REVIEW_FIELDS = {
    "status",
    "disposition",
    "human_condition_present",
    "human_introduced_by_pr",
    "human_valid_issue",
    "human_actionability",
    "human_confidence",
    "human_notes",
    "notes",
    "flagged",
    "revision",
    "started_at",
    "submitted_at",
    "updated_at",
}
FULL_SELECTION_SEED = 2026081701
FULL_UI_ORDER_SEED = 2026081702


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def csv_bytes(fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> bytes:
    from io import StringIO

    buffer = StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(content)
    temporary.replace(path)


def stable_rank(seed: int, source: str, disposition: str, alert_id: str) -> str:
    payload = f"{seed}|{source}|{disposition}|{alert_id}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def keyed(rows: list[dict[str, str]], name: str) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for row in rows:
        alert_id = row.get("alert_id", "").strip()
        if not alert_id:
            raise ValueError(f"{name} contains a row without alert_id")
        if alert_id in result:
            raise ValueError(f"{name} contains duplicate alert_id {alert_id}")
        result[alert_id] = row
    return result


def validate_reference_labels(rows: list[dict[str, str]], expected_n: int, name: str) -> None:
    if len(rows) != expected_n:
        raise ValueError(f"{name} expected {expected_n} labels, found {len(rows)}")
    for row in rows:
        if row.get("status") != "completed":
            raise ValueError(f"{name} contains incomplete label {row.get('alert_id')}")
        if row.get("disposition") not in DISPOSITIONS:
            raise ValueError(f"{name} contains invalid disposition {row.get('disposition')}")


def select_rows(
    source: str,
    labels: list[dict[str, str]],
    payloads: dict[str, dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    selected_payloads: list[dict[str, str]] = []
    references: list[dict[str, Any]] = []
    for disposition, sample_n in QUOTAS[source].items():
        pool = [row for row in labels if row["disposition"] == disposition]
        population_n = len(pool)
        if population_n < sample_n:
            raise ValueError(
                f"{source}/{disposition} has {population_n} labels but quota is {sample_n}"
            )
        pool.sort(
            key=lambda row: stable_rank(
                SELECTION_SEED, source, disposition, row["alert_id"]
            )
        )
        weight = population_n / sample_n
        for label in pool[:sample_n]:
            alert_id = label["alert_id"]
            if alert_id not in payloads:
                raise ValueError(f"payload is missing selected alert {alert_id}")
            payload = dict(payloads[alert_id])
            for field in MODEL_FIELDS:
                if field in payload:
                    payload[field] = ""
            # Sampling metadata belongs only in the sealed reference key.  In
            # particular, a stratum name containing ``disposition`` would
            # reveal the first reviewer's answer to anyone opening sample.csv
            # even though the web UI does not render arbitrary input fields.
            payload["verification_audit_scope"] = (
                "second_reviewer_reliability_sample"
            )
            selected_payloads.append(payload)
            references.append(
                {
                    "alert_id": alert_id,
                    "reliability_source": source,
                    "reliability_stratum": f"{source}__{disposition}",
                    "stratum_population_n": population_n,
                    "stratum_sample_n": sample_n,
                    "design_weight": f"{weight:.12f}",
                    "first_disposition": disposition,
                    "group": label.get("group", ""),
                    "issue_domain": label.get("issue_domain", ""),
                    "repo_name": label.get("repo_name", ""),
                    "pr_number": label.get("pr_number", ""),
                    "rule_id": label.get("rule_id", ""),
                    "file_path": label.get("file_path", ""),
                    "start_line": label.get("start_line", ""),
                }
            )
    return selected_payloads, references


def prepare(args: argparse.Namespace) -> None:
    manifest_path = args.output_dir / "sampling_manifest.json"
    input_paths = {
        "retained_payload": args.retained_payload,
        "retained_labels": args.retained_labels,
        "excluded_payload": args.excluded_payload,
        "excluded_labels": args.excluded_labels,
    }
    input_hashes = {name: sha256_file(path) for name, path in input_paths.items()}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("inputs") != input_hashes:
            raise ValueError("frozen reliability sample inputs changed; choose a new version")
        for key, record in manifest["outputs"].items():
            path = args.output_dir / record["relative_path"]
            if sha256_file(path) != record["sha256"]:
                raise ValueError(f"frozen output changed: {key}")
        print(f"Reliability sample already frozen and verified: {args.output_dir}")
        return

    retained_fields, retained_payload_rows = read_csv(args.retained_payload)
    excluded_fields, excluded_payload_rows = read_csv(args.excluded_payload)
    _, retained_label_rows = read_csv(args.retained_labels)
    _, excluded_label_rows = read_csv(args.excluded_labels)
    validate_reference_labels(retained_label_rows, 2495, "retained census")
    validate_reference_labels(excluded_label_rows, 400, "excluded audit")

    retained_payloads = keyed(retained_payload_rows, "retained payload")
    excluded_payloads = keyed(excluded_payload_rows, "excluded payload")
    if set(retained_payloads) & set(excluded_payloads):
        raise ValueError("retained and excluded payloads unexpectedly overlap")

    selected: list[dict[str, str]] = []
    references: list[dict[str, Any]] = []
    for source, labels, payloads in (
        ("retained", retained_label_rows, retained_payloads),
        ("excluded_audit", excluded_label_rows, excluded_payloads),
    ):
        source_selected, source_references = select_rows(source, labels, payloads)
        selected.extend(source_selected)
        references.extend(source_references)

    if len(selected) != 200 or len({row["alert_id"] for row in selected}) != 200:
        raise ValueError("reliability sample must contain 200 unique alerts")
    selected.sort(key=lambda row: stable_rank(SELECTION_SEED, "final", "", row["alert_id"]))
    references.sort(key=lambda row: row["alert_id"])

    extra_fields = ["verification_audit_scope"]
    sample_fields = list(dict.fromkeys([*retained_fields, *excluded_fields, *extra_fields]))
    reference_fields = list(references[0])
    sample_content = csv_bytes(sample_fields, selected)
    reference_content = csv_bytes(reference_fields, references)
    sample_path = args.output_dir / "sample.csv"
    reference_path = args.output_dir / "admin/first_reviewer_reference.csv"
    write_bytes(sample_path, sample_content)
    write_bytes(reference_path, reference_content)
    # The reviewer-facing application never reads this key.  Restrict it to
    # the experiment owner so an independently reviewing collaborator cannot
    # accidentally inspect the first decisions through a shared directory.
    reference_path.chmod(0o600)

    coverage = Counter(
        (row["reliability_source"], row["group"], row["issue_domain"], row["first_disposition"])
        for row in references
    )
    coverage_rows = [
        {
            "source": key[0],
            "group": key[1],
            "issue_domain": key[2],
            "first_disposition": key[3],
            "sample_n": value,
        }
        for key, value in sorted(coverage.items())
    ]
    coverage_fields = list(coverage_rows[0])
    coverage_path = args.output_dir / "sample_coverage.csv"
    write_bytes(coverage_path, csv_bytes(coverage_fields, coverage_rows))

    outputs = {}
    for name, path in {
        "reviewer_sample": sample_path,
        "sealed_reference": reference_path,
        "sample_coverage": coverage_path,
    }.items():
        outputs[name] = {
            "relative_path": str(path.relative_to(args.output_dir)),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
    manifest = {
        "schema_version": "1.0.0",
        "status": "frozen_awaiting_independent_review",
        "created_at": utc_now(),
        "sample_n": 200,
        "source_sample_n": {"retained": 160, "excluded_audit": 40},
        "selection_seed": SELECTION_SEED,
        "ui_order_seed": UI_ORDER_SEED,
        "stratum_definition": "source_by_first_reviewer_disposition",
        "quotas": QUOTAS,
        "blindness": {
            "first_reviewer_labels_in_reviewer_sample": False,
            "model_judgment_fields_blank": True,
            "authorship_group_hidden_by_ui": True,
            "residual_identity_leakage": "repository paths and code may reveal provenance cues",
        },
        "estimand_boundary": (
            "Reliability of the four-way contextual disposition among the 2,895 alerts "
            "previously human-reviewed; this audit does not estimate CodeQL recall."
        ),
        "inputs": input_hashes,
        "outputs": outputs,
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Frozen second-reviewer sample: {sample_path} (n=200)")
    print(f"Sealed first-reviewer key: {reference_path}")


def read_primary_review_database(
    database: Path,
    *,
    source_set: str,
    source_reviewer_role: str,
    expected_total: int,
    expected_confirmed: int,
) -> tuple[list[dict[str, str]], list[dict[str, str]], str, dict[str, int]]:
    """Read one source reviewer's complete census, including live WAL contents."""
    if not database.is_file():
        raise FileNotFoundError(database)
    uri = f"file:{database.resolve()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        connection.row_factory = sqlite3.Row
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        if quick_check != "ok":
            raise ValueError(f"{database}: SQLite quick_check returned {quick_check!r}")
        rows = connection.execute(
            """
            SELECT i.alert_id,i.payload_json,l.status,l.disposition,l.flagged
            FROM items i JOIN labels l USING(alert_id)
            ORDER BY i.alert_id
            """
        ).fetchall()
    if len(rows) != expected_total:
        raise ValueError(
            f"{source_set} source review expected {expected_total} rows, found {len(rows)}"
        )
    bad_status = [row["alert_id"] for row in rows if row["status"] != "completed"]
    if bad_status:
        raise ValueError(
            f"{source_set} source review has {len(bad_status)} incomplete labels"
        )
    flagged = [row["alert_id"] for row in rows if int(row["flagged"] or 0)]
    if flagged:
        raise ValueError(f"{source_set} source review has {len(flagged)} flagged labels")
    invalid = [
        row["alert_id"] for row in rows if row["disposition"] not in DISPOSITIONS
    ]
    if invalid:
        raise ValueError(f"{source_set} source review has invalid dispositions")

    disposition_counts = Counter(row["disposition"] for row in rows)
    if disposition_counts["confirmed_valid"] != expected_confirmed:
        raise ValueError(
            f"{source_set} source review expected {expected_confirmed} confirmed-valid "
            f"alerts, found {disposition_counts['confirmed_valid']}"
        )

    selected_payloads: list[dict[str, str]] = []
    references: list[dict[str, str]] = []
    canonical_state: list[dict[str, str]] = []
    for row in rows:
        raw_payload = row["payload_json"]
        payload = json.loads(raw_payload)
        if not isinstance(payload, dict):
            raise ValueError(f"{source_set}/{row['alert_id']} payload is not an object")
        alert_id = str(row["alert_id"])
        if str(payload.get("alert_id", "")).strip() != alert_id:
            raise ValueError(f"{source_set}/{alert_id} payload alert_id mismatch")
        payload_hash = sha256_bytes(raw_payload.encode("utf-8"))
        canonical_state.append(
            {
                "alert_id": alert_id,
                "disposition": str(row["disposition"]),
                "flagged": str(int(row["flagged"] or 0)),
                "payload_sha256": payload_hash,
            }
        )
        if row["disposition"] != "confirmed_valid":
            continue
        reviewer_payload = {key: str(value) if value is not None else "" for key, value in payload.items()}
        for field in MODEL_FIELDS | PRIMARY_REVIEW_FIELDS:
            if field in reviewer_payload:
                reviewer_payload[field] = ""
        reviewer_payload["verification_audit_scope"] = (
            "independent_full_rereview_2379"
        )
        selected_payloads.append(reviewer_payload)
        references.append(
            {
                "alert_id": alert_id,
                "source_set": source_set,
                "source_reviewer_role": source_reviewer_role,
                "source_reviewer_disposition": "confirmed_valid",
                "group": str(payload.get("group", "")),
                "issue_domain": str(payload.get("issue_domain", "")),
                "repo_name": str(payload.get("repo_name", "")),
                "pr_number": str(payload.get("pr_number", "")),
                "rule_id": str(payload.get("rule_id", "")),
                "file_path": str(payload.get("file_path", "")),
                "start_line": str(payload.get("start_line", "")),
                "payload_sha256": payload_hash,
            }
        )
    canonical_bytes = b"".join(
        (
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        for record in canonical_state
    )
    return (
        selected_payloads,
        references,
        sha256_bytes(canonical_bytes),
        dict(disposition_counts),
    )


def prepare_full_rereview(args: argparse.Namespace) -> None:
    retained, retained_refs, retained_state, retained_counts = (
        read_primary_review_database(
            args.retained_database,
            source_set="model_retained",
            source_reviewer_role="reviewer_a_retained_census",
            expected_total=2495,
            expected_confirmed=2246,
        )
    )
    excluded, excluded_refs, excluded_state, excluded_counts = (
        read_primary_review_database(
            args.excluded_database,
            source_set="model_excluded",
            source_reviewer_role="reviewer_b_excluded_census",
            expected_total=4629,
            expected_confirmed=133,
        )
    )
    selected = [*retained, *excluded]
    references = [*retained_refs, *excluded_refs]
    if len(selected) != 2379 or len({row["alert_id"] for row in selected}) != 2379:
        raise ValueError("full independent re-review must contain 2,379 unique alerts")
    if set(row["alert_id"] for row in selected) != set(
        row["alert_id"] for row in references
    ):
        raise ValueError("reviewer payloads and sealed references do not match")

    selected.sort(
        key=lambda row: stable_rank(
            FULL_SELECTION_SEED, "full_rereview", "", row["alert_id"]
        )
    )
    references.sort(key=lambda row: row["alert_id"])
    sample_fields: list[str] = []
    for row in selected:
        for field in row:
            if field not in sample_fields:
                sample_fields.append(field)
    reference_fields = list(references[0])
    sample_content = csv_bytes(sample_fields, selected)
    reference_content = csv_bytes(reference_fields, references)
    input_state = {
        "retained_database": str(args.retained_database.resolve()),
        "retained_state_sha256": retained_state,
        "retained_dispositions": retained_counts,
        "excluded_database": str(args.excluded_database.resolve()),
        "excluded_state_sha256": excluded_state,
        "excluded_dispositions": excluded_counts,
    }

    manifest_path = args.output_dir / "preparation_manifest.json"
    sample_path = args.output_dir / "sample.csv"
    reference_path = args.output_dir / "admin/source_reviewer_reference.csv"
    legacy_reference_path: Path | None = None
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("inputs") != input_state:
            raise ValueError(
                "source-review state changed after the full re-review was frozen; "
                "choose a new output version"
            )
        if "sealed_source_reference" in manifest.get("outputs", {}):
            for name, path in {
                "reviewer_sample": sample_path,
                "sealed_source_reference": reference_path,
            }.items():
                expected_hash = manifest["outputs"][name]["sha256"]
                if not path.is_file() or sha256_file(path) != expected_hash:
                    raise ValueError(f"frozen full re-review output changed: {name}")
            print(
                f"Full independent re-review already frozen and verified: {sample_path}"
            )
            return

        # Version 1.0 incorrectly described the two source reviewers as one
        # "primary reviewer".  Permit an in-place metadata correction only
        # before Reviewer C has created any labels.
        review_database = args.output_dir / "review/review.sqlite3"
        if review_database.exists():
            with sqlite3.connect(review_database) as connection:
                label_n = connection.execute("SELECT COUNT(*) FROM labels").fetchone()[0]
            if label_n:
                raise ValueError(
                    "cannot amend reviewer-role metadata after Reviewer C has started; "
                    "choose a new output version"
                )
        legacy_record = manifest.get("outputs", {}).get("sealed_primary_reference")
        if not legacy_record:
            raise ValueError("unrecognized full re-review preparation manifest")
        legacy_reference_path = args.output_dir / legacy_record["relative_path"]
        if (
            not legacy_reference_path.is_file()
            or sha256_file(legacy_reference_path) != legacy_record["sha256"]
        ):
            raise ValueError("legacy sealed reference changed before role correction")

    write_bytes(sample_path, sample_content)
    write_bytes(reference_path, reference_content)
    reference_path.chmod(0o600)
    outputs = {
        "reviewer_sample": {
            "relative_path": str(sample_path.relative_to(args.output_dir)),
            "sha256": sha256_file(sample_path),
            "rows": 2379,
        },
        "sealed_source_reference": {
            "relative_path": str(reference_path.relative_to(args.output_dir)),
            "sha256": sha256_file(reference_path),
            "rows": 2379,
        },
    }
    manifest = {
        "schema_version": "1.1.0",
        "status": "frozen_awaiting_independent_full_rereview",
        "created_at": utc_now(),
        "sample_n": 2379,
        "source_n": {"model_retained": 2246, "model_excluded": 133},
        "reviewer_roles": {
            "reviewer_a": "reviewed the complete 2,495-alert model-retained set and confirmed 2,246",
            "reviewer_b": "reviewed the complete 4,629-alert model-excluded set and confirmed 133",
            "reviewer_c": "independently re-reviews the combined 2,379 confirmed alerts",
        },
        "selection_seed": FULL_SELECTION_SEED,
        "ui_order_seed": FULL_UI_ORDER_SEED,
        "blindness": {
            "source_reviewer_dispositions_in_reviewer_sample": False,
            "source_reviewer_notes_in_reviewer_sample": False,
            "model_judgment_fields_blank": True,
            "authorship_group_hidden_by_ui": True,
            "residual_identity_leakage": (
                "repository paths and code can reveal identity cues; the sealed admin "
                "reference must not be shared with Reviewer C"
            ),
        },
        "estimand_boundary": (
            "Reviewer C confirmation among the 2,379 alerts selected because Reviewer A "
            "or Reviewer B labeled them confirmed_valid in separate retained and excluded "
            "censuses. Because both source-reviewer labels are constant by design, this "
            "full re-review estimates confirmation and disagreement rates, not Cohen's "
            "kappa over the complete disposition space."
        ),
        "inputs": input_state,
        "outputs": outputs,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if legacy_reference_path and legacy_reference_path != reference_path:
        legacy_reference_path.unlink()
    print(f"Frozen full independent re-review: {sample_path} (n=2,379)")
    print(f"Sealed source-reviewer key: {reference_path}")


def read_live_review_labels(database: Path) -> tuple[list[dict[str, str]], str]:
    if not database.is_file():
        raise FileNotFoundError(database)
    uri = f"file:{database.resolve()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        connection.row_factory = sqlite3.Row
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        if quick_check != "ok":
            raise ValueError(f"{database}: SQLite quick_check returned {quick_check!r}")
        rows = connection.execute(
            """
            SELECT alert_id,status,disposition,confidence,notes,flagged,revision
            FROM labels ORDER BY alert_id
            """
        ).fetchall()
    labels = [{key: str(row[key]) for key in row.keys()} for row in rows]
    canonical = b"".join(
        (
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        for row in labels
    )
    return labels, sha256_bytes(canonical)


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if total <= 0 or not (0 <= successes <= total):
        raise ValueError("invalid binomial counts")
    rate = successes / total
    denominator = 1.0 + z * z / total
    center = (rate + z * z / (2.0 * total)) / denominator
    margin = (
        z
        * math.sqrt(rate * (1.0 - rate) / total + z * z / (4.0 * total * total))
        / denominator
    )
    return center - margin, center + margin


def analyze_full_rereview(args: argparse.Namespace) -> None:
    manifest_path = args.output_dir / "preparation_manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError("run prepare-full before analyze-full")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    reference_record = manifest["outputs"]["sealed_source_reference"]
    reference_path = args.output_dir / reference_record["relative_path"]
    if sha256_file(reference_path) != reference_record["sha256"]:
        raise ValueError("sealed source-reviewer reference has changed")
    _, reference_rows = read_csv(reference_path)
    second_rows, second_state_hash = read_live_review_labels(
        args.second_review_database
    )
    references = keyed(reference_rows, "source-reviewer reference")
    seconds = keyed(second_rows, "Reviewer C full re-review")
    if set(references) != set(seconds):
        missing = len(set(references) - set(seconds))
        extra = len(set(seconds) - set(references))
        raise ValueError(
            f"independent review IDs do not match frozen set: missing={missing}, extra={extra}"
        )
    for row in second_rows:
        if row.get("status") != "completed":
            raise ValueError("all 2,379 independent labels must be completed")
        if row.get("disposition") not in DISPOSITIONS:
            raise ValueError("uncertain or invalid independent disposition remains")
        if row.get("flagged") not in {"0", "false", "False", ""}:
            raise ValueError("flagged independent decisions must be resolved")

    joined: list[dict[str, str]] = []
    for alert_id, reference in references.items():
        second = seconds[alert_id]
        joined.append(
            {
                **reference,
                "second_disposition": second["disposition"],
                "second_confidence": second.get("confidence", ""),
                "second_notes": second.get("notes", ""),
                "agreement": str(second["disposition"] == "confirmed_valid").lower(),
            }
        )
    confirmed_n = sum(
        row["second_disposition"] == "confirmed_valid" for row in joined
    )
    ci_low, ci_high = wilson_interval(confirmed_n, len(joined))

    dimensions = {
        "overall": lambda row: "all",
        "source_set": lambda row: row["source_set"],
        "source_reviewer_role": lambda row: row["source_reviewer_role"],
        "group": lambda row: row["group"],
        "issue_domain": lambda row: row["issue_domain"],
    }
    strata_rows: list[dict[str, Any]] = []
    for dimension, value_fn in dimensions.items():
        groups: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in joined:
            groups[value_fn(row)].append(row)
        for value, rows in sorted(groups.items()):
            successes = sum(
                row["second_disposition"] == "confirmed_valid" for row in rows
            )
            low, high = wilson_interval(successes, len(rows))
            strata_rows.append(
                {
                    "dimension": dimension,
                    "value": value,
                    "n": len(rows),
                    "confirmed_n": successes,
                    "confirmation_rate": f"{successes / len(rows):.12f}",
                    "wilson_95_low": f"{low:.12f}",
                    "wilson_95_high": f"{high:.12f}",
                }
            )
    disagreements = [
        {
            **row,
            "consensus_disposition": "",
            "consensus_notes": "",
        }
        for row in joined
        if row["second_disposition"] != "confirmed_valid"
    ]
    analysis_dir = args.output_dir / args.analysis_subdir
    analysis_dir.mkdir(parents=True, exist_ok=True)
    strata_path = analysis_dir / "confirmation_by_stratum.csv"
    disagreement_path = analysis_dir / "disagreements_for_consensus.csv"
    write_bytes(strata_path, csv_bytes(list(strata_rows[0]), strata_rows))
    disagreement_fields = list(disagreements[0]) if disagreements else [
        *list(joined[0]),
        "consensus_disposition",
        "consensus_notes",
    ]
    write_bytes(
        disagreement_path,
        csv_bytes(disagreement_fields, disagreements),
    )
    summary = {
        "schema_version": "1.0.0",
        "status": (
            "independent_full_rereview_complete_consensus_pending"
            if disagreements
            else "independent_full_rereview_complete_no_disagreements"
        ),
        "analyzed_at": utc_now(),
        "reviewed_n": len(joined),
        "confirmed_n": confirmed_n,
        "disagreement_n": len(disagreements),
        "confirmation_rate": confirmed_n / len(joined),
        "confirmation_rate_wilson_95": [ci_low, ci_high],
        "cohen_kappa": None,
        "kappa_reason": (
            "Undefined/not informative because the frozen full re-review set contains "
            "only source-reviewer confirmed_valid alerts."
        ),
        "boundary": manifest["estimand_boundary"],
        "inputs": {
            "preparation_manifest_sha256": sha256_file(manifest_path),
            "sealed_source_reviewer_reference_sha256": sha256_file(reference_path),
            "independent_review_database": str(args.second_review_database.resolve()),
            "independent_review_state_sha256": second_state_hash,
        },
        "outputs": {
            "confirmation_by_stratum": {
                "path": str(strata_path.resolve()),
                "sha256": sha256_file(strata_path),
            },
            "disagreements_for_consensus": {
                "path": str(disagreement_path.resolve()),
                "sha256": sha256_file(disagreement_path),
            },
        },
    }
    summary_path = analysis_dir / "confirmation_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"Independent full re-review confirmation: {confirmed_n}/{len(joined)} "
        f"({confirmed_n / len(joined):.2%}, 95% CI {ci_low:.2%}–{ci_high:.2%})"
    )
    print(f"Disagreements for consensus: {len(disagreements)} -> {disagreement_path}")


def cohen_kappa(
    first: list[str], second: list[str], weights: list[float] | None = None
) -> tuple[float, float, float]:
    if not (len(first) == len(second)) or not first:
        raise ValueError("kappa inputs must be non-empty and equally sized")
    actual_weights = weights or [1.0] * len(first)
    if len(actual_weights) != len(first):
        raise ValueError("weight count does not match label count")
    total = sum(actual_weights)
    observed = sum(
        weight for a, b, weight in zip(first, second, actual_weights) if a == b
    ) / total
    first_marginal: Counter[str] = Counter()
    second_marginal: Counter[str] = Counter()
    for a, b, weight in zip(first, second, actual_weights):
        first_marginal[a] += weight
        second_marginal[b] += weight
    expected = sum(
        (first_marginal[label] / total) * (second_marginal[label] / total)
        for label in set(first_marginal) | set(second_marginal)
    )
    kappa = (observed - expected) / (1.0 - expected) if expected < 1.0 else math.nan
    return observed, expected, kappa


def agreement_rows(joined: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dimensions = {
        "overall": lambda row: "all",
        "source": lambda row: row["reliability_source"],
        "group": lambda row: row["group"],
        "issue_domain": lambda row: row["issue_domain"],
        "first_disposition": lambda row: row["first_disposition"],
    }
    output: list[dict[str, Any]] = []
    for dimension, value_fn in dimensions.items():
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in joined:
            grouped[value_fn(row)].append(row)
        for value, rows in sorted(grouped.items()):
            weights = [float(row["design_weight"]) for row in rows]
            agree_n = sum(row["first_disposition"] == row["second_disposition"] for row in rows)
            weighted_total = sum(weights)
            weighted_agree = sum(
                weight
                for row, weight in zip(rows, weights)
                if row["first_disposition"] == row["second_disposition"]
            )
            output.append(
                {
                    "dimension": dimension,
                    "value": value,
                    "sample_n": len(rows),
                    "agreement_n": agree_n,
                    "raw_agreement": agree_n / len(rows),
                    "weighted_population_n": f"{weighted_total:.6f}",
                    "weighted_agreement": weighted_agree / weighted_total,
                }
            )
    return output


def labels_from_event_prefix(database: Path, max_event_id: int) -> tuple[list[dict[str, str]], str]:
    """Recover the last independent decision per alert from an append-only prefix."""
    if max_event_id < 1:
        raise ValueError("max_event_id must be positive")
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        events = connection.execute(
            """
            SELECT event_id,alert_id,event_json,created_at
            FROM events WHERE event_id<=? ORDER BY event_id
            """,
            (max_event_id,),
        ).fetchall()
    if not events or events[-1]["event_id"] != max_event_id:
        raise ValueError(f"event prefix does not end at event {max_event_id}")
    prefix = b"".join(
        (
            json.dumps(dict(event), ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        for event in events
    )
    latest: dict[str, dict[str, str]] = {}
    for event in events:
        payload = json.loads(event["event_json"])
        latest[event["alert_id"]] = {
            "alert_id": event["alert_id"],
            "status": str(payload.get("status", "")),
            "disposition": str(payload.get("disposition", "")),
            "confidence": str(payload.get("confidence", "")),
            "notes": str(payload.get("notes", "")),
            "flagged": "1" if payload.get("flagged") else "0",
        }
    return list(latest.values()), sha256_bytes(prefix)


def analyze(args: argparse.Namespace) -> None:
    manifest_path = args.output_dir / "sampling_manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError("run prepare before analyze")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    reference_path = args.output_dir / manifest["outputs"]["sealed_reference"]["relative_path"]
    if sha256_file(reference_path) != manifest["outputs"]["sealed_reference"]["sha256"]:
        raise ValueError("sealed first-reviewer reference has changed")
    _, reference_rows = read_csv(reference_path)
    event_prefix_sha256 = ""
    if args.max_event_id is not None:
        second_rows, event_prefix_sha256 = labels_from_event_prefix(
            args.second_review_database, args.max_event_id
        )
    else:
        _, second_rows = read_csv(args.second_labels)
    references = keyed(reference_rows, "first-reviewer reference")
    seconds = keyed(second_rows, "second-reviewer labels")
    if set(references) != set(seconds):
        raise ValueError("second-reviewer alert IDs do not exactly match the frozen sample")
    for row in second_rows:
        if row.get("status") != "completed":
            raise ValueError("all 200 second-reviewer labels must be completed")
        if row.get("disposition") not in DISPOSITIONS:
            raise ValueError("uncertain or invalid second-reviewer disposition remains")
        if row.get("flagged") not in {"0", "false", "False", ""}:
            raise ValueError("flagged second-reviewer decisions must be resolved before analysis")

    joined: list[dict[str, Any]] = []
    for alert_id, reference in references.items():
        second = seconds[alert_id]
        joined.append(
            {
                **reference,
                "second_disposition": second["disposition"],
                "second_confidence": second.get("confidence", ""),
                "second_notes": second.get("notes", ""),
                "agreement": reference["first_disposition"] == second["disposition"],
                "binary_agreement": (
                    (reference["first_disposition"] == "confirmed_valid")
                    == (second["disposition"] == "confirmed_valid")
                ),
            }
        )
    first = [row["first_disposition"] for row in joined]
    second = [row["second_disposition"] for row in joined]
    weights = [float(row["design_weight"]) for row in joined]
    raw_agreement, raw_expected, raw_kappa = cohen_kappa(first, second)
    weighted_agreement, weighted_expected, weighted_kappa = cohen_kappa(
        first, second, weights
    )
    first_binary = [
        "confirmed_valid" if value == "confirmed_valid" else "other"
        for value in first
    ]
    second_binary = [
        "confirmed_valid" if value == "confirmed_valid" else "other"
        for value in second
    ]
    binary_agreement, binary_expected, binary_kappa = cohen_kappa(
        first_binary, second_binary
    )
    (
        binary_weighted_agreement,
        binary_weighted_expected,
        binary_weighted_kappa,
    ) = cohen_kappa(first_binary, second_binary, weights)
    weighted_universe = sum(weights)
    if abs(weighted_universe - 2895.0) > 1e-6:
        raise ValueError(f"design weights sum to {weighted_universe}, expected 2895")

    analysis_dir = args.output_dir / args.analysis_subdir
    analysis_dir.mkdir(parents=True, exist_ok=True)
    labels = list(DISPOSITIONS)
    confusion_rows = []
    for first_label in labels:
        for second_label in labels:
            cell = [
                row
                for row in joined
                if row["first_disposition"] == first_label
                and row["second_disposition"] == second_label
            ]
            confusion_rows.append(
                {
                    "first_disposition": first_label,
                    "second_disposition": second_label,
                    "sample_n": len(cell),
                    "design_weighted_n": f"{sum(float(row['design_weight']) for row in cell):.6f}",
                }
            )
    confusion_path = analysis_dir / "confusion_matrix.csv"
    write_bytes(confusion_path, csv_bytes(list(confusion_rows[0]), confusion_rows))

    strata = agreement_rows(joined)
    strata_path = analysis_dir / "agreement_by_stratum.csv"
    write_bytes(strata_path, csv_bytes(list(strata[0]), strata))

    disagreements = [row for row in joined if not row["agreement"]]
    disagreement_rows = [
        {
            **row,
            "consensus_disposition": "",
            "consensus_notes": "",
        }
        for row in disagreements
    ]
    disagreement_path = analysis_dir / "disagreements_for_consensus.csv"
    fields = list(disagreement_rows[0]) if disagreement_rows else [
        *list(joined[0]),
        "consensus_disposition",
        "consensus_notes",
    ]
    write_bytes(disagreement_path, csv_bytes(fields, disagreement_rows))

    summary = {
        "schema_version": "1.0.0",
        "status": "independent_review_complete_consensus_pending"
        if disagreements
        else "independent_review_complete_no_disagreements",
        "analyzed_at": utc_now(),
        "sample_n": len(joined),
        "disagreement_n": len(disagreements),
        "binary_disagreement_n": sum(not row["binary_agreement"] for row in joined),
        "four_way_unweighted": {
            "raw_agreement": raw_agreement,
            "chance_expected_agreement": raw_expected,
            "cohen_kappa": raw_kappa,
        },
        "four_way_design_weighted_to_reviewed_universe": {
            "universe_n": weighted_universe,
            "raw_agreement": weighted_agreement,
            "chance_expected_agreement": weighted_expected,
            "cohen_kappa": weighted_kappa,
        },
        "primary_binary_unweighted": {
            "positive_label": "confirmed_valid",
            "raw_agreement": binary_agreement,
            "chance_expected_agreement": binary_expected,
            "cohen_kappa": binary_kappa,
        },
        "primary_binary_design_weighted_to_reviewed_universe": {
            "positive_label": "confirmed_valid",
            "universe_n": weighted_universe,
            "raw_agreement": binary_weighted_agreement,
            "chance_expected_agreement": binary_weighted_expected,
            "cohen_kappa": binary_weighted_kappa,
        },
        "boundary": manifest["estimand_boundary"],
        "inputs": {
            "sampling_manifest_sha256": sha256_file(manifest_path),
            "sealed_reference_sha256": sha256_file(reference_path),
            "second_reviewer_labels_sha256": (
                sha256_file(args.second_labels) if args.max_event_id is None else ""
            ),
            "second_reviewer_event_prefix_max_id": args.max_event_id,
            "second_reviewer_event_prefix_sha256": event_prefix_sha256,
        },
        "outputs": {},
    }
    for name, path in {
        "confusion_matrix": confusion_path,
        "agreement_by_stratum": strata_path,
        "disagreements_for_consensus": disagreement_path,
    }.items():
        summary["outputs"][name] = {
            "path": str(path.resolve()),
            "sha256": sha256_file(path),
        }
    summary_path = analysis_dir / "agreement_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"Four-way agreement: {raw_agreement:.2%}, kappa={raw_kappa:.3f}; "
        f"weighted agreement={weighted_agreement:.2%}, weighted kappa={weighted_kappa:.3f}"
    )
    print(
        f"Primary binary agreement: {binary_agreement:.2%}, "
        f"kappa={binary_kappa:.3f}; weighted agreement="
        f"{binary_weighted_agreement:.2%}, weighted kappa="
        f"{binary_weighted_kappa:.3f}"
    )
    print(f"Disagreements for consensus: {len(disagreements)} -> {disagreement_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    prepare_parser.add_argument(
        "--retained-payload", type=Path, default=DEFAULT_RETAINED_PAYLOAD
    )
    prepare_parser.add_argument(
        "--retained-labels", type=Path, default=DEFAULT_RETAINED_LABELS
    )
    prepare_parser.add_argument(
        "--excluded-payload", type=Path, default=DEFAULT_EXCLUDED_PAYLOAD
    )
    prepare_parser.add_argument(
        "--excluded-labels", type=Path, default=DEFAULT_EXCLUDED_LABELS
    )
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    analyze_parser.add_argument(
        "--second-labels",
        type=Path,
        default=DEFAULT_OUTPUT / "review/human_labels.csv",
    )
    analyze_parser.add_argument(
        "--second-review-database",
        type=Path,
        default=DEFAULT_OUTPUT / "review/review.sqlite3",
    )
    analyze_parser.add_argument(
        "--max-event-id",
        type=int,
        help="analyze an immutable append-only event prefix instead of the current CSV",
    )
    analyze_parser.add_argument(
        "--analysis-subdir",
        default="analysis",
        help="output directory relative to --output-dir",
    )
    prepare_full_parser = subparsers.add_parser(
        "prepare-full",
        help="freeze all 2,379 primary-confirmed alerts for an independent re-review",
    )
    prepare_full_parser.add_argument(
        "--output-dir", type=Path, default=DEFAULT_FULL_OUTPUT
    )
    prepare_full_parser.add_argument(
        "--retained-database", type=Path, default=DEFAULT_RETAINED_DATABASE
    )
    prepare_full_parser.add_argument(
        "--excluded-database", type=Path, default=DEFAULT_EXCLUDED_DATABASE
    )
    analyze_full_parser = subparsers.add_parser(
        "analyze-full",
        help="analyze the completed independent re-review of all 2,379 alerts",
    )
    analyze_full_parser.add_argument(
        "--output-dir", type=Path, default=DEFAULT_FULL_OUTPUT
    )
    analyze_full_parser.add_argument(
        "--second-review-database",
        type=Path,
        default=DEFAULT_FULL_OUTPUT / "review/review.sqlite3",
    )
    analyze_full_parser.add_argument(
        "--analysis-subdir",
        default="analysis",
        help="output directory relative to --output-dir",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "prepare":
        prepare(args)
    elif args.command == "analyze":
        analyze(args)
    elif args.command == "prepare-full":
        prepare_full_rereview(args)
    else:
        analyze_full_rereview(args)


if __name__ == "__main__":
    main()
