#!/usr/bin/env python3
"""Build a PR-complete analysis snapshot from adjudicated CodeQL alerts.

The raw snapshot remains immutable.  This script copies its PR-level table,
preserves the raw differential-alert outcomes in explicit ``raw_*`` columns,
and replaces the compatibility ``introduced_*`` outcomes with either the
strict model-adjudicated definition or, when ``--human-labels`` is supplied,
the final human-confirmed definition used by the paper.

    condition_present == yes
    and introduced_by_pr == yes
    and valid_issue == yes

All quality-gated PRs remain in the output, including PRs with zero confirmed
issues.  Human labels may cover either the legacy complete model-positive
frame or the final complete raw-differential frame.  The latter is required
for the final paper after the retained and excluded censuses, independent
positive re-review, and consensus resolution were completed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
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
DEFAULT_RAW_SNAPSHOT = REPORTS / "rq_analysis_final_20260727_v3"
DEFAULT_ADJUDICATION = (
    REPORTS
    / "codeql_alert_adjudication_20260804_v5"
    / "formal_run_20260804_v5"
    / "results"
)
DEFAULT_OUTPUT = REPORTS / "validated_issue_analysis_20260808_v1"
DEFAULT_HUMAN_LABELS = (
    REPORTS
    / "manual_validation"
    / "full_validated_2495_v1"
    / "human_labels.csv"
)

RAW_OUTCOME_FIELDS = (
    "introduced_alerts",
    "introduced_quality_alerts",
    "introduced_security_alerts",
    "introduced_quality_any",
    "introduced_security_any",
    "net_quality_count",
    "net_security_count",
)

HUMAN_DISPOSITIONS = (
    "confirmed_valid",
    "condition_absent",
    "not_pr_introduced",
    "not_valid_issue",
)

HUMAN_STRATA = (
    ("group", "group"),
    ("issue_domain", "issue_domain"),
    ("quality_category", "quality_category"),
    ("precision", "precision"),
    ("problem_severity", "problem_severity"),
    ("language", "language"),
    ("task_type", "task_type"),
    ("rule_id", "rule_id"),
)


class SnapshotError(RuntimeError):
    """Raised when a frozen input or conservation invariant is violated."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-snapshot-dir", type=Path, default=DEFAULT_RAW_SNAPSHOT)
    parser.add_argument("--adjudication-dir", type=Path, default=DEFAULT_ADJUDICATION)
    parser.add_argument(
        "--human-labels",
        type=Path,
        help=(
            "completed final human labels covering either every model-positive "
            "alert (legacy) or every raw differential alert (final paper)"
        ),
    )
    parser.add_argument(
        "--derived-snapshot-id",
        help="explicit identifier for the derived snapshot",
    )
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


def normalize_pr_number(value: Any) -> str:
    text = clean(value)
    try:
        return str(int(float(text)))
    except (TypeError, ValueError):
        return text


def pr_key(row: dict[str, str]) -> tuple[str, str, str]:
    return (
        clean(row.get("group")).casefold(),
        clean(row.get("repo_name")).casefold(),
        normalize_pr_number(row.get("pr_number")),
    )


def strict_true(value: Any) -> bool:
    return clean(value).casefold() in {"1", "true", "yes", "y"}


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    maximize_csv_field_limit()
    if not path.is_file():
        raise SnapshotError(f"missing CSV input: {path}")
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


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise SnapshotError(f"missing JSON input: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SnapshotError(f"JSON input must be an object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def output_record(path: Path, root: Path) -> dict[str, Any]:
    return {
        "path": str(path.relative_to(root)),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def model_supported(row: dict[str, str]) -> bool:
    return (
        row.get("condition_present") == "yes"
        and row.get("introduced_by_pr") == "yes"
        and row.get("valid_issue") == "yes"
    )


def actionable(row: dict[str, str]) -> bool:
    return model_supported(row) and row.get("actionability") in {
        "must_fix",
        "should_fix",
    }


def human_confirmed(row: dict[str, str]) -> bool:
    return row.get("human_disposition") == "confirmed_valid"


def determine_human_validation_scope(
    label_ids: set[str],
    *,
    all_alert_ids: set[str],
    model_positive_ids: set[str],
) -> str:
    if label_ids == all_alert_ids:
        return "complete_raw_differential_alert_frame"
    if label_ids == model_positive_ids:
        return "complete_model_positive_frame"
    raise SnapshotError(
        "human labels must cover either the complete raw-differential "
        "frame or the complete model-positive frame: "
        f"labels={len(label_ids)}, raw={len(all_alert_ids)}, "
        f"model_positive={len(model_positive_ids)}"
    )


def build_human_validation_strata(
    alert_rows: Sequence[dict[str, str]],
    *,
    expected_reviewed_n: int,
) -> list[dict[str, Any]]:
    """Summarize final human decisions within the frozen human-review frame."""

    reviewed = [row for row in alert_rows if row.get("human_status") == "completed"]
    if len(reviewed) != expected_reviewed_n:
        raise SnapshotError(
            f"expected {expected_reviewed_n:,} completed human-reviewed alerts, "
            f"found {len(reviewed)}"
        )

    output: list[dict[str, Any]] = []
    for dimension, field in HUMAN_STRATA:
        eligible = (
            [row for row in reviewed if row.get("issue_domain") == "quality"]
            if dimension == "quality_category"
            else reviewed
        )
        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in eligible:
            stratum = clean(row.get(field))
            if not stratum:
                raise SnapshotError(
                    f"missing {field} in completed human-reviewed alert "
                    f"{row.get('alert_id')}"
                )
            grouped[stratum].append(row)

        if sum(len(rows) for rows in grouped.values()) != len(eligible):
            raise SnapshotError(f"human-validation strata do not conserve {dimension}")

        for stratum in sorted(grouped):
            rows = grouped[stratum]
            counts = Counter(row.get("human_disposition") for row in rows)
            if set(counts) - set(HUMAN_DISPOSITIONS):
                raise SnapshotError(
                    f"unexpected human disposition in {dimension}={stratum}: {counts}"
                )
            confirmed = counts["confirmed_valid"]
            output.append(
                {
                    "dimension": dimension,
                    "stratum": stratum,
                    "reviewed_alert_n": len(rows),
                    "confirmed_valid_n": confirmed,
                    "confirmation_rate": f"{confirmed / len(rows):.12f}",
                    "condition_absent_n": counts["condition_absent"],
                    "not_pr_introduced_n": counts["not_pr_introduced"],
                    "not_valid_issue_n": counts["not_valid_issue"],
                }
            )
    return output


def run(args: argparse.Namespace) -> None:
    raw_dir = resolve(args.raw_snapshot_dir)
    adjudication_dir = resolve(args.adjudication_dir)
    output_dir = resolve(args.output_dir)
    human_labels_path = resolve(args.human_labels) if args.human_labels else None

    raw_manifest = load_json(raw_dir / "snapshot_manifest.json")
    adjudication_manifest = load_json(adjudication_dir / "manifest.json")
    if raw_manifest.get("snapshot_id") != "study_stars500_final_20260727_v3":
        raise SnapshotError("unexpected raw snapshot ID")
    if raw_manifest.get("rq2_ready") is not True:
        raise SnapshotError("raw snapshot is not RQ2-ready")
    if adjudication_manifest.get("status") != "formal_complete":
        raise SnapshotError("adjudication manifest is not formal_complete")

    pr_fields, pr_rows = read_csv(raw_dir / "analysis_pr_level.csv")
    alert_fields, alert_rows = read_csv(adjudication_dir / "model_adjudications.csv")
    if len(alert_rows) != 7_124:
        raise SnapshotError(f"expected 7,124 adjudications, found {len(alert_rows)}")
    alert_ids = [row.get("alert_id", "") for row in alert_rows]
    if not all(alert_ids) or len(set(alert_ids)) != len(alert_ids):
        raise SnapshotError("adjudication alert IDs are missing or duplicated")

    human_by_alert: dict[str, dict[str, str]] = {}
    human_validation_scope: str | None = None
    if human_labels_path is not None:
        human_fields, human_rows = read_csv(human_labels_path)
        required_human = {
            "alert_id",
            "status",
            "disposition",
            "human_condition_present",
            "human_introduced_by_pr",
            "human_valid_issue",
        }
        if missing := required_human - set(human_fields):
            raise SnapshotError(f"human labels missing fields: {sorted(missing)}")
        for row in human_rows:
            alert_id = row.get("alert_id", "")
            if not alert_id or alert_id in human_by_alert:
                raise SnapshotError(f"missing or duplicate human alert ID: {alert_id!r}")
            if row.get("status") != "completed":
                raise SnapshotError(f"human label is not completed: {alert_id}")
            if row.get("disposition") not in HUMAN_DISPOSITIONS:
                raise SnapshotError(
                    f"invalid final human disposition for {alert_id}: {row.get('disposition')}"
                )
            human_by_alert[alert_id] = row
        model_positive_ids = {
            row["alert_id"] for row in alert_rows if model_supported(row)
        }
        all_alert_ids = set(alert_ids)
        human_validation_scope = determine_human_validation_scope(
            set(human_by_alert),
            all_alert_ids=all_alert_ids,
            model_positive_ids=model_positive_ids,
        )
        for row in alert_rows:
            decision = human_by_alert.get(row["alert_id"])
            if decision:
                row.update(
                    {
                        "human_status": decision["status"],
                        "human_disposition": decision["disposition"],
                        "human_condition_present": decision[
                            "human_condition_present"
                        ],
                        "human_introduced_by_pr": decision[
                            "human_introduced_by_pr"
                        ],
                        "human_valid_issue": decision["human_valid_issue"],
                        "human_actionability": decision.get(
                            "human_actionability", ""
                        ),
                        "human_confidence": decision.get("confidence", ""),
                        "human_notes": decision.get("notes", ""),
                        "human_revision": decision.get("revision", ""),
                        "human_source_set": decision.get("source_set", ""),
                        "human_source_disposition": decision.get(
                            "source_disposition", ""
                        ),
                        "human_independent_rereview_disposition": decision.get(
                            "independent_rereview_disposition", ""
                        ),
                        "human_consensus_disposition": decision.get(
                            "consensus_disposition", ""
                        ),
                        "human_resolution_basis": decision.get(
                            "resolution_basis", ""
                        ),
                    }
                )

    gated: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in pr_rows:
        if not strict_true(row.get("quality_gate_pass")):
            continue
        key = pr_key(row)
        if key in gated:
            raise SnapshotError(f"duplicate quality-gated PR: {key}")
        gated[key] = row
    if len(gated) != 5_404:
        raise SnapshotError(f"expected 5,404 quality-gated PRs, found {len(gated)}")

    counters: dict[tuple[str, str, str], Counter[str]] = defaultdict(Counter)
    pr_sets: dict[tuple[str, str, str], set[tuple[str, str, str]]] = defaultdict(set)
    layers = {
        "raw_differential": lambda row: True,
        "condition_present": lambda row: row.get("condition_present") == "yes",
        "pr_attributed": lambda row: (
            row.get("condition_present") == "yes"
            and row.get("introduced_by_pr") == "yes"
        ),
        "validated_issue": model_supported,
    }
    if human_by_alert:
        layers["human_confirmed_issue"] = human_confirmed
        primary_predicate = human_confirmed
    else:
        layers["actionable_issue"] = actionable
        primary_predicate = model_supported

    for row in alert_rows:
        key = pr_key(row)
        if key not in gated:
            raise SnapshotError(f"adjudicated alert is outside the frozen roster: {key}")
        domain = row.get("issue_domain")
        if domain not in {"quality", "security"}:
            raise SnapshotError(f"invalid issue_domain for {row.get('alert_id')}: {domain}")
        for layer, predicate in layers.items():
            if predicate(row):
                counters[key][f"{layer}_{domain}"] += 1
                pr_sets[(layer, domain, row["group"])].add(key)

    derived_fields = list(pr_fields)
    for field in RAW_OUTCOME_FIELDS:
        raw_field = f"raw_{field}"
        if raw_field not in derived_fields:
            derived_fields.append(raw_field)
    for field in (
        "outcome_measurement_layer",
        "validated_quality_alerts",
        "validated_security_alerts",
        "validated_quality_any",
        "validated_security_any",
        "attributed_quality_alerts",
        "attributed_security_alerts",
        "condition_present_quality_alerts",
        "condition_present_security_alerts",
        "actionable_quality_alerts",
        "actionable_security_alerts",
    ):
        if field not in derived_fields:
            derived_fields.append(field)

    derived_rows: list[dict[str, Any]] = []
    for source in pr_rows:
        row: dict[str, Any] = dict(source)
        for field in RAW_OUTCOME_FIELDS:
            row[f"raw_{field}"] = source.get(field, "")
        key = pr_key(source)
        if strict_true(source.get("quality_gate_pass")):
            count = counters[key]
            primary_layer = (
                "human_confirmed_issue" if human_by_alert else "validated_issue"
            )
            quality = count[f"{primary_layer}_quality"]
            security = count[f"{primary_layer}_security"]
            row.update(
                {
                    "outcome_measurement_layer": (
                        (
                            "human_consensus_complete_differential_frame_v1"
                            if human_validation_scope
                            == "complete_raw_differential_alert_frame"
                            else "human_confirmed_model_adjudicated_issue_v1"
                        )
                        if human_by_alert
                        else "model_adjudicated_validated_issue_v1"
                    ),
                    "introduced_alerts": quality + security,
                    "introduced_quality_alerts": quality,
                    "introduced_security_alerts": security,
                    "introduced_quality_any": int(quality > 0),
                    "introduced_security_any": int(security > 0),
                    "net_quality_count": "",
                    "net_security_count": "",
                    "validated_quality_alerts": quality,
                    "validated_security_alerts": security,
                    "validated_quality_any": int(quality > 0),
                    "validated_security_any": int(security > 0),
                    "attributed_quality_alerts": count["pr_attributed_quality"],
                    "attributed_security_alerts": count["pr_attributed_security"],
                    "condition_present_quality_alerts": count[
                        "condition_present_quality"
                    ],
                    "condition_present_security_alerts": count[
                        "condition_present_security"
                    ],
                    "actionable_quality_alerts": (
                        "" if human_by_alert else count["actionable_issue_quality"]
                    ),
                    "actionable_security_alerts": (
                        "" if human_by_alert else count["actionable_issue_security"]
                    ),
                }
            )
        derived_rows.append(row)

    funnel_rows: list[dict[str, Any]] = []
    for layer, predicate in layers.items():
        for group in ("ai", "human", "all"):
            for domain in ("quality", "security", "all"):
                selected = [
                    row
                    for row in alert_rows
                    if predicate(row)
                    and (group == "all" or row["group"] == group)
                    and (domain == "all" or row["issue_domain"] == domain)
                ]
                raw_denominator = sum(
                    1
                    for row in alert_rows
                    if (group == "all" or row["group"] == group)
                    and (domain == "all" or row["issue_domain"] == domain)
                )
                funnel_rows.append(
                    {
                        "layer": layer,
                        "group": group,
                        "domain": domain,
                        "alert_n": len(selected),
                        "raw_alert_n": raw_denominator,
                        "retention_rate": (
                            f"{len(selected) / raw_denominator:.12f}"
                            if raw_denominator
                            else ""
                        ),
                        "affected_pr_n": len({pr_key(row) for row in selected}),
                    }
                )

    output_dir.mkdir(parents=True, exist_ok=True)
    pr_output = output_dir / "analysis_pr_level.csv"
    alert_output = output_dir / "validated_alerts.csv"
    funnel_output = output_dir / "adjudication_funnel.csv"
    write_csv(pr_output, derived_fields, derived_rows)
    validated_alert_fields = list(alert_fields)
    if "is_security_alert" not in validated_alert_fields:
        validated_alert_fields.append("is_security_alert")
    for field in (
        "human_status",
        "human_disposition",
        "human_condition_present",
        "human_introduced_by_pr",
        "human_valid_issue",
        "human_actionability",
        "human_confidence",
        "human_notes",
        "human_revision",
        "human_source_set",
        "human_source_disposition",
        "human_independent_rereview_disposition",
        "human_consensus_disposition",
        "human_resolution_basis",
    ):
        if human_by_alert and field not in validated_alert_fields:
            validated_alert_fields.append(field)
    validated_alert_rows = []
    for source in alert_rows:
        if not primary_predicate(source):
            continue
        row = dict(source)
        row["is_security_alert"] = str(source.get("issue_domain") == "security")
        validated_alert_rows.append(row)
    write_csv(alert_output, validated_alert_fields, validated_alert_rows)
    write_csv(
        funnel_output,
        ("layer", "group", "domain", "alert_n", "raw_alert_n", "retention_rate", "affected_pr_n"),
        funnel_rows,
    )

    disposition_output: Path | None = None
    strata_output: Path | None = None
    if human_by_alert:
        disposition_output = output_dir / "human_validation_dispositions.csv"
        disposition_rows: list[dict[str, Any]] = []
        for group in ("all", "ai", "human"):
            for domain in ("all", "quality", "security"):
                selected = [
                    row
                    for row in alert_rows
                    if row.get("human_status") == "completed"
                    and (group == "all" or row["group"] == group)
                    and (domain == "all" or row["issue_domain"] == domain)
                ]
                for disposition in HUMAN_DISPOSITIONS:
                    count = sum(
                        row.get("human_disposition") == disposition for row in selected
                    )
                    disposition_rows.append(
                        {
                            "group": group,
                            "domain": domain,
                            "disposition": disposition,
                            "alert_n": count,
                            "reviewed_alert_n": len(selected),
                            "rate": f"{count / len(selected):.12f}" if selected else "",
                        }
                    )
        write_csv(
            disposition_output,
            ("group", "domain", "disposition", "alert_n", "reviewed_alert_n", "rate"),
            disposition_rows,
        )
        strata_output = output_dir / "human_validation_strata.csv"
        write_csv(
            strata_output,
            (
                "dimension",
                "stratum",
                "reviewed_alert_n",
                "confirmed_valid_n",
                "confirmation_rate",
                "condition_absent_n",
                "not_pr_introduced_n",
                "not_valid_issue_n",
            ),
            build_human_validation_strata(
                alert_rows, expected_reviewed_n=len(human_by_alert)
            ),
        )

    quality_total = sum(primary_predicate(row) and row["issue_domain"] == "quality" for row in alert_rows)
    security_total = sum(primary_predicate(row) and row["issue_domain"] == "security" for row in alert_rows)
    if human_validation_scope == "complete_raw_differential_alert_frame":
        expected_totals = (2_194, 128)
    elif human_by_alert:
        expected_totals = (2_116, 130)
    else:
        expected_totals = (2_328, 167)
    if (quality_total, security_total) != expected_totals:
        raise SnapshotError(
            "validated Quality/Security conservation failed: "
            f"{quality_total}/{security_total}; expected {expected_totals}"
        )
    gated_outputs = [row for row in derived_rows if strict_true(row.get("quality_gate_pass"))]
    if sum(int(row["introduced_quality_alerts"]) for row in gated_outputs) != quality_total:
        raise SnapshotError("PR-level Quality counts do not conserve alert-level counts")
    if sum(int(row["introduced_security_alerts"]) for row in gated_outputs) != security_total:
        raise SnapshotError("PR-level Security counts do not conserve alert-level counts")

    manifest = {
        "schema_version": "1.0.0",
        "status": "final_ready",
        "rq2_ready": True,
        "snapshot_id": str(raw_manifest["snapshot_id"]),
        "derived_snapshot_id": (
            clean(args.derived_snapshot_id)
            or (
                "final_human_confirmed_issue_analysis_20260817_v1"
                if human_validation_scope
                == "complete_raw_differential_alert_frame"
                else (
                    "human_validated_issue_analysis_20260813_v1"
                    if human_by_alert
                    else "validated_issue_analysis_20260808_v1"
                )
            )
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "adjudicator_type": (
            "model_screen_then_complete_human_census_and_consensus"
            if human_validation_scope == "complete_raw_differential_alert_frame"
            else "model_then_human"
            if human_by_alert
            else "model"
        ),
        "ground_truth_claimed": False,
        "human_validation_scope": human_validation_scope,
        "primary_outcome_definition": {
            "condition_present": "yes",
            "introduced_by_pr": "yes",
            "valid_issue": "yes",
            "actionability_filter": None,
            "final_human_disposition": (
                "confirmed_valid" if human_by_alert else None
            ),
        },
        "analysis_population": raw_manifest.get("analysis_population"),
        "counts": {
            "raw_differential_alert_n": len(alert_rows),
            "validated_issue_n": quality_total + security_total,
            "validated_quality_n": quality_total,
            "validated_security_n": security_total,
            "quality_gated_pr_n": len(gated),
        },
        "inputs": {
            "raw_snapshot_manifest_sha256": sha256_file(
                raw_dir / "snapshot_manifest.json"
            ),
            "adjudication_manifest_sha256": sha256_file(
                adjudication_dir / "manifest.json"
            ),
            "model_adjudications_sha256": sha256_file(
                adjudication_dir / "model_adjudications.csv"
            ),
        },
        "outputs": [],
    }
    manifest_path = output_dir / "snapshot_manifest.json"
    if human_labels_path is not None:
        manifest["inputs"]["human_labels_sha256"] = sha256_file(human_labels_path)
        manifest["counts"]["human_reviewed_alert_n"] = len(human_by_alert)
        manifest["counts"]["human_reviewed_model_positive_n"] = sum(
            alert_id in human_by_alert
            for alert_id in {
                row["alert_id"] for row in alert_rows if model_supported(row)
            }
        )
    output_paths = [pr_output, alert_output, funnel_output]
    if disposition_output is not None:
        output_paths.append(disposition_output)
    if strata_output is not None:
        output_paths.append(strata_output)
    for path in output_paths:
        manifest["outputs"].append(output_record(path, output_dir))
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        "Validated-issue snapshot complete: "
        f"PRs={len(gated):,}, Quality={quality_total:,}, Security={security_total:,}, "
        f"output={output_dir}"
    )


def main() -> None:
    run(parse_args())


if __name__ == "__main__":
    main()
