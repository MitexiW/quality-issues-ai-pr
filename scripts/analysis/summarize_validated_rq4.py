#!/usr/bin/env python3
"""Re-score the frozen LLM-review outputs on validated CodeQL references.

No model call is made.  The script joins every frozen RQ4 reference to the
completed full-alert adjudication, filters the strict validated-issue layer,
and recomputes recovery metrics from the existing semantic same-root-cause
decisions.  The original differential-reference metrics are retained as a
sensitivity rather than overwritten.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

import numpy as np
from statsmodels.stats.proportion import proportion_confint


ROOT = Path(__file__).resolve().parents[2]
REPORTS = (
    ROOT
    / "data"
    / "experiments"
    / "security-and-quality"
    / "study_stars500"
    / "reports"
)
DEFAULT_ADJUDICATIONS = (
    REPORTS
    / "codeql_alert_adjudication_20260804_v5"
    / "formal_run_20260804_v5"
    / "results"
    / "model_adjudications.csv"
)
DEFAULT_REFERENCES = (
    REPORTS
    / "rq3_semantic_results_20260729_v1"
    / "semantic_reference_recovery.csv"
)
DEFAULT_CASES = REPORTS / "rq3_formal_plan_20260727_v1" / "formal_cases.csv"
DEFAULT_OUTPUT = REPORTS / "validated_issue_rq4_20260808_v1"
DEFAULT_HUMAN_LABELS = (
    REPORTS
    / "manual_validation"
    / "full_validated_2495_v1"
    / "human_labels.csv"
)


class RQ4Error(RuntimeError):
    """Raised when the frozen references cannot be joined or conserved."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adjudications", type=Path, default=DEFAULT_ADJUDICATIONS)
    parser.add_argument("--references", type=Path, default=DEFAULT_REFERENCES)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument(
        "--human-labels",
        type=Path,
        help="optional completed human review export; confirmed_valid becomes primary",
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--bootstrap-draws", type=int, default=50_000)
    parser.add_argument("--seed", type=int, default=20260623)
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


def join_key(row: dict[str, str]) -> tuple[str, ...]:
    return (
        clean(row.get("group")).casefold(),
        clean(row.get("repo_name")).casefold(),
        normalize_pr_number(row.get("pr_number")),
        clean(row.get("rule_id")),
        clean(row.get("file_path")),
        normalize_pr_number(row.get("start_line")),
        clean(row.get("fingerprint")),
    )


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    maximize_csv_field_limit()
    if not path.is_file():
        raise RQ4Error(f"missing CSV input: {path}")
    with path.open("r", encoding="utf-8", newline="") as handle:
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


def strict_valid(row: dict[str, str]) -> bool:
    return (
        row.get("condition_present") == "yes"
        and row.get("introduced_by_pr") == "yes"
        and row.get("valid_issue") == "yes"
    )


def recovered(row: dict[str, str]) -> bool:
    return row.get("semantic_recovered") == "1"


def wilson(success: int, total: int) -> tuple[float, float]:
    low, high = proportion_confint(success, total, alpha=0.05, method="wilson")
    return float(low), float(high)


def group_metrics(rows: list[dict[str, str]], group: str) -> dict[str, Any]:
    selected = [row for row in rows if row["group"] == group]
    by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in selected:
        by_case[row["case_id"]].append(row)
    reference_n = len(selected)
    recovered_n = sum(recovered(row) for row in selected)
    positive_pr_n = len(by_case)
    hit_pr_n = sum(any(recovered(row) for row in values) for values in by_case.values())
    macro = (
        sum(sum(recovered(row) for row in values) / len(values) for values in by_case.values())
        / positive_pr_n
    )
    micro_ci = wilson(recovered_n, reference_n)
    hit_ci = wilson(hit_pr_n, positive_pr_n)
    return {
        "group": group,
        "positive_pr_n": positive_pr_n,
        "reference_n": reference_n,
        "recovered_n": recovered_n,
        "micro_recall": recovered_n / reference_n,
        "micro_ci_low": micro_ci[0],
        "micro_ci_high": micro_ci[1],
        "macro_recall": macro,
        "hit_pr_n": hit_pr_n,
        "pr_hit_rate": hit_pr_n / positive_pr_n,
        "hit_ci_low": hit_ci[0],
        "hit_ci_high": hit_ci[1],
    }


def bootstrap_differences(
    rows: list[dict[str, str]], draws: int, seed: int
) -> dict[str, dict[str, float]]:
    by_group: dict[str, list[tuple[int, int]]] = {}
    for group in ("ai", "human"):
        by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in rows:
            if row["group"] == group:
                by_case[row["case_id"]].append(row)
        by_group[group] = [
            (len(values), sum(recovered(row) for row in values))
            for values in by_case.values()
        ]
    rng = np.random.default_rng(seed)
    sampled: dict[str, dict[str, np.ndarray]] = {}
    for group, values in by_group.items():
        array = np.asarray(values, dtype=float)
        n = len(array)
        metrics = {name: np.empty(draws) for name in ("micro", "macro", "hit")}
        for draw in range(draws):
            sample = array[rng.integers(0, n, size=n)]
            metrics["micro"][draw] = sample[:, 1].sum() / sample[:, 0].sum()
            metrics["macro"][draw] = np.mean(sample[:, 1] / sample[:, 0])
            metrics["hit"][draw] = np.mean(sample[:, 1] > 0)
        sampled[group] = metrics
    result: dict[str, dict[str, float]] = {}
    for metric in ("micro", "macro", "hit"):
        difference = sampled["ai"][metric] - sampled["human"][metric]
        result[metric] = {
            "ci_low": float(np.quantile(difference, 0.025)),
            "ci_high": float(np.quantile(difference, 0.975)),
        }
    return result


def run(args: argparse.Namespace) -> None:
    adjudication_path = resolve(args.adjudications)
    reference_path = resolve(args.references)
    cases_path = resolve(args.cases)
    output_dir = resolve(args.output_dir)
    adjudication_fields, adjudications = read_csv(adjudication_path)
    reference_fields, references = read_csv(reference_path)
    _, cases = read_csv(cases_path)
    human_labels_path = resolve(args.human_labels) if args.human_labels else None
    human_by_alert: dict[str, dict[str, str]] = {}
    if human_labels_path is not None:
        _, human_rows = read_csv(human_labels_path)
        for row in human_rows:
            alert_id = row.get("alert_id", "")
            if not alert_id or alert_id in human_by_alert:
                raise RQ4Error(f"missing or duplicate human alert ID: {alert_id!r}")
            if row.get("status") != "completed":
                raise RQ4Error(f"human label is not completed: {alert_id}")
            human_by_alert[alert_id] = row

    adjudication_alert_ids = [row.get("alert_id", "") for row in adjudications]
    if "" in adjudication_alert_ids or len(set(adjudication_alert_ids)) != len(
        adjudication_alert_ids
    ):
        raise RQ4Error("adjudications must contain unique, non-empty alert IDs")
    adjudication_alert_id_set = set(adjudication_alert_ids)
    extra_human_ids = set(human_by_alert) - adjudication_alert_id_set
    if extra_human_ids:
        raise RQ4Error(
            "human labels contain alert IDs outside the adjudication frame: "
            f"{sorted(extra_human_ids)[:3]}"
        )
    if not human_by_alert:
        human_validation_scope = "model_only"
    elif set(human_by_alert) == adjudication_alert_id_set:
        human_validation_scope = "complete_raw_differential_census"
    else:
        human_validation_scope = "partial_human_label_frame"
    all_case_ids = {row.get("case_id", "") for row in cases}
    if len(cases) != 267 or len(all_case_ids) != 267 or "" in all_case_ids:
        raise RQ4Error("formal case plan must contain 267 unique case IDs")

    index: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in adjudications:
        index[join_key(row)].append(row)
    joined: list[dict[str, str]] = []
    for reference in references:
        matches = index.get(join_key(reference), [])
        if len(matches) != 1:
            raise RQ4Error(
                f"reference {reference.get('reference_id')} has {len(matches)} adjudication matches"
            )
        merged = dict(reference)
        decision = matches[0]
        for field in (
            "alert_id",
            "condition_present",
            "introduced_by_pr",
            "valid_issue",
            "actionability",
            "confidence",
            "model_supported_introduced_issue",
        ):
            merged[f"adjudication_{field}"] = decision.get(field, "")
        human = human_by_alert.get(decision.get("alert_id", ""))
        if human_by_alert:
            merged["human_review_status"] = human.get("status", "") if human else ""
            merged["human_disposition"] = human.get("disposition", "") if human else ""
            merged["human_confidence"] = human.get("confidence", "") if human else ""
            merged["validated_issue_reference"] = int(
                bool(human) and human.get("disposition") == "confirmed_valid"
            )
        else:
            merged["validated_issue_reference"] = int(strict_valid(decision))
        joined.append(merged)

    if len(joined) != 571:
        raise RQ4Error(f"expected 571 joined references, found {len(joined)}")
    primary_raw = [row for row in joined if row["quality_primary_reference"] == "True"]
    primary_validated = [
        row for row in primary_raw if row["validated_issue_reference"] == 1
    ]
    if len(primary_raw) != 420:
        raise RQ4Error(
            f"unexpected primary raw count: {len(primary_raw)}"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    joined_fields = list(reference_fields) + [
        "adjudication_alert_id",
        "adjudication_condition_present",
        "adjudication_introduced_by_pr",
        "adjudication_valid_issue",
        "adjudication_actionability",
        "adjudication_confidence",
        "adjudication_model_supported_introduced_issue",
        "human_review_status",
        "human_disposition",
        "human_confidence",
        "validated_issue_reference",
    ]
    joined_path = output_dir / "reference_adjudication_join.csv"
    write_csv(joined_path, joined_fields, joined)

    metric_rows: list[dict[str, Any]] = []
    summaries: dict[str, Any] = {}
    validated_layer = (
        "human_confirmed_primary" if human_by_alert else "validated_issue_primary"
    )
    for layer, rows in (
        ("raw_differential_primary", primary_raw),
        (validated_layer, primary_validated),
    ):
        group_rows = [group_metrics(rows, group) for group in ("ai", "human")]
        ai, human = group_rows
        differences = bootstrap_differences(rows, args.bootstrap_draws, args.seed)
        for row in group_rows:
            row["layer"] = layer
            metric_rows.append(row)
        summaries[layer] = {
            "groups": {row["group"]: row for row in group_rows},
            "differences": {
                "micro_recall": {
                    "estimate": ai["micro_recall"] - human["micro_recall"],
                    **differences["micro"],
                },
                "macro_recall": {
                    "estimate": ai["macro_recall"] - human["macro_recall"],
                    **differences["macro"],
                },
                "pr_hit_rate": {
                    "estimate": ai["pr_hit_rate"] - human["pr_hit_rate"],
                    **differences["hit"],
                },
            },
        }

    metrics_path = output_dir / "group_metrics.csv"
    write_csv(
        metrics_path,
        (
            "layer",
            "group",
            "positive_pr_n",
            "reference_n",
            "recovered_n",
            "micro_recall",
            "micro_ci_low",
            "micro_ci_high",
            "macro_recall",
            "hit_pr_n",
            "pr_hit_rate",
            "hit_ci_low",
            "hit_ci_high",
        ),
        metric_rows,
    )

    validated_positive_case_ids = {row["case_id"] for row in primary_validated}
    result = {
        "schema_version": "1.0.0",
        "status": "formal_complete",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_calls_added": 0,
        "frozen_review_case_n": len(all_case_ids),
        "strict_validated_positive_case_n": len(validated_positive_case_ids),
        "human_validation_scope": human_validation_scope,
        "primary_reference_definition": (
            "final_human_consensus_complete_differential_frame"
            if human_validation_scope == "complete_raw_differential_census"
            else "human_confirmed_model_positive"
            if human_by_alert
            else "strict_model_adjudicated"
        ),
        "strict_reference_negative_reviewed_case_n": len(all_case_ids - validated_positive_case_ids),
        "reference_join": {
            "reference_n": len(joined),
            "matched_n": len(joined),
            "missing_n": 0,
            "ambiguous_n": 0,
        },
        "summaries": summaries,
        "secondary_validated_security": {
            "reference_n": sum(
                row["reference_family"] == "security"
                and row["validated_issue_reference"] == 1
                for row in joined
            ),
            "recovered_n": sum(
                row["reference_family"] == "security"
                and row["validated_issue_reference"] == 1
                and recovered(row)
                for row in joined
            ),
        },
        "inputs": {
            "adjudications_sha256": sha256_file(adjudication_path),
            "references_sha256": sha256_file(reference_path),
            "formal_cases_sha256": sha256_file(cases_path),
        },
        "outputs": {},
    }
    if human_labels_path is not None:
        result["inputs"]["human_labels_sha256"] = sha256_file(human_labels_path)
    summary_path = output_dir / "summary.json"
    for path in (joined_path, metrics_path):
        result["outputs"][path.name] = {
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
    summary_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Validated RQ4 re-score complete: "
        f"raw={len(primary_raw)}, validated={len(primary_validated)}, "
        f"recovered={sum(recovered(row) for row in primary_validated)}, "
        f"output={output_dir}"
    )


def main() -> None:
    run(parse_args())


if __name__ == "__main__":
    main()
