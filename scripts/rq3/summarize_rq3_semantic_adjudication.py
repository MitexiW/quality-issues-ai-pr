#!/usr/bin/env python3
# RQ3 review experiment entry point.
"""Summarize frozen RQ3 results after semantic relation adjudication.

The automatic matcher and semantic adjudication are intentionally reported
side by side.  Semantic ``same_issue`` labels recover CodeQL references;
``related_distinct`` never counts as a recovery.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import random
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable


SEED = 20260623
BOOTSTRAP_REPETITIONS = 50_000
AUTO_RECOVERED_STATUSES = {
    "compatible_location_recovery",
    "off_target_reference_recovery",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--formal-results", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def write_csv(
    path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None
) -> None:
    if fields is None:
        fields = list(rows[0]) if rows else []
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=fields, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def write_json(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes"}


def as_int(value: str) -> int:
    return int(value) if value else 0


def as_float(value: str) -> float:
    return float(value) if value else 0.0


def ratio(numerator: int | float, denominator: int | float) -> float | None:
    return numerator / denominator if denominator else None


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float | None, float | None]:
    if not total:
        return None, None
    p = successes / total
    z2 = z * z
    denominator = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denominator
    spread = (
        z
        * math.sqrt(p * (1 - p) / total + z2 / (4 * total * total))
        / denominator
    )
    return max(0.0, center - spread), min(1.0, center + spread)


def percentile(values: list[float], proportion: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    position = (len(ordered) - 1) * proportion
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (
        position - lower
    )


def bootstrap_difference(
    ai_rows: list[dict[str, Any]],
    human_rows: list[dict[str, Any]],
    statistic: Callable[[list[dict[str, Any]]], float],
    *,
    seed_offset: int,
) -> tuple[float, float]:
    rng = random.Random(SEED + seed_offset)
    differences: list[float] = []
    for _ in range(BOOTSTRAP_REPETITIONS):
        ai_sample = [rng.choice(ai_rows) for _ in ai_rows]
        human_sample = [rng.choice(human_rows) for _ in human_rows]
        differences.append(statistic(ai_sample) - statistic(human_sample))
    return percentile(differences, 0.025), percentile(differences, 0.975)


def fisher_two_sided(a: int, b: int, c: int, d: int) -> float:
    """Two-sided Fisher exact p-value for [[a,b],[c,d]]."""

    row1 = a + b
    row2 = c + d
    column1 = a + c
    total = row1 + row2

    def probability(x: int) -> float:
        return (
            math.comb(column1, x)
            * math.comb(total - column1, row1 - x)
            / math.comb(total, row1)
        )

    low = max(0, row1 - (total - column1))
    high = min(row1, column1)
    observed = probability(a)
    return min(
        1.0,
        sum(
            probability(x)
            for x in range(low, high + 1)
            if probability(x) <= observed + 1e-15
        ),
    )


def mean(values: Iterable[float]) -> float:
    materialized = list(values)
    return statistics.fmean(materialized) if materialized else math.nan


def main() -> None:
    args = parse_args()
    workspace = Path(args.workspace).resolve()
    formal_results = Path(args.formal_results).resolve()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)

    cases = read_csv(workspace / "cases.csv")
    findings = read_csv(workspace / "findings_for_adjudication.csv")
    references = read_csv(workspace / "references_for_adjudication.csv")
    labels = read_csv(workspace / "finding_labels.csv")
    frozen_case_metrics = read_csv(formal_results / "case_metrics.csv")

    if len(cases) != 267 or len(findings) != 1016 or len(references) != 571:
        raise SystemExit(
            "Unexpected frozen frame size; refusing to summarize a changed run"
        )
    if any(not row["codeql_relation"] for row in labels):
        raise SystemExit("Semantic relation adjudication is incomplete")

    label_by_finding = {row["model_finding_id"]: row for row in labels}
    finding_by_id = {row["model_finding_id"]: row for row in findings}
    reference_by_id = {row["reference_id"]: row for row in references}
    frozen_metrics_by_case = {
        row["case_id"]: row for row in frozen_case_metrics
    }

    semantic_finding_rows: list[dict[str, Any]] = []
    matched_findings_by_reference: dict[str, set[str]] = defaultdict(set)
    relations_by_case: dict[str, Counter[str]] = defaultdict(Counter)
    for finding in findings:
        label = label_by_finding[finding["model_finding_id"]]
        matched = [
            value
            for value in label["matched_reference_ids"].split("|")
            if value
        ]
        for reference_id in matched:
            if reference_id not in reference_by_id:
                raise SystemExit(f"Unknown matched reference {reference_id}")
            matched_findings_by_reference[reference_id].add(
                finding["model_finding_id"]
            )
        relation = label["codeql_relation"]
        relations_by_case[finding["case_id"]][relation] += 1
        automatic_recovered = finding["match_status"] in AUTO_RECOVERED_STATUSES
        semantic_finding_rows.append(
            {
                **finding,
                "finding_validity": label["finding_validity"],
                "codeql_relation": relation,
                "matched_reference_ids": label["matched_reference_ids"],
                "relation_confidence": label["confidence"],
                "relation_rationale": label["rationale"],
                "adjudicator": label["adjudicator"],
                "adjudicator_type": label["adjudicator_type"],
                "automatic_recovered": int(automatic_recovered),
                "automatic_semantic_agreement": int(
                    automatic_recovered == (relation == "same_issue")
                ),
            }
        )

    semantic_reference_rows: list[dict[str, Any]] = []
    reference_counts_by_case: dict[str, Counter[str]] = defaultdict(Counter)
    for reference in references:
        reference_id = reference["reference_id"]
        recovered_by = sorted(matched_findings_by_reference[reference_id])
        semantic_recovered = bool(recovered_by)
        tier_names = []
        if as_bool(reference["quality_primary_reference"]):
            tier_names.append("quality_primary")
        if as_bool(reference["quality_strict_reference"]):
            tier_names.append("quality_strict")
        if as_bool(reference["quality_broad_reference"]):
            tier_names.append("quality_broad")
        if reference["reference_family"] == "security":
            tier_names.append("security")
        for tier in tier_names:
            reference_counts_by_case[reference["case_id"]][f"{tier}_n"] += 1
            if semantic_recovered:
                reference_counts_by_case[reference["case_id"]][
                    f"{tier}_recovered_n"
                ] += 1
        semantic_reference_rows.append(
            {
                **reference,
                "semantic_recovered": int(semantic_recovered),
                "semantic_recovered_by_finding_ids": "|".join(recovered_by),
                "automatic_semantic_agreement": int(
                    as_bool(reference["automatic_recovered"])
                    == semantic_recovered
                ),
            }
        )

    semantic_case_rows: list[dict[str, Any]] = []
    for case in cases:
        case_id = case["case_id"]
        frozen = frozen_metrics_by_case[case_id]
        relations = relations_by_case[case_id]
        refs = reference_counts_by_case[case_id]
        row: dict[str, Any] = {
            **case,
            "model_output_valid": frozen["model_output_valid"],
            "invalid_model_output_reason": frozen[
                "invalid_model_output_reason"
            ],
            "review_finding_n": frozen["review_finding_n"],
            "semantic_same_issue_finding_n": relations["same_issue"],
            "semantic_related_distinct_finding_n": relations[
                "related_distinct"
            ],
            "semantic_no_match_finding_n": relations["no_match"],
            "semantic_no_reference_finding_n": relations["no_reference"],
            "latency_ms": frozen["latency_ms"],
            "sdk_reported_cost_usd": frozen["total_cost_usd"],
        }
        for tier in (
            "quality_primary",
            "quality_strict",
            "quality_broad",
            "security",
        ):
            n = refs[f"{tier}_n"]
            recovered = refs[f"{tier}_recovered_n"]
            row[f"{tier}_reference_n"] = n
            row[f"{tier}_automatic_recovered_n"] = as_int(
                frozen.get(f"{tier}_recovered_n", "")
            )
            row[f"{tier}_semantic_recovered_n"] = recovered
            row[f"{tier}_semantic_recovery_rate"] = (
                recovered / n if n else ""
            )
            row[f"{tier}_semantic_pr_hit"] = int(recovered > 0)
        semantic_case_rows.append(row)

    positive_rows = [
        row
        for row in semantic_case_rows
        if row["case_control"] == "positive"
    ]
    groups = {
        group: [row for row in positive_rows if row["group"] == group]
        for group in ("ai", "human")
    }

    def macro_primary(rows: list[dict[str, Any]]) -> float:
        return mean(
            float(row["quality_primary_semantic_recovery_rate"])
            for row in rows
        )

    def pr_hit(rows: list[dict[str, Any]]) -> float:
        return mean(
            float(row["quality_primary_semantic_pr_hit"]) for row in rows
        )

    def micro_primary(rows: list[dict[str, Any]]) -> float:
        denominator = sum(
            int(row["quality_primary_reference_n"]) for row in rows
        )
        numerator = sum(
            int(row["quality_primary_semantic_recovered_n"]) for row in rows
        )
        return numerator / denominator

    macro_ci = bootstrap_difference(
        groups["ai"], groups["human"], macro_primary, seed_offset=1
    )
    hit_ci = bootstrap_difference(
        groups["ai"], groups["human"], pr_hit, seed_offset=2
    )
    micro_ci = bootstrap_difference(
        groups["ai"], groups["human"], micro_primary, seed_offset=3
    )

    group_rows: list[dict[str, Any]] = []
    for group, rows in groups.items():
        primary_n = sum(int(row["quality_primary_reference_n"]) for row in rows)
        primary_recovered = sum(
            int(row["quality_primary_semantic_recovered_n"]) for row in rows
        )
        hit_n = sum(
            int(row["quality_primary_semantic_pr_hit"]) for row in rows
        )
        micro_low, micro_high = wilson(primary_recovered, primary_n)
        hit_low, hit_high = wilson(hit_n, len(rows))
        valid_rows = [row for row in rows if row["model_output_valid"] == "1"]
        group_findings = [
            row for row in semantic_finding_rows if row["group"] == group
        ]
        relation_counter = Counter(
            row["codeql_relation"] for row in group_findings
        )
        group_rows.append(
            {
                "group": group,
                "positive_case_n": len(rows),
                "valid_output_positive_case_n": len(valid_rows),
                "invalid_output_positive_case_n": len(rows) - len(valid_rows),
                "review_finding_n_all_cases": len(group_findings),
                "semantic_same_issue_finding_n": relation_counter[
                    "same_issue"
                ],
                "semantic_related_distinct_finding_n": relation_counter[
                    "related_distinct"
                ],
                "semantic_no_match_finding_n": relation_counter["no_match"],
                "semantic_no_reference_finding_n": relation_counter[
                    "no_reference"
                ],
                "quality_primary_reference_n": primary_n,
                "quality_primary_semantic_recovered_n": primary_recovered,
                "quality_primary_micro_recall": primary_recovered / primary_n,
                "quality_primary_micro_recall_ci_low": micro_low,
                "quality_primary_micro_recall_ci_high": micro_high,
                "quality_primary_macro_recall": macro_primary(rows),
                "quality_primary_pr_hit_n": hit_n,
                "quality_primary_pr_hit_rate": hit_n / len(rows),
                "quality_primary_pr_hit_ci_low": hit_low,
                "quality_primary_pr_hit_ci_high": hit_high,
                "quality_primary_complete_case_macro_recall": macro_primary(
                    valid_rows
                ),
                "quality_primary_complete_case_pr_hit_rate": pr_hit(valid_rows),
            }
        )

    ai = groups["ai"]
    human = groups["human"]
    ai_hits = sum(int(row["quality_primary_semantic_pr_hit"]) for row in ai)
    human_hits = sum(
        int(row["quality_primary_semantic_pr_hit"]) for row in human
    )
    comparisons = {
        "ai_minus_human_quality_primary_macro_recall": {
            "estimate": macro_primary(ai) - macro_primary(human),
            "bootstrap_95_ci_low": macro_ci[0],
            "bootstrap_95_ci_high": macro_ci[1],
        },
        "ai_minus_human_quality_primary_micro_recall": {
            "estimate": micro_primary(ai) - micro_primary(human),
            "cluster_bootstrap_95_ci_low": micro_ci[0],
            "cluster_bootstrap_95_ci_high": micro_ci[1],
        },
        "ai_minus_human_quality_primary_pr_hit_rate": {
            "estimate": pr_hit(ai) - pr_hit(human),
            "bootstrap_95_ci_low": hit_ci[0],
            "bootstrap_95_ci_high": hit_ci[1],
            "fisher_exact_two_sided_p": fisher_two_sided(
                ai_hits,
                len(ai) - ai_hits,
                human_hits,
                len(human) - human_hits,
            ),
        },
    }

    auto_tp = auto_fp = auto_fn = auto_tn = 0
    for row in semantic_finding_rows:
        automatic = bool(int(row["automatic_recovered"]))
        semantic = row["codeql_relation"] == "same_issue"
        if automatic and semantic:
            auto_tp += 1
        elif automatic and not semantic:
            auto_fp += 1
        elif not automatic and semantic:
            auto_fn += 1
        else:
            auto_tn += 1
    auto_precision = ratio(auto_tp, auto_tp + auto_fp)
    auto_recall = ratio(auto_tp, auto_tp + auto_fn)
    auto_f1 = (
        2 * auto_precision * auto_recall / (auto_precision + auto_recall)
        if auto_precision is not None
        and auto_recall is not None
        and auto_precision + auto_recall
        else None
    )
    confusion_rows = [
        {
            "automatic_recovered": 1,
            "semantic_same_issue": 1,
            "finding_n": auto_tp,
            "interpretation": "automatic semantic agreement",
        },
        {
            "automatic_recovered": 1,
            "semantic_same_issue": 0,
            "finding_n": auto_fp,
            "interpretation": "automatic false alignment",
        },
        {
            "automatic_recovered": 0,
            "semantic_same_issue": 1,
            "finding_n": auto_fn,
            "interpretation": "automatic missed semantic recovery",
        },
        {
            "automatic_recovered": 0,
            "semantic_same_issue": 0,
            "finding_n": auto_tn,
            "interpretation": "automatic semantic agreement",
        },
    ]

    rule_counter: dict[tuple[str, str, str, str], Counter[str]] = defaultdict(
        Counter
    )
    for row in semantic_reference_rows:
        key = (
            row["group"],
            row["reference_family"],
            row["quality_category"],
            row["rule_id"],
        )
        rule_counter[key]["reference_n"] += 1
        rule_counter[key]["automatic_recovered_n"] += as_bool(
            row["automatic_recovered"]
        )
        rule_counter[key]["semantic_recovered_n"] += bool(
            int(row["semantic_recovered"])
        )
    rule_rows = []
    for key, counts in sorted(rule_counter.items()):
        n = counts["reference_n"]
        recovered = counts["semantic_recovered_n"]
        rule_rows.append(
            {
                "group": key[0],
                "reference_family": key[1],
                "quality_category": key[2],
                "rule_id": key[3],
                "reference_n": n,
                "automatic_recovered_n": counts["automatic_recovered_n"],
                "semantic_recovered_n": recovered,
                "semantic_recovery_rate": recovered / n,
            }
        )

    control_rows = [
        row
        for row in semantic_case_rows
        if row["case_control"] == "control"
    ]
    control_metrics = {}
    for group in ("ai", "human"):
        rows = [row for row in control_rows if row["group"] == group]
        with_findings = sum(int(row["review_finding_n"]) > 0 for row in rows)
        low, high = wilson(with_findings, len(rows))
        control_metrics[group] = {
            "case_n": len(rows),
            "case_with_any_reviewer_finding_n": with_findings,
            "case_with_any_reviewer_finding_rate": with_findings / len(rows),
            "wilson_95_ci_low": low,
            "wilson_95_ci_high": high,
            "mean_reviewer_findings_per_case": mean(
                int(row["review_finding_n"]) for row in rows
            ),
            "interpretation": (
                "reference-negative control reporting propensity; not a "
                "false-positive rate because CodeQL absence is not a defect-"
                "free human gold standard"
            ),
        }

    costs = [as_float(row["total_cost_usd"]) for row in frozen_case_metrics]
    latencies = [as_float(row["latency_ms"]) / 1000 for row in frozen_case_metrics]
    validity_counter = Counter(
        row["finding_validity"] or "not_adjudicated" for row in labels
    )
    relation_counter = Counter(row["codeql_relation"] for row in labels)
    summary = {
        "schema_version": "1.0.0",
        "status": "completed",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "case_n": len(cases),
            "positive_case_n": len(positive_rows),
            "control_case_n": len(control_rows),
            "review_finding_n": len(findings),
            "codeql_reference_n": len(references),
            "relation_adjudicated_finding_n": sum(relation_counter.values()),
            "validity_adjudicated_finding_n": len(labels)
            - validity_counter["not_adjudicated"],
        },
        "semantic_relation_counts": dict(relation_counter),
        "finding_validity_counts": dict(validity_counter),
        "groups": {row["group"]: row for row in group_rows},
        "comparisons": comparisons,
        "automatic_matcher_audit": {
            "true_semantic_alignment_n": auto_tp,
            "false_alignment_n": auto_fp,
            "missed_semantic_alignment_n": auto_fn,
            "true_non_alignment_n": auto_tn,
            "agreement_accuracy": (auto_tp + auto_tn) / len(findings),
            "positive_predictive_value": auto_precision,
            "sensitivity_to_semantic_recoveries": auto_recall,
            "f1": auto_f1,
            "warning": (
                "These values audit the deterministic matcher against "
                "LLM-assisted semantic adjudication; they are not model "
                "precision/recall against independent human ground truth."
            ),
        },
        "control_reporting": control_metrics,
        "execution": {
            "completed_case_n": len(frozen_case_metrics),
            "valid_model_output_n": sum(
                row["model_output_valid"] == "1"
                for row in frozen_case_metrics
            ),
            "response_contract_violation_n": sum(
                row["model_output_valid"] != "1"
                for row in frozen_case_metrics
            ),
            "zero_finding_case_n": sum(
                as_int(row["review_finding_n"]) == 0
                for row in frozen_case_metrics
            ),
            "sdk_reported_total_cost_usd": sum(costs),
            "sdk_reported_mean_cost_usd": mean(costs),
            "sdk_reported_median_cost_usd": statistics.median(costs),
            "sdk_reported_p95_cost_usd": percentile(costs, 0.95),
            "mean_latency_seconds": mean(latencies),
            "median_latency_seconds": statistics.median(latencies),
            "p95_latency_seconds": percentile(latencies, 0.95),
            "provider_invoice_cost_available": False,
        },
        "adjudication_disclosure": (
            "All 1,016 finding-to-CodeQL relation decisions are complete. "
            "Codex-authored decisions are LLM-assisted semantic adjudication, "
            "not independent human annotation. Only 48 findings have a "
            "separate validity judgment, so reviewer precision is not "
            "estimated from this artifact."
        ),
    }

    write_csv(output / "semantic_finding_relations.csv", semantic_finding_rows)
    write_csv(
        output / "semantic_reference_recovery.csv", semantic_reference_rows
    )
    write_csv(output / "semantic_case_metrics.csv", semantic_case_rows)
    write_csv(output / "semantic_group_metrics.csv", group_rows)
    write_csv(
        output / "automatic_vs_semantic_confusion.csv", confusion_rows
    )
    write_csv(output / "semantic_rule_recovery.csv", rule_rows)
    write_json(output / "summary.json", summary)

    output_files = sorted(
        path for path in output.iterdir() if path.name != "manifest.json"
    )
    write_json(
        output / "manifest.json",
        {
            "schema_version": "1.0.0",
            "status": "completed",
            "inputs": {
                "workspace": str(workspace),
                "finding_labels_sha256": sha256_file(
                    workspace / "finding_labels.csv"
                ),
                "formal_results": str(formal_results),
                "formal_summary_sha256": sha256_file(
                    formal_results / "summary.json"
                ),
            },
            "outputs": {
                path.name: sha256_file(path) for path in output_files
            },
        },
    )
    print(
        "RQ3 semantic summary completed: "
        f"same_issue={relation_counter['same_issue']}, "
        "semantic_refs="
        f"{sum(bool(ids) for ids in matched_findings_by_reference.values())}, "
        f"output={output}"
    )


if __name__ == "__main__":
    main()
