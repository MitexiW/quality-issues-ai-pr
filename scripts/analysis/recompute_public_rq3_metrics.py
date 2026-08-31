#!/usr/bin/env python3
"""Recompute RQ3 recovery metrics from the released joined reference frame."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
from statsmodels.stats.proportion import proportion_confint


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--joined-references", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--bootstrap-draws", type=int, default=50_000)
    parser.add_argument("--seed", type=int, default=20260623)
    return parser.parse_args()


def truthy(value: str) -> bool:
    return value.strip().casefold() in {"1", "true", "yes", "y"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def group_metrics(rows: list[dict[str, str]], group: str) -> dict[str, object]:
    selected = [row for row in rows if row["group"] == group]
    by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in selected:
        by_case[row["case_id"]].append(row)
    recovered_n = sum(truthy(row["semantic_recovered"]) for row in selected)
    hit_pr_n = sum(
        any(truthy(row["semantic_recovered"]) for row in values)
        for values in by_case.values()
    )
    reference_n = len(selected)
    positive_pr_n = len(by_case)
    micro_ci = proportion_confint(recovered_n, reference_n, method="wilson")
    hit_ci = proportion_confint(hit_pr_n, positive_pr_n, method="wilson")
    macro = sum(
        sum(truthy(row["semantic_recovered"]) for row in values) / len(values)
        for values in by_case.values()
    ) / positive_pr_n
    return {
        "group": group,
        "positive_pr_n": positive_pr_n,
        "reference_n": reference_n,
        "recovered_n": recovered_n,
        "micro_recall": recovered_n / reference_n,
        "micro_ci_low": float(micro_ci[0]),
        "micro_ci_high": float(micro_ci[1]),
        "macro_recall": macro,
        "hit_pr_n": hit_pr_n,
        "pr_hit_rate": hit_pr_n / positive_pr_n,
        "hit_ci_low": float(hit_ci[0]),
        "hit_ci_high": float(hit_ci[1]),
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
            (len(values), sum(truthy(row["semantic_recovered"]) for row in values))
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


def main() -> None:
    args = parse_args()
    source = args.joined_references.resolve()
    rows = read_rows(source)
    if len(rows) != 571 or len({row["reference_id"] for row in rows}) != 571:
        raise SystemExit("released joined reference frame must contain 571 unique references")
    raw = [row for row in rows if truthy(row["quality_primary_reference"])]
    confirmed = [row for row in raw if truthy(row["validated_issue_reference"])]
    if len(raw) != 420 or len(confirmed) != 114:
        raise SystemExit("unexpected RQ3 reference counts")

    metric_rows: list[dict[str, object]] = []
    summaries: dict[str, object] = {}
    for layer, selected in (
        ("raw_differential_primary", raw),
        ("human_confirmed_primary", confirmed),
    ):
        groups = [group_metrics(selected, group) for group in ("ai", "human")]
        intervals = bootstrap_differences(selected, args.bootstrap_draws, args.seed)
        ai, human = groups
        for row in groups:
            row["layer"] = layer
            metric_rows.append(row)
        summaries[layer] = {
            "groups": {str(row["group"]): row for row in groups},
            "differences": {
                "micro_recall": {
                    "estimate": float(ai["micro_recall"]) - float(human["micro_recall"]),
                    **intervals["micro"],
                },
                "macro_recall": {
                    "estimate": float(ai["macro_recall"]) - float(human["macro_recall"]),
                    **intervals["macro"],
                },
                "pr_hit_rate": {
                    "estimate": float(ai["pr_hit_rate"]) - float(human["pr_hit_rate"]),
                    **intervals["hit"],
                },
            },
        }

    if sum(int(row["recovered_n"]) for row in metric_rows if row["layer"] == "human_confirmed_primary") != 20:
        raise SystemExit("unexpected confirmed-reference recovery count")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    fields = (
        "layer", "group", "positive_pr_n", "reference_n", "recovered_n",
        "micro_recall", "micro_ci_low", "micro_ci_high", "macro_recall",
        "hit_pr_n", "pr_hit_rate", "hit_ci_low", "hit_ci_high",
    )
    with (output / "group_metrics.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(metric_rows)
    summary = {
        "schema_version": "1.0.0",
        "status": "reproduced_from_public_join",
        "model_calls_added": 0,
        "source_sha256": sha256(source),
        "reference_n": len(rows),
        "raw_quality_reference_n": len(raw),
        "human_confirmed_quality_reference_n": len(confirmed),
        "human_confirmed_recovered_n": 20,
        "bootstrap_draws": args.bootstrap_draws,
        "seed": args.seed,
        "summaries": summaries,
    }
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print("RQ3 public re-score complete: confirmed=114 recovered=20")


if __name__ == "__main__":
    main()
