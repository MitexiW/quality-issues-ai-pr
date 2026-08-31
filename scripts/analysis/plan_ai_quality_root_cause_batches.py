#!/usr/bin/env python3
"""Partition the non-pilot positive PRs into deterministic review batches."""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REVIEW = ROOT / "data/experiments/security-and-quality/study_stars500/reports/ai_quality_root_cause_review_20260831_v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-dir", type=Path, default=DEFAULT_REVIEW)
    parser.add_argument("--pilot-prs", type=Path, default=DEFAULT_REVIEW / "pilot_v1/pilot_prs.csv")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_REVIEW / "full_review_batches_v1")
    parser.add_argument("--max-prs-per-batch", type=int, default=25)
    return parser.parse_args()


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
    temporary.replace(path)


def run(args: argparse.Namespace) -> None:
    review, pilot_path, output = map(resolve, (args.review_dir, args.pilot_prs, args.output_dir))
    if args.max_prs_per_batch <= 0:
        raise ValueError("--max-prs-per-batch must be positive")
    all_prs, pilot = read_csv(review / "positive_prs.csv"), read_csv(pilot_path)
    pilot_keys = {(row["repo_name"], row["pr_number"]) for row in pilot}
    remaining = [row for row in all_prs if (row["repo_name"], row["pr_number"]) not in pilot_keys]
    batch_n = math.ceil(len(remaining) / args.max_prs_per_batch)
    batches: list[list[dict[str, str]]] = [[] for _ in range(batch_n)]
    loads = [0] * batch_n

    def weight(row: dict[str, str]) -> int:
        return int(row["alert_n"]) + 4 * (int(row["rule_n"]) - 1) + (3 if row["source_status"] != "available" else 0)

    for row in sorted(remaining, key=lambda item: (-weight(item), item["repo_name"], int(item["pr_number"]))):
        candidates = [index for index, batch in enumerate(batches) if len(batch) < args.max_prs_per_batch]
        index = min(candidates, key=lambda value: (loads[value], len(batches[value]), value))
        batches[index].append(row); loads[index] += weight(row)

    fields = list(all_prs[0]) + ["review_batch", "review_weight", "coding_status"]
    plan_rows = []
    for index, batch in enumerate(batches, 1):
        batch_id = f"batch_{index:03d}"
        rows = []
        for row in sorted(batch, key=lambda item: (item["repo_name"], int(item["pr_number"]))):
            enriched = {**row, "review_batch": batch_id, "review_weight": weight(row), "coding_status": "pending"}
            rows.append(enriched); plan_rows.append(enriched)
        write_csv(output / "scopes" / f"{batch_id}_prs.csv", rows, fields)
    write_csv(output / "batch_plan.csv", sorted(plan_rows, key=lambda row: row["review_batch"]), fields)
    manifest = {"schema_version": "1.0.0", "status": "planned", "pilot_pr_n": len(pilot_keys),
        "remaining_pr_n": len(remaining), "remaining_alert_n": sum(int(row["alert_n"]) for row in remaining),
        "remaining_pr_rule_n": sum(int(row["rule_n"]) for row in remaining), "batch_n": batch_n,
        "max_prs_per_batch": args.max_prs_per_batch,
        "batches": [{"batch_id": f"batch_{i+1:03d}", "pr_n": len(batch),
                     "alert_n": sum(int(row["alert_n"]) for row in batch),
                     "pr_rule_n": sum(int(row["rule_n"]) for row in batch), "review_weight": loads[i],
                     "language_counts": dict(Counter(row["language"] for row in batch))}
                    for i, batch in enumerate(batches)]}
    output.mkdir(parents=True, exist_ok=True)
    temporary = output / "manifest.json.tmp"
    temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(output / "manifest.json")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    run(parse_args())
