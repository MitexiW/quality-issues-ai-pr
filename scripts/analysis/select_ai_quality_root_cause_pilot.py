#!/usr/bin/env python3
"""Select a deterministic, purposive pilot for root-cause codebook development.

The pilot maximizes mechanism diversity; it is not a probability sample and
must not be used to estimate full-frame category frequencies.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REVIEW = ROOT / "data/experiments/security-and-quality/study_stars500/reports/ai_quality_root_cause_review_20260831_v1"
DEFAULT_OUTPUT = DEFAULT_REVIEW / "pilot_v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-dir", type=Path, default=DEFAULT_REVIEW)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--target-prs", type=int, default=30)
    return parser.parse_args()


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


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def integer(value: str) -> int:
    return int(float(value))


def pr_number_key(value: str) -> tuple[int, str]:
    try:
        return int(float(value)), value
    except ValueError:
        return 2**63 - 1, value


def stable_key(key: tuple[str, str]) -> str:
    return hashlib.sha256(f"{key[0]}\0{key[1]}".encode()).hexdigest()


def run(args: argparse.Namespace) -> None:
    review = args.review_dir if args.review_dir.is_absolute() else ROOT / args.review_dir
    output = args.output_dir if args.output_dir.is_absolute() else ROOT / args.output_dir
    units = read_csv(review / "pr_rule_review_units.csv")
    if args.target_prs <= 0:
        raise ValueError("--target-prs must be positive")
    by_pr: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    by_rule: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in units:
        key = row["repo_name"], row["pr_number"]
        by_pr[key].append(row); by_rule[row["rule_id"]].append(row)
    if args.target_prs > len(by_pr):
        raise ValueError("pilot target exceeds available PRs")

    roles: dict[tuple[str, str], set[str]] = defaultdict(set)
    selected: set[tuple[str, str]] = set()

    def add(key: tuple[str, str], role: str) -> None:
        if key in selected or len(selected) < args.target_prs:
            selected.add(key); roles[key].add(role)

    def burden(key: tuple[str, str]) -> int:
        return sum(integer(row["alert_n"]) for row in by_pr[key])

    ranked_burst = sorted(by_pr, key=lambda key: (-burden(key), key[0], pr_number_key(key[1])))
    for key in ranked_burst[:5]:
        add(key, "high_alert_burst")

    ranked_multi = sorted(by_pr, key=lambda key: (-len(by_pr[key]), -burden(key), key[0], pr_number_key(key[1])))
    for key in [key for key in ranked_multi if len(by_pr[key]) > 1][:5]:
        add(key, "multi_rule_pr")

    rule_rank = sorted(by_rule, key=lambda rule: (-len({(r['repo_name'], r['pr_number']) for r in by_rule[rule]}), rule))
    for rule in rule_rank[:8]:
        candidates = {(row["repo_name"], row["pr_number"]): integer(row["alert_n"]) for row in by_rule[rule]}
        median = statistics.median(candidates.values())
        key = min(candidates, key=lambda item: (item in selected, abs(candidates[item] - median), item[0], pr_number_key(item[1])))
        add(key, "broad_rule_recurrence")

    correctness_rules = [rule for rule in rule_rank if any(row["quality_category"] == "correctness_reliability" for row in by_rule[rule])]
    for rule in correctness_rules[:8]:
        candidates = [(row["repo_name"], row["pr_number"]) for row in by_rule[rule]]
        key = min(candidates, key=lambda item: (item in selected, burden(item), item[0], pr_number_key(item[1])))
        add(key, "correctness_long_tail")

    languages = sorted({rows[0]["language"] for rows in by_pr.values() if rows[0]["language"]})
    for language in languages:
        candidates = [key for key, rows in by_pr.items() if rows[0]["language"] == language]
        key = min(candidates, key=lambda item: (item in selected, -len(by_pr[item]), -burden(item), item[0], pr_number_key(item[1])))
        add(key, "language_coverage")

    for key in sorted(by_pr, key=lambda item: (item in selected, stable_key(item))):
        if len(selected) >= args.target_prs:
            break
        add(key, "deterministic_diversity_fill")
    if len(selected) != args.target_prs:
        raise ValueError(f"could not fill pilot target: selected {len(selected)} of {args.target_prs}")

    pilot_prs = []
    pilot_units = []
    for key in sorted(selected, key=lambda item: (item[0], pr_number_key(item[1]))):
        rows = by_pr[key]
        pilot_prs.append({
            "repo_name": key[0], "pr_number": key[1], "language": rows[0]["language"],
            "task_type": rows[0]["task_type"], "alert_n": burden(key), "rule_n": len(rows),
            "rules_json": json.dumps(sorted(row["rule_id"] for row in rows)),
            "selection_roles": "|".join(sorted(roles[key])), "packet_path": rows[0]["packet_path"],
            "source_status": rows[0]["source_status"],
        })
        for row in rows:
            pilot_units.append({**row, "selection_roles": "|".join(sorted(roles[key]))})
    pr_fields = ["repo_name", "pr_number", "language", "task_type", "alert_n", "rule_n", "rules_json",
                 "selection_roles", "packet_path", "source_status"]
    unit_fields = list(units[0]) + ["selection_roles"]
    write_csv(output / "pilot_prs.csv", pilot_prs, pr_fields)
    write_csv(output / "pilot_review_units.csv", pilot_units, unit_fields)
    manifest = {
        "schema_version": "1.0.0", "status": "selected_not_annotated",
        "generated_at": datetime.now(timezone.utc).isoformat(), "sampling_design": "purposive_codebook_development",
        "frequency_estimation_allowed": False, "target_pr_n": args.target_prs,
        "selected_pr_n": len(pilot_prs), "selected_alert_n": sum(integer(row["alert_n"]) for row in pilot_prs),
        "selected_pr_rule_n": len(pilot_units), "language_counts": dict(Counter(row["language"] for row in pilot_prs)),
        "role_counts": dict(Counter(role for row in pilot_prs for role in row["selection_roles"].split("|"))),
    }
    write_json(output / "manifest.json", manifest)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    run(parse_args())
