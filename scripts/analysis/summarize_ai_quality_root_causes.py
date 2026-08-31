#!/usr/bin/env python3
"""Summarize a compiled root-cause cluster dataset without changing coding."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiled-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--scope-label", required=True)
    parser.add_argument("--frequency-estimation-allowed", action="store_true")
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
        writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader(); writer.writerows(rows)
    temporary.replace(path)


def run(args: argparse.Namespace) -> None:
    compiled, output = resolve(args.compiled_dir), resolve(args.output_dir)
    clusters = read_csv(compiled / "root_cause_clusters.csv")
    links = read_csv(compiled / "alert_cluster_links.csv")
    manifest = json.loads((compiled / "manifest.json").read_text())
    by_category: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_sub: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in clusters:
        key = row["root_cause_category"] or row["disposition"]
        by_category[key].append(row)
        by_sub[(key, row["mechanism_subcategory"] or row["disposition"])].append(row)
    category_rows = []
    for category, rows in sorted(by_category.items(), key=lambda item: (-len(item[1]), item[0])):
        alert_n = sum(int(row["alert_n"]) for row in rows)
        pr_n = len({(row["repo_name"], row["pr_number"]) for row in rows})
        category_rows.append({"root_cause_category": category, "cluster_n": len(rows),
            "alert_n": alert_n, "pr_n": pr_n,
            "cluster_percent": 100 * len(rows) / len(clusters),
            "alert_percent": 100 * alert_n / len(links),
            "pr_percent": 100 * pr_n / manifest["scope_pr_n"]})
    sub_rows = []
    for (category, sub), rows in sorted(by_sub.items(), key=lambda item: (-len(item[1]), item[0])):
        sub_rows.append({"root_cause_category": category, "mechanism_subcategory": sub,
            "cluster_n": len(rows), "alert_n": sum(int(row["alert_n"]) for row in rows),
            "pr_n": len({(row["repo_name"], row["pr_number"]) for row in rows})})
    write_csv(output / "category_summary.csv", category_rows,
              ["root_cause_category", "cluster_n", "alert_n", "pr_n", "cluster_percent", "alert_percent", "pr_percent"])
    write_csv(output / "submechanism_summary.csv", sub_rows,
              ["root_cause_category", "mechanism_subcategory", "cluster_n", "alert_n", "pr_n"])

    disclaimer = (
        "This scope is a purposive codebook-development sample. Category shares must not be used as population estimates."
        if not args.frequency_estimation_allowed else
        "This scope is the frozen full analysis frame; category shares may be reported with the study's stated uncertainty limits."
    )
    lines = [f"# Root-cause summary: {args.scope_label}", "", disclaimer, "", "## Partition audit", "",
        f"- PRs: {manifest['scope_pr_n']}", f"- Alerts: {manifest['alert_n']}",
        f"- Initial PR–Rule units: {manifest.get('initial_pr_rule_n', 'not recorded')}",
        f"- Root-cause clusters: {manifest['root_cause_cluster_n']}",
        f"- PR–Rule units split across multiple clusters: {manifest.get('split_pr_rule_n', 'not recorded')}",
        f"- Cross-rule clusters: {manifest['cross_rule_cluster_n']}",
        f"- Singleton-alert clusters: {manifest.get('singleton_alert_cluster_n', 'not recorded')}", "", "## Five-category fit", ""]
    lines += [f"- `{row['root_cause_category']}`: {row['cluster_n']} clusters "
              f"({row['cluster_percent']:.1f}%), covering {row['alert_n']} alerts "
              f"({row['alert_percent']:.1f}%) in {row['pr_n']} PRs"
              for row in category_rows]
    lines += ["", "PR counts are non-exclusive because one PR may contain clusters from multiple categories.",
              "These counts describe coded clusters, not independent causal events outside the sampled PRs.", ""]
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"clusters": len(clusters), "alerts": len(links),
                      "categories": dict(Counter(row["root_cause_category"] or row["disposition"] for row in clusters))},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    run(parse_args())
