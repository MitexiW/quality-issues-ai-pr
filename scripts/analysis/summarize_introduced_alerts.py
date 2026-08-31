#!/usr/bin/env python3
# Statistical analysis entry point.
"""Build an introduced-only RQ1 profile from enhanced CodeQL alert CSV files.

The script never changes experiment inputs.  It joins introduced alerts to the
quality-gated PR population emitted by ``analyze_study_results.py`` and writes
auditable task, language, change-size, category, location, severity, CWE, rule,
and within-PR breadth profiles.  PR-level summaries retain zero-alert PRs in
their denominators.
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

import numpy as np

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from compare_sarif import load_location_rules, location_class


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCATION_RULES = ROOT / "config" / "study" / "pr_enrichment_rules.json"
FAMILIES = ("quality", "security")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts", type=Path, required=True)
    parser.add_argument("--analysis-pr-level", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--group", default="ai")
    parser.add_argument("--location-rules", type=Path, default=DEFAULT_LOCATION_RULES)
    parser.add_argument("--bootstrap-replicates", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20260623)
    parser.add_argument(
        "--status",
        choices=("provisional", "final"),
        default="provisional",
    )
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


def truthy(value: Any) -> bool:
    return clean(value).casefold() in {"1", "true", "yes", "y"}


def integer(value: Any) -> int:
    text = clean(value)
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return 0


def number(value: Any) -> float:
    text = clean(value)
    try:
        parsed = float(text)
    except (TypeError, ValueError):
        raise ValueError(f"expected a numeric value, got {value!r}") from None
    if not math.isfinite(parsed):
        raise ValueError(f"expected a finite numeric value, got {value!r}")
    return parsed


def pr_key(row: dict[str, str]) -> tuple[str, str]:
    repo = clean(row.get("repo_name")).casefold()
    number = clean(row.get("pr_number"))
    try:
        number = str(int(float(number)))
    except (TypeError, ValueError):
        pass
    return repo, number


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    maximize_csv_field_limit()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), [
            {key: clean(value) for key, value in row.items()} for row in reader
        ]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_csv(
    path: Path,
    fields: Sequence[str],
    rows: Iterable[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def family(row: dict[str, str]) -> str:
    if truthy(row.get("is_quality_alert")):
        return "quality"
    if truthy(row.get("is_security_alert")):
        return "security"
    category = clean(row.get("alert_category")).casefold()
    return category if category in FAMILIES else ""


def percentile(values: list[int], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def wilson(successes: int, total: int) -> tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / total + z * z / (4 * total * total)
        )
        / denominator
    )
    return max(0.0, centre - margin), min(1.0, centre + margin)


def eligible_prs(
    rows: list[dict[str, str]], group: str
) -> dict[tuple[str, str], dict[str, str]]:
    selected: dict[tuple[str, str], dict[str, str]] = {}
    for row in rows:
        if clean(row.get("group")).casefold() != group.casefold():
            continue
        if not truthy(row.get("quality_gate_pass")):
            continue
        key = pr_key(row)
        if not all(key):
            continue
        if key in selected:
            raise ValueError(f"analysis_pr_level 中存在重复 PR: {key}")
        selected[key] = row
    return selected


def stratum_rows(
    prs: dict[tuple[str, str], dict[str, str]],
    alerts: list[dict[str, str]],
    dimension: str,
) -> list[dict[str, Any]]:
    dimensions: list[tuple[str, set[tuple[str, str]]]] = [
        ("all", set(prs)),
    ]
    values = sorted({clean(row.get(dimension)) or "unknown" for row in prs.values()})
    for value in values:
        dimensions.append(
            (
                value,
                {
                    key
                    for key, row in prs.items()
                    if (clean(row.get(dimension)) or "unknown") == value
                },
            )
        )

    records: list[dict[str, Any]] = []
    for value, keys in dimensions:
        for alert_family in FAMILIES:
            counts: Counter[tuple[str, str]] = Counter(
                pr_key(row)
                for row in alerts
                if row["_family"] == alert_family and pr_key(row) in keys
            )
            zero_aware = [counts.get(key, 0) for key in keys]
            affected = sum(count > 0 for count in zero_aware)
            total = sum(zero_aware)
            low, high = wilson(affected, len(keys))
            records.append(
                {
                    "dimension": dimension,
                    "stratum": value,
                    "family": alert_family,
                    "pr_n": len(keys),
                    "introduced_alert_n": total,
                    "affected_pr_n": affected,
                    "affected_pr_percent": 100 * affected / len(keys) if keys else 0,
                    "affected_pr_wilson_low_percent": 100 * low,
                    "affected_pr_wilson_high_percent": 100 * high,
                    "alerts_per_100_pr": 100 * total / len(keys) if keys else 0,
                    "mean_per_pr": total / len(keys) if keys else 0,
                    "median_per_pr": percentile(zero_aware, 0.5),
                    "p95_per_pr": percentile(zero_aware, 0.95),
                    "max_per_pr": max(zero_aware, default=0),
                }
            )
    return records


def change_size_band(changed_kloc: float) -> str:
    """Return the prespecified descriptive band for changed code lines."""

    if changed_kloc < 0:
        raise ValueError(f"changed_kloc must be non-negative, got {changed_kloc}")
    if changed_kloc <= 0.1:
        return "le_100"
    if changed_kloc <= 1.0:
        return "101_1000"
    return "gt_1000"


def issue_count_distribution(
    prs: dict[tuple[str, str], dict[str, str]],
    alerts: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Summarize zero-aware per-PR issue counts in interpretable bins."""

    definitions = [
        ("0", lambda count: count == 0),
        ("1", lambda count: count == 1),
        ("2_3", lambda count: 2 <= count <= 3),
        ("4_10", lambda count: 4 <= count <= 10),
        ("gt_10", lambda count: count > 10),
    ]
    rows: list[dict[str, Any]] = []
    for alert_family in FAMILIES:
        counts = Counter(
            pr_key(row) for row in alerts if row["_family"] == alert_family
        )
        total_alerts = sum(counts.values())
        for label, predicate in definitions:
            selected = [counts.get(key, 0) for key in prs if predicate(counts.get(key, 0))]
            alert_n = sum(selected)
            rows.append(
                {
                    "family": alert_family,
                    "issue_count_bin": label,
                    "pr_n": len(selected),
                    "pr_percent": 100 * len(selected) / len(prs) if prs else 0,
                    "introduced_alert_n": alert_n,
                    "alert_percent_within_family": (
                        100 * alert_n / total_alerts if total_alerts else 0
                    ),
                }
            )
    return rows


def positive_pr_breadth(
    alerts: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Describe alert, rule, category, and file breadth within positive PRs."""

    rows: list[dict[str, Any]] = []
    for alert_family in FAMILIES:
        selected = [row for row in alerts if row["_family"] == alert_family]
        by_pr: defaultdict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
        for row in selected:
            by_pr[pr_key(row)].append(row)
        metrics = {
            "alerts": [len(items) for items in by_pr.values()],
            "rules": [
                len({clean(row.get("rule_id")) or "unknown" for row in items})
                for items in by_pr.values()
            ],
            "categories": [
                len(
                    {
                        clean(row.get("quality_category")) or "not_applicable"
                        for row in items
                    }
                )
                for items in by_pr.values()
            ],
            "files": [
                len({clean(row.get("file_path")) or "unknown" for row in items})
                for items in by_pr.values()
            ],
        }
        positive_pr_n = len(by_pr)
        for metric, values in metrics.items():
            rows.append(
                {
                    "family": alert_family,
                    "metric": metric,
                    "positive_pr_n": positive_pr_n,
                    "single_value_pr_n": sum(value == 1 for value in values),
                    "single_value_pr_percent": (
                        100 * sum(value == 1 for value in values) / positive_pr_n
                        if positive_pr_n
                        else 0
                    ),
                    "median": percentile(values, 0.5),
                    "p75": percentile(values, 0.75),
                    "p90": percentile(values, 0.9),
                    "p95": percentile(values, 0.95),
                    "max": max(values, default=0),
                }
            )
    return rows


def categorical_profile(
    alerts: list[dict[str, str]],
    field: str,
    *,
    family_filter: str | None = None,
) -> list[dict[str, Any]]:
    filtered = [
        row for row in alerts if family_filter is None or row["_family"] == family_filter
    ]
    counts: Counter[tuple[str, str]] = Counter()
    prs: defaultdict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)
    for row in filtered:
        alert_family = row["_family"]
        value = clean(row.get(field)) or "unknown"
        counts[(alert_family, value)] += 1
        prs[(alert_family, value)].add(pr_key(row))
    totals = Counter(row["_family"] for row in filtered)
    records = []
    for (alert_family, value), count in sorted(
        counts.items(), key=lambda item: (item[0][0], -item[1], item[0][1])
    ):
        records.append(
            {
                "family": alert_family,
                "value": value,
                "introduced_alert_n": count,
                "affected_pr_n": len(prs[(alert_family, value)]),
                "alert_percent_within_family": (
                    100 * count / totals[alert_family] if totals[alert_family] else 0
                ),
            }
        )
    return records


def rule_profiles(
    alerts: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    detailed: list[dict[str, Any]] = []
    concentration: list[dict[str, Any]] = []
    strata = ["all", *sorted({row["_task_type"] for row in alerts})]
    for alert_family in FAMILIES:
        for task in strata:
            selected = [
                row
                for row in alerts
                if row["_family"] == alert_family
                and (task == "all" or row["_task_type"] == task)
            ]
            counts = Counter(clean(row.get("rule_id")) or "unknown" for row in selected)
            total = sum(counts.values())
            ordered = counts.most_common()
            hhi = (
                sum((count / total) ** 2 for _, count in ordered) if total else 0.0
            )
            concentration.append(
                {
                    "family": alert_family,
                    "task_type": task,
                    "introduced_alert_n": total,
                    "distinct_rule_n": len(counts),
                    "top1_alert_percent": (
                        100 * sum(count for _, count in ordered[:1]) / total
                        if total
                        else 0
                    ),
                    "top5_alert_percent": (
                        100 * sum(count for _, count in ordered[:5]) / total
                        if total
                        else 0
                    ),
                    "top10_alert_percent": (
                        100 * sum(count for _, count in ordered[:10]) / total
                        if total
                        else 0
                    ),
                    "hhi": hhi,
                    "effective_rule_n": 1 / hhi if hhi else 0,
                }
            )
            cumulative = 0
            for rank, (rule_id, count) in enumerate(ordered, start=1):
                matching = [row for row in selected if clean(row.get("rule_id")) == rule_id]
                cumulative += count
                detailed.append(
                    {
                        "family": alert_family,
                        "task_type": task,
                        "rank": rank,
                        "rule_id": rule_id,
                        "rule_name": clean(matching[0].get("rule_name")),
                        "quality_category": (
                            clean(matching[0].get("quality_category"))
                            if alert_family == "quality"
                            else ""
                        ),
                        "introduced_alert_n": count,
                        "affected_pr_n": len({pr_key(row) for row in matching}),
                        "alert_percent": 100 * count / total if total else 0,
                        "cumulative_alert_percent": (
                            100 * cumulative / total if total else 0
                        ),
                    }
                )
    return detailed, concentration


def cluster_bootstrap_intervals(
    prs: dict[tuple[str, str], dict[str, str]],
    alerts: list[dict[str, str]],
    replicates: int,
    seed: int,
) -> list[dict[str, Any]]:
    if replicates < 1:
        raise ValueError("bootstrap_replicates 必须大于 0")
    rng = np.random.default_rng(seed)
    records: list[dict[str, Any]] = []
    tasks = ["all", *sorted({clean(row.get("task_type")) for row in prs.values()})]
    for task in tasks:
        keys = {
            key
            for key, row in prs.items()
            if task == "all" or clean(row.get("task_type")) == task
        }
        repositories = sorted({key[0] for key in keys})
        if not repositories:
            continue
        for alert_family in FAMILIES:
            counts = Counter(
                pr_key(row)
                for row in alerts
                if row["_family"] == alert_family and pr_key(row) in keys
            )
            aggregates = []
            for repository in repositories:
                repository_keys = [key for key in keys if key[0] == repository]
                aggregates.append(
                    (
                        len(repository_keys),
                        sum(counts.get(key, 0) > 0 for key in repository_keys),
                        sum(counts.get(key, 0) for key in repository_keys),
                    )
                )
            values = np.asarray(aggregates, dtype=float)
            sampled_indexes = rng.integers(
                0,
                len(repositories),
                size=(replicates, len(repositories)),
            )
            sampled = values[sampled_indexes].sum(axis=1)
            sampled_pr_n = sampled[:, 0]
            metrics = {
                "affected_pr_percent": (
                    100 * sum(counts.get(key, 0) > 0 for key in keys) / len(keys),
                    100 * sampled[:, 1] / sampled_pr_n,
                ),
                "alerts_per_100_pr": (
                    100 * sum(counts.get(key, 0) for key in keys) / len(keys),
                    100 * sampled[:, 2] / sampled_pr_n,
                ),
            }
            for metric, (estimate, bootstrap_values) in metrics.items():
                records.append(
                    {
                        "family": alert_family,
                        "task_type": task,
                        "metric": metric,
                        "estimate": estimate,
                        "ci_low": float(np.percentile(bootstrap_values, 2.5)),
                        "ci_high": float(np.percentile(bootstrap_values, 97.5)),
                        "repository_n": len(repositories),
                        "pr_n": len(keys),
                        "bootstrap_replicates": replicates,
                        "seed": seed,
                    }
                )
    return records


def markdown_table(
    rows: Sequence[dict[str, Any]], fields: Sequence[str], limit: int | None = None
) -> list[str]:
    selected = list(rows[:limit] if limit is not None else rows)
    lines = [
        "| " + " | ".join(fields) + " |",
        "| " + " | ".join("---" for _ in fields) + " |",
    ]
    for row in selected:
        values = []
        for field in fields:
            value = row.get(field, "")
            if isinstance(value, float):
                value = f"{value:.2f}"
            values.append(str(value).replace("|", "\\|"))
        lines.append("| " + " | ".join(values) + " |")
    return lines


def main() -> None:
    args = parse_args()
    alerts_path = resolve(args.alerts)
    analysis_path = resolve(args.analysis_pr_level)
    output_dir = resolve(args.output_dir)
    location_rules = load_location_rules(resolve(args.location_rules))

    alert_fields, raw_alerts = read_csv(alerts_path)
    _, analysis_rows = read_csv(analysis_path)
    required = {
        "repo_name",
        "pr_number",
        "rule_id",
        "file_path",
        "is_security_alert",
        "is_quality_alert",
    }
    missing = required - set(alert_fields)
    if missing:
        raise ValueError(f"introduced alerts 缺少字段: {sorted(missing)}")

    prs = eligible_prs(analysis_rows, args.group)
    alerts: list[dict[str, str]] = []
    excluded_alert_n = 0
    invalid_family_n = 0
    for row in raw_alerts:
        if pr_key(row) not in prs:
            excluded_alert_n += 1
            continue
        alert_family = family(row)
        if alert_family not in FAMILIES:
            invalid_family_n += 1
            continue
        enriched = dict(row)
        enriched["_family"] = alert_family
        enriched["_task_type"] = clean(prs[pr_key(row)].get("task_type")) or "unknown"
        enriched["_repo_language"] = (
            clean(prs[pr_key(row)].get("repo_language"))
            or clean(prs[pr_key(row)].get("language"))
            or "unknown"
        )
        enriched["_location_class"] = (
            clean(row.get("location_class"))
            or location_class(clean(row.get("file_path")), location_rules)
        )
        alerts.append(enriched)

    expected = {
        alert_family: sum(
            integer(row.get(f"introduced_{alert_family}_alerts"))
            for row in prs.values()
        )
        for alert_family in FAMILIES
    }
    observed = Counter(row["_family"] for row in alerts)
    conservation = {
        alert_family: expected[alert_family] == observed[alert_family]
        for alert_family in FAMILIES
    }

    task_rows = stratum_rows(prs, alerts, "task_type")
    language_rows = stratum_rows(prs, alerts, "repo_language")
    size_prs: dict[tuple[str, str], dict[str, str]] = {}
    for key, row in prs.items():
        enriched = dict(row)
        enriched["change_size_band"] = change_size_band(number(row.get("changed_kloc")))
        size_prs[key] = enriched
    change_size_rows = stratum_rows(size_prs, alerts, "change_size_band")
    location_rows = categorical_profile(
        [{**row, "profile_value": row["_location_class"]} for row in alerts],
        "profile_value",
    )
    category_rows = categorical_profile(alerts, "quality_category", family_filter="quality")
    severity_rows = categorical_profile(
        [
            {
                **row,
                "profile_value": clean(row.get("problem_severity"))
                or clean(row.get("severity"))
                or "unknown",
            }
            for row in alerts
        ],
        "profile_value",
    )
    precision_rows = categorical_profile(alerts, "precision")
    cwe_rows = categorical_profile(alerts, "cwe", family_filter="security")
    rule_rows, concentration_rows = rule_profiles(alerts)
    issue_count_rows = issue_count_distribution(prs, alerts)
    breadth_rows = positive_pr_breadth(alerts)
    bootstrap_rows = cluster_bootstrap_intervals(
        prs,
        alerts,
        args.bootstrap_replicates,
        args.seed,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    stratum_fields = [
        "dimension",
        "stratum",
        "family",
        "pr_n",
        "introduced_alert_n",
        "affected_pr_n",
        "affected_pr_percent",
        "affected_pr_wilson_low_percent",
        "affected_pr_wilson_high_percent",
        "alerts_per_100_pr",
        "mean_per_pr",
        "median_per_pr",
        "p95_per_pr",
        "max_per_pr",
    ]
    categorical_fields = [
        "family",
        "value",
        "introduced_alert_n",
        "affected_pr_n",
        "alert_percent_within_family",
    ]
    write_csv(output_dir / "introduced_by_task.csv", stratum_fields, task_rows)
    write_csv(output_dir / "introduced_by_language.csv", stratum_fields, language_rows)
    write_csv(
        output_dir / "introduced_by_change_size.csv",
        stratum_fields,
        change_size_rows,
    )
    write_csv(output_dir / "introduced_by_location.csv", categorical_fields, location_rows)
    write_csv(
        output_dir / "quality_category_profile.csv", categorical_fields, category_rows
    )
    write_csv(output_dir / "severity_profile.csv", categorical_fields, severity_rows)
    write_csv(output_dir / "precision_profile.csv", categorical_fields, precision_rows)
    write_csv(output_dir / "security_cwe_profile.csv", categorical_fields, cwe_rows)
    write_csv(
        output_dir / "rule_profile.csv",
        [
            "family",
            "task_type",
            "rank",
            "rule_id",
            "rule_name",
            "quality_category",
            "introduced_alert_n",
            "affected_pr_n",
            "alert_percent",
            "cumulative_alert_percent",
        ],
        rule_rows,
    )
    write_csv(
        output_dir / "rule_concentration.csv",
        [
            "family",
            "task_type",
            "introduced_alert_n",
            "distinct_rule_n",
            "top1_alert_percent",
            "top5_alert_percent",
            "top10_alert_percent",
            "hhi",
            "effective_rule_n",
        ],
        concentration_rows,
    )
    write_csv(
        output_dir / "repository_cluster_bootstrap_intervals.csv",
        [
            "family",
            "task_type",
            "metric",
            "estimate",
            "ci_low",
            "ci_high",
            "repository_n",
            "pr_n",
            "bootstrap_replicates",
            "seed",
        ],
        bootstrap_rows,
    )
    write_csv(
        output_dir / "pr_issue_count_distribution.csv",
        [
            "family",
            "issue_count_bin",
            "pr_n",
            "pr_percent",
            "introduced_alert_n",
            "alert_percent_within_family",
        ],
        issue_count_rows,
    )
    write_csv(
        output_dir / "positive_pr_breadth.csv",
        [
            "family",
            "metric",
            "positive_pr_n",
            "single_value_pr_n",
            "single_value_pr_percent",
            "median",
            "p75",
            "p90",
            "p95",
            "max",
        ],
        breadth_rows,
    )

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": args.status,
        "group": args.group,
        "eligible_pr_n": len(prs),
        "raw_introduced_alert_n": len(raw_alerts),
        "eligible_introduced_alert_n": len(alerts),
        "excluded_alert_n": excluded_alert_n,
        "invalid_family_alert_n": invalid_family_n,
        "expected_family_counts": expected,
        "observed_family_counts": dict(observed),
        "count_conservation": conservation,
        "count_conservation_pass": all(conservation.values()),
        "repository_cluster_bootstrap": {
            "replicates": args.bootstrap_replicates,
            "seed": args.seed,
            "method": "repository-cluster percentile",
        },
        "change_size_bands": {
            "unit": "changed code lines",
            "le_100": "changed_kloc <= 0.1",
            "101_1000": "0.1 < changed_kloc <= 1.0",
            "gt_1000": "changed_kloc > 1.0",
            "role": "post-outcome descriptive extension; not a threshold-effect analysis",
        },
        "inputs": {
            "alerts": {
                "path": str(alerts_path),
                "sha256": sha256_file(alerts_path),
            },
            "analysis_pr_level": {
                "path": str(analysis_path),
                "sha256": sha256_file(analysis_path),
            },
            "location_rules": {
                "path": str(resolve(args.location_rules)),
                "sha256": sha256_file(resolve(args.location_rules)),
            },
        },
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    overall = [row for row in task_rows if row["stratum"] == "all"]
    task_detail = [row for row in task_rows if row["stratum"] != "all"]
    language_detail = [row for row in language_rows if row["stratum"] != "all"]
    change_size_detail = [
        row for row in change_size_rows if row["stratum"] != "all"
    ]
    top_rules = [
        row for row in rule_rows if row["task_type"] == "all" and row["rank"] <= 10
    ]
    overall_bootstrap = [
        row for row in bootstrap_rows if row["task_type"] == "all"
    ]
    report = [
        "# Introduced-only RQ1 profile",
        "",
        f"状态：**{args.status}**。本报告只包含 `{args.group}` 组，"
        "不得在 Human 批次结束前作为 AI–Human 比较或论文最终结果。",
        "",
        "## 数据门禁",
        "",
        f"- 门禁通过 PR：{len(prs):,}",
        f"- 纳入 introduced alerts：{len(alerts):,}",
        f"- 因 PR 门禁排除的 alerts：{excluded_alert_n:,}",
        f"- family 非法 alerts：{invalid_family_n:,}",
        f"- PR-level 与 alert-level 计数守恒："
        f"{'通过' if all(conservation.values()) else '未通过'}",
        f"- Quality：期望 {expected['quality']:,}，观察 {observed['quality']:,}",
        f"- Security：期望 {expected['security']:,}，观察 {observed['security']:,}",
        "",
        "## 总体 introduced 分布",
        "",
        *markdown_table(
            overall,
            [
                "family",
                "pr_n",
                "introduced_alert_n",
                "affected_pr_n",
                "affected_pr_percent",
                "alerts_per_100_pr",
                "median_per_pr",
                "p95_per_pr",
                "max_per_pr",
            ],
        ),
        "",
        "## Repository-cluster 95% intervals",
        "",
        *markdown_table(
            overall_bootstrap,
            [
                "family",
                "metric",
                "estimate",
                "ci_low",
                "ci_high",
                "repository_n",
                "bootstrap_replicates",
            ],
        ),
        "",
        "## Task type",
        "",
        *markdown_table(
            task_detail,
            [
                "stratum",
                "family",
                "pr_n",
                "introduced_alert_n",
                "affected_pr_n",
                "affected_pr_percent",
                "alerts_per_100_pr",
                "p95_per_pr",
                "max_per_pr",
            ],
        ),
        "",
        "## Changed-code size bands",
        "",
        *markdown_table(
            change_size_detail,
            [
                "stratum",
                "family",
                "pr_n",
                "introduced_alert_n",
                "affected_pr_n",
                "affected_pr_percent",
                "alerts_per_100_pr",
                "max_per_pr",
            ],
        ),
        "",
        "The bands are a post-outcome descriptive extension (at most 100, "
        "101--1,000, and more than 1,000 changed code lines), not an estimated "
        "threshold effect.",
        "",
        "## CodeQL database language",
        "",
        *markdown_table(
            language_detail,
            [
                "stratum",
                "family",
                "pr_n",
                "introduced_alert_n",
                "affected_pr_n",
                "affected_pr_percent",
                "alerts_per_100_pr",
            ],
        ),
        "",
        "## Quality categories",
        "",
        *markdown_table(
            category_rows,
            [
                "value",
                "introduced_alert_n",
                "affected_pr_n",
                "alert_percent_within_family",
            ],
        ),
        "",
        "## Alert locations",
        "",
        *markdown_table(
            location_rows,
            [
                "family",
                "value",
                "introduced_alert_n",
                "affected_pr_n",
                "alert_percent_within_family",
            ],
        ),
        "",
        "## Problem severity",
        "",
        *markdown_table(
            severity_rows,
            [
                "family",
                "value",
                "introduced_alert_n",
                "affected_pr_n",
                "alert_percent_within_family",
            ],
        ),
        "",
        "## Zero-aware PR issue-count distribution",
        "",
        *markdown_table(
            issue_count_rows,
            [
                "family",
                "issue_count_bin",
                "pr_n",
                "pr_percent",
                "introduced_alert_n",
                "alert_percent_within_family",
            ],
        ),
        "",
        "## Positive-PR breadth",
        "",
        *markdown_table(
            breadth_rows,
            [
                "family",
                "metric",
                "positive_pr_n",
                "single_value_pr_n",
                "single_value_pr_percent",
                "median",
                "p75",
                "p90",
                "p95",
                "max",
            ],
        ),
        "",
        "## Rule concentration",
        "",
        *markdown_table(
            concentration_rows,
            [
                "family",
                "task_type",
                "introduced_alert_n",
                "distinct_rule_n",
                "top1_alert_percent",
                "top5_alert_percent",
                "top10_alert_percent",
                "hhi",
                "effective_rule_n",
            ],
        ),
        "",
        "## Top rules",
        "",
        *markdown_table(
            top_rules,
            [
                "family",
                "rank",
                "rule_id",
                "quality_category",
                "introduced_alert_n",
                "affected_pr_n",
                "alert_percent",
            ],
        ),
        "",
        "## 产物",
        "",
        "- `introduced_by_task.csv`：task 分层，包含零告警 PR；",
        "- `introduced_by_language.csv`：CodeQL database language 分层；",
        "- `introduced_by_change_size.csv`：changed-code size 分层，包含零告警 PR；",
        "- `introduced_by_location.csv`：由 SARIF `file_path` 派生的位置类别；",
        "- `quality_category_profile.csv`：Quality taxonomy；",
        "- `severity_profile.csv`、`precision_profile.csv`、"
        "`security_cwe_profile.csv`：告警属性；",
        "- `rule_profile.csv`、`rule_concentration.csv`：规则排名与集中度；",
        "- `pr_issue_count_distribution.csv`、`positive_pr_breadth.csv`："
        "零感知的 PR 计数分布与阳性 PR 内部广度；",
        "- `repository_cluster_bootstrap_intervals.csv`：repository-cluster "
        "percentile 95% CI；",
        "- `manifest.json`：输入、门禁和守恒记录。",
        "",
    ]
    (output_dir / "report.md").write_text("\n".join(report), encoding="utf-8")
    print(f"已生成 introduced-only RQ1 profile: {output_dir}")
    print(
        f"eligible_prs={len(prs)} alerts={len(alerts)} "
        f"count_conservation_pass={all(conservation.values())}"
    )


if __name__ == "__main__":
    main()
