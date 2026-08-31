#!/usr/bin/env python3
"""Run zero-aware RQ1/RQ2 alert sensitivities on the full frozen cohort.

The command retains every quality-gated PR in the denominator (3,087 AI and
2,317 Human PRs in the frozen study).  Alert filters change only the numerator:
the command never matches PRs, trims observations, estimates propensity
scores, weights observations, treats failed scans as zero-alert PRs, or fits an
outcome model.

Inputs must be the final PR-level analysis snapshot and the enhanced AI/Human
``introduced_alerts.csv`` files containing mutually exclusive Quality and
Security family flags.  Outputs are descriptive CSV files, a Markdown report,
and a hash-bearing manifest.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import posixpath
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from compare_sarif import load_location_rules, location_class


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCATION_RULES = ROOT / "config" / "study" / "pr_enrichment_rules.json"
DEFAULT_PR_FILES = (
    ROOT
    / "data"
    / "experiments"
    / "security-and-quality"
    / "study_stars500"
    / "reports"
    / "pr_enrichment"
    / "file_enrichment.csv"
)
GROUPS = ("ai", "human")
FAMILIES = ("quality", "security")
FROZEN_GROUP_COUNTS = {"ai": 3087, "human": 2317}
CHANGED_FILE_FIELD_CANDIDATES = (
    "is_changed_file",
    "in_changed_file",
    "within_changed_file",
    "file_changed",
    "changed_file",
)
REQUIRED_ANALYSIS_FIELDS = {
    "group",
    "repo_name",
    "pr_number",
    "repo_language",
    "task_type",
    "changed_kloc",
    "quality_gate_pass",
    "introduced_quality_alerts",
    "introduced_security_alerts",
}
REQUIRED_ALERT_FIELDS = {
    "repo_name",
    "pr_number",
    "rule_id",
    "is_quality_alert",
    "is_security_alert",
    "precision",
    "problem_severity",
    "file_path",
}
REQUIRED_PR_FILE_FIELDS = {
    "group",
    "repo_name",
    "pr_number",
    "filename",
}
SUMMARY_FIELDS = (
    "family",
    "sensitivity_id",
    "sensitivity_label",
    "group",
    "denominator_pr_n",
    "positive_pr_n",
    "positive_pr_percent",
    "positive_pr_wilson_low_percent",
    "positive_pr_wilson_high_percent",
    "introduced_alert_n",
    "alerts_per_100_pr",
    "available",
    "filter_definition",
    "notes",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-pr-level", type=Path, required=True)
    parser.add_argument("--ai-alerts", type=Path, required=True)
    parser.add_argument("--human-alerts", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--location-rules",
        type=Path,
        default=DEFAULT_LOCATION_RULES,
        help="冻结的 SARIF file_path 位置分类规则",
    )
    parser.add_argument(
        "--changed-file-field",
        help=(
            "可选 alert-level 布尔字段；省略时从已知字段名自动探测。"
            "两个 alert 输入都必须完整包含该字段。"
        ),
    )
    parser.add_argument(
        "--pr-files",
        type=Path,
        default=DEFAULT_PR_FILES,
        help=(
            "PR changed-file roster (normally pr_enrichment/file_enrichment.csv). "
            "Used when the alert inputs do not share an alert-level changed-file "
            "boolean field."
        ),
    )
    parser.add_argument("--min-language-prs-per-group", type=int, default=50)
    parser.add_argument(
        "--min-language-positive-prs-per-group", type=int, default=5
    )
    parser.add_argument(
        "--expected-ai-prs", type=int, default=FROZEN_GROUP_COUNTS["ai"]
    )
    parser.add_argument(
        "--expected-human-prs", type=int, default=FROZEN_GROUP_COUNTS["human"]
    )
    parser.add_argument(
        "--allow-nonstandard-population",
        action="store_true",
        help="仅用于小型合成测试；正式研究不得启用",
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


def optional_bool(value: Any) -> bool | None:
    text = clean(value).casefold()
    if text in {"1", "true", "yes", "y"}:
        return True
    if text in {"0", "false", "no", "n"}:
        return False
    return None


def integer(value: Any) -> int:
    text = clean(value).replace(",", "")
    if not text:
        return 0
    try:
        parsed = int(float(text))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"无法解析整数: {value!r}") from exc
    if parsed < 0:
        raise ValueError(f"计数不能为负数: {value!r}")
    return parsed


def nonnegative_float(value: Any) -> float:
    text = clean(value).replace(",", "")
    try:
        parsed = float(text)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"无法解析非负数: {value!r}") from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"数值必须有限且非负: {value!r}")
    return parsed


def normalize_pr_number(value: Any) -> str:
    text = clean(value)
    try:
        return str(int(float(text)))
    except (TypeError, ValueError):
        return text


def bare_pr_key(row: dict[str, str]) -> tuple[str, str]:
    return (
        clean(row.get("repo_name")).casefold(),
        normalize_pr_number(row.get("pr_number")),
    )


def grouped_pr_key(group: str, row: dict[str, str]) -> tuple[str, str, str]:
    repo, number = bare_pr_key(row)
    return group, repo, number


def normalize_repo_path(value: Any) -> str:
    """Normalize path syntax without changing repository-case semantics."""

    path = clean(value).replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if not path:
        return ""
    normalized = posixpath.normpath(path)
    if (
        not normalized
        or normalized == "."
        or normalized.startswith("/")
        or normalized == ".."
        or normalized.startswith("../")
    ):
        raise ValueError(f"非法 repository-relative path: {value!r}")
    return normalized


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    maximize_csv_field_limit()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
        rows = [
            {key: clean(value) for key, value in row.items()} for row in reader
        ]
    return fields, rows


def load_changed_file_index(
    *,
    path: Path,
    population: dict[
        str, dict[tuple[str, str, str], dict[str, str]]
    ],
) -> tuple[
    dict[tuple[str, str, str], set[str]],
    set[tuple[str, str, str]],
    list[dict[str, Any]],
]:
    """Load and audit the deterministic PR-to-changed-path roster.

    File-list completeness comes from the frozen PR-level snapshot.  The file
    table supplies only the changed paths.  A PR with an incomplete list may
    remain in the 5,404-PR outcome denominator, but no alert on that PR may be
    classified as changed/not-changed.
    """

    fields, rows = read_csv(path)
    missing = REQUIRED_PR_FILE_FIELDS - set(fields)
    if missing:
        raise ValueError(f"PR file input 缺少字段: {sorted(missing)}")

    all_population = {
        key
        for group in GROUPS
        for key in population[group]
    }
    population_rows = {
        key: row
        for group in GROUPS
        for key, row in population[group].items()
    }
    paths: defaultdict[tuple[str, str, str], set[str]] = defaultdict(set)
    raw_by_normalized: defaultdict[
        tuple[tuple[str, str, str], str], set[str]
    ] = defaultdict(set)
    raw_row_keys: set[tuple[tuple[str, str, str], str]] = set()
    outside_by_group: Counter[str] = Counter()
    included_rows_by_group: Counter[str] = Counter()
    incomplete_duplicate_rows_by_group: Counter[str] = Counter()

    for row in rows:
        group = clean(row.get("group")).casefold()
        if group not in GROUPS:
            raise ValueError(f"PR file input 包含非法 group: {group!r}")
        key = grouped_pr_key(group, row)
        if key not in all_population:
            outside_by_group[group] += 1
            continue
        included_rows_by_group[group] += 1
        raw_path = clean(row.get("filename"))
        normalized = normalize_repo_path(raw_path)
        if not normalized:
            raise ValueError(f"PR file input 缺少 filename: {key}")
        raw_row_key = (key, raw_path)
        if raw_row_key in raw_row_keys:
            if optional_bool(
                population_rows[key].get("file_list_complete")
            ) is True:
                raise ValueError(
                    "PR file input 包含重复 changed-file row: "
                    f"{key} {raw_path!r}"
                )
            incomplete_duplicate_rows_by_group[group] += 1
            continue
        raw_row_keys.add(raw_row_key)
        raw_by_normalized[(key, normalized)].add(raw_path)
        paths[key].add(normalized)

    collisions = [
        (key, normalized, sorted(raw_paths))
        for (key, normalized), raw_paths in raw_by_normalized.items()
        if len(raw_paths) > 1
    ]
    complete_collisions = [
        item
        for item in collisions
        if optional_bool(
            population_rows[item[0]].get("file_list_complete")
        ) is True
    ]
    if complete_collisions:
        key, normalized, raw_paths = complete_collisions[0]
        raise ValueError(
            "PR file path normalization collision: "
            f"{key} normalized={normalized!r} raw={raw_paths!r}"
        )
    incomplete_collisions_by_group = Counter(
        key[0]
        for key, _normalized, _raw_paths in collisions
        if optional_bool(
            population_rows[key].get("file_list_complete")
        ) is not True
    )

    complete_keys: set[tuple[str, str, str]] = set()
    audit_rows: list[dict[str, Any]] = []
    for group in GROUPS:
        missing_enrichment = 0
        complete = 0
        incomplete = 0
        count_mismatch = 0
        expected_file_n = 0
        observed_file_n = 0
        for key, pr_row in population[group].items():
            enrichment = optional_bool(pr_row.get("enrichment_available"))
            list_complete = optional_bool(pr_row.get("file_list_complete"))
            if enrichment is not True:
                missing_enrichment += 1
            if list_complete is True:
                complete += 1
                complete_keys.add(key)
                expected = integer(pr_row.get("changed_files"))
                observed = len(paths.get(key, set()))
                expected_file_n += expected
                observed_file_n += observed
                if expected != observed:
                    count_mismatch += 1
            else:
                incomplete += 1
        if missing_enrichment or count_mismatch:
            raise ValueError(
                "changed-file roster coverage audit failed: "
                f"group={group} missing_enrichment_pr_n={missing_enrichment} "
                f"complete_list_count_mismatch_pr_n={count_mismatch}"
            )
        audit_rows.append(
            {
                "group": group,
                "source": "pr_file_path_join",
                "denominator_pr_n": len(population[group]),
                "complete_file_list_pr_n": complete,
                "incomplete_file_list_pr_n": incomplete,
                "expected_changed_file_n_complete_prs": expected_file_n,
                "observed_changed_file_n_complete_prs": observed_file_n,
                "included_pr_file_row_n": included_rows_by_group[group],
                "outside_population_pr_file_row_n": outside_by_group[group],
                "normalization_collision_n": 0,
                "incomplete_list_duplicate_file_row_n": (
                    incomplete_duplicate_rows_by_group[group]
                ),
                "incomplete_list_normalization_collision_n": (
                    incomplete_collisions_by_group[group]
                ),
                "complete_list_count_mismatch_pr_n": count_mismatch,
                "eligible_alert_n": "",
                "changed_file_alert_n": "",
                "not_changed_file_alert_n": "",
                "unclassifiable_alert_n": "",
            }
        )
    return dict(paths), complete_keys, audit_rows


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


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def wilson(successes: int, total: int) -> tuple[float, float]:
    if total <= 0:
        return 0.0, 0.0
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / total
            + z * z / (4 * total * total)
        )
        / denominator
    )
    return max(0.0, centre - margin), min(1.0, centre + margin)


def slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
    return normalized or "unknown"


def validate_population_options(args: argparse.Namespace) -> dict[str, int]:
    expected = {
        "ai": args.expected_ai_prs,
        "human": args.expected_human_prs,
    }
    if any(value < 1 for value in expected.values()):
        raise ValueError("expected group PR counts 必须为正整数")
    if (
        expected != FROZEN_GROUP_COUNTS
        and not args.allow_nonstandard_population
    ):
        raise ValueError(
            "正式运行必须使用冻结队列 AI=3087、Human=2317；"
            "小型合成测试才可启用 --allow-nonstandard-population"
        )
    if args.allow_nonstandard_population and expected == FROZEN_GROUP_COUNTS:
        raise ValueError(
            "--allow-nonstandard-population 必须同时显式提供测试用 group counts"
        )
    if args.min_language_prs_per_group < 1:
        raise ValueError("--min-language-prs-per-group 必须大于 0")
    if args.min_language_positive_prs_per_group < 1:
        raise ValueError(
            "--min-language-positive-prs-per-group 必须大于 0"
        )
    return expected


def select_population(
    rows: list[dict[str, str]], expected: dict[str, int]
) -> tuple[
    dict[str, dict[tuple[str, str, str], dict[str, str]]],
    dict[str, list[dict[str, str]]],
]:
    by_group: dict[str, list[dict[str, str]]] = {group: [] for group in GROUPS}
    selected: dict[
        str, dict[tuple[str, str, str], dict[str, str]]
    ] = {group: {} for group in GROUPS}
    for row in rows:
        group = clean(row.get("group")).casefold()
        if group not in GROUPS:
            raise ValueError(f"analysis_pr_level 包含非法 group: {group!r}")
        by_group[group].append(row)
        if not truthy(row.get("quality_gate_pass")):
            continue
        key = grouped_pr_key(group, row)
        if not key[1] or not key[2]:
            raise ValueError(f"quality-gated PR 缺少身份字段: {key}")
        if key in selected[group]:
            raise ValueError(f"analysis_pr_level 包含重复 PR: {key}")
        if not clean(row.get("repo_language")):
            raise ValueError(f"quality-gated PR 缺少 repo_language: {key}")
        if not clean(row.get("task_type")):
            raise ValueError(f"quality-gated PR 缺少 task_type: {key}")
        nonnegative_float(row.get("changed_kloc"))
        selected[group][key] = row
    observed = {group: len(selected[group]) for group in GROUPS}
    if observed != expected:
        raise ValueError(
            f"quality-gated denominator 不符合预期: observed={observed}, "
            f"expected={expected}"
        )
    return selected, by_group


def detect_changed_file_field(
    ai_fields: set[str],
    human_fields: set[str],
    requested: str | None,
) -> tuple[str, str]:
    shared = ai_fields & human_fields
    if requested:
        if requested not in shared:
            return "", (
                f"requested field {requested!r} is not present in both alert inputs"
            )
        return requested, "explicit shared alert-level field"
    for candidate in CHANGED_FILE_FIELD_CANDIDATES:
        if candidate in shared:
            return candidate, "auto-detected shared alert-level field"
    return "", "no shared alert-level changed-file field"


def strict_family(row: dict[str, str]) -> str:
    quality = optional_bool(row.get("is_quality_alert"))
    security = optional_bool(row.get("is_security_alert"))
    if quality is True and security is False:
        return "quality"
    if security is True and quality is False:
        return "security"
    raise ValueError(
        "introduced alert 必须恰好属于 Quality 或 Security："
        f"{row.get('repo_name')}#{row.get('pr_number')} "
        f"rule={row.get('rule_id')} quality={row.get('is_quality_alert')!r} "
        f"security={row.get('is_security_alert')!r}"
    )


def load_group_alerts(
    *,
    group: str,
    rows: list[dict[str, str]],
    population: dict[tuple[str, str, str], dict[str, str]],
    location_rules: dict[str, Any],
    changed_file_field: str,
    changed_file_paths: dict[tuple[str, str, str], set[str]] | None = None,
    complete_file_keys: set[tuple[str, str, str]] | None = None,
) -> tuple[list[dict[str, Any]], int, int]:
    alerts: list[dict[str, Any]] = []
    outside_population = 0
    missing_changed_value = 0
    for row in rows:
        key = grouped_pr_key(group, row)
        if key not in population:
            outside_population += 1
            continue
        family = strict_family(row)
        rule_id = clean(row.get("rule_id"))
        if not rule_id:
            raise ValueError(f"introduced alert 缺少 rule_id: {key}")
        if changed_file_field:
            changed_value = optional_bool(row.get(changed_file_field))
        elif changed_file_paths is not None and complete_file_keys is not None:
            alert_path = normalize_repo_path(row.get("file_path"))
            changed_value = (
                alert_path in changed_file_paths.get(key, set())
                if key in complete_file_keys
                else None
            )
        else:
            changed_value = None
        if (
            (changed_file_field or changed_file_paths is not None)
            and changed_value is None
        ):
            missing_changed_value += 1
        stored: dict[str, Any] = dict(row)
        stored["_group"] = group
        stored["_key"] = key
        stored["_family"] = family
        stored["_rule_id"] = rule_id
        stored["_precision"] = clean(row.get("precision")).casefold()
        stored["_problem_severity"] = clean(
            row.get("problem_severity")
        ).casefold()
        stored["_location_class"] = (
            clean(row.get("location_class")).casefold()
            or location_class(clean(row.get("file_path")), location_rules)
        )
        stored["_in_changed_file"] = changed_value
        alerts.append(stored)
    return alerts, outside_population, missing_changed_value


def scenario_rows(
    *,
    sensitivity_id: str,
    label: str,
    family: str,
    alerts: list[dict[str, Any]],
    population: dict[
        str, dict[tuple[str, str, str], dict[str, str]]
    ],
    available: bool = True,
    filter_definition: str,
    notes: str = "",
) -> list[dict[str, Any]]:
    if family not in FAMILIES:
        raise ValueError(f"非法 family: {family}")
    rows: list[dict[str, Any]] = []
    for group in GROUPS:
        denominator = len(population[group])
        selected = [
            alert
            for alert in alerts
            if alert["_family"] == family and alert["_group"] == group
        ]
        if available:
            positive = len({alert["_key"] for alert in selected})
            low, high = wilson(positive, denominator)
            row = {
                "positive_pr_n": positive,
                "positive_pr_percent": 100 * positive / denominator,
                "positive_pr_wilson_low_percent": 100 * low,
                "positive_pr_wilson_high_percent": 100 * high,
                "introduced_alert_n": len(selected),
                "alerts_per_100_pr": 100 * len(selected) / denominator,
            }
        else:
            row = {
                "positive_pr_n": "",
                "positive_pr_percent": "",
                "positive_pr_wilson_low_percent": "",
                "positive_pr_wilson_high_percent": "",
                "introduced_alert_n": "",
                "alerts_per_100_pr": "",
            }
        rows.append(
            {
                "family": family,
                "sensitivity_id": sensitivity_id,
                "sensitivity_label": label,
                "group": group,
                "denominator_pr_n": denominator,
                **row,
                "available": str(available).lower(),
                "filter_definition": filter_definition,
                "notes": notes,
            }
        )
    return rows


def top_quality_rules(
    alerts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    quality = [row for row in alerts if row["_family"] == "quality"]
    counts = Counter(row["_rule_id"] for row in quality)
    pr_sets: defaultdict[str, set[tuple[str, str, str]]] = defaultdict(set)
    for row in quality:
        pr_sets[row["_rule_id"]].add(row["_key"])
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    total = len(quality)
    return [
        {
            "rank": rank,
            "rule_id": rule_id,
            "introduced_alert_n": count,
            "affected_pr_n": len(pr_sets[rule_id]),
            "alert_percent": 100 * count / total if total else 0,
        }
        for rank, (rule_id, count) in enumerate(ordered, start=1)
    ]


def build_sensitivities(
    alerts: list[dict[str, Any]],
    population: dict[
        str, dict[tuple[str, str, str], dict[str, str]]
    ],
    changed_available: bool,
    changed_filter_definition: str,
    changed_note: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    for family in FAMILIES:
        rows.extend(
            scenario_rows(
                sensitivity_id="baseline",
                label="All introduced alerts in the frozen family",
                family=family,
                alerts=alerts,
                population=population,
                filter_definition=f"family == {family}",
            )
        )

    rules = top_quality_rules(alerts)
    for count in (1, 5):
        excluded = {row["rule_id"] for row in rules[:count]}
        selected = [
            row
            for row in alerts
            if not (
                row["_family"] == "quality"
                and row["_rule_id"] in excluded
            )
        ]
        rows.extend(
            scenario_rows(
                sensitivity_id=f"exclude_pooled_top{count}_quality_rules",
                label=f"Quality excluding pooled full-cohort Top-{count} rules",
                family="quality",
                alerts=selected,
                population=population,
                filter_definition=(
                    "exclude rule_id in {" + ", ".join(sorted(excluded)) + "}"
                ),
                notes=(
                    "Rule ranks are computed once from pooled AI+Human Quality "
                    "alerts; PR denominators are unchanged."
                ),
            )
        )

    high_precision = [
        row
        for row in alerts
        if row["_precision"] in {"high", "very-high", "very_high"}
    ]
    for family in FAMILIES:
        rows.extend(
            scenario_rows(
                sensitivity_id="precision_high_or_very_high",
                label="High/very-high precision alerts only",
                family=family,
                alerts=high_precision,
                population=population,
                filter_definition="precision in {high, very-high}",
            )
        )

    severities = sorted(
        {
            row["_problem_severity"]
            for row in alerts
            if row["_problem_severity"]
        }
    )
    for severity in severities:
        selected = [
            row for row in alerts if row["_problem_severity"] == severity
        ]
        for family in FAMILIES:
            rows.extend(
                scenario_rows(
                    sensitivity_id=f"problem_severity_{slug(severity)}",
                    label=f"Problem severity: {severity}",
                    family=family,
                    alerts=selected,
                    population=population,
                    filter_definition=f"problem_severity == {severity}",
                )
            )
    error_warning = [
        row
        for row in alerts
        if row["_problem_severity"] in {"error", "warning"}
    ]
    for family in FAMILIES:
        rows.extend(
            scenario_rows(
                sensitivity_id="problem_severity_error_or_warning",
                label="Error/warning problem severity only",
                family=family,
                alerts=error_warning,
                population=population,
                filter_definition="problem_severity in {error, warning}",
            )
        )

    production = [
        row for row in alerts if row["_location_class"] == "production"
    ]
    for family in FAMILIES:
        rows.extend(
            scenario_rows(
                sensitivity_id="location_production_only",
                label="Production-path alerts only",
                family=family,
                alerts=production,
                population=population,
                filter_definition="derived location_class == production",
            )
        )

    changed = [
        row for row in alerts if row["_in_changed_file"] is True
    ]
    for family in FAMILIES:
        rows.extend(
            scenario_rows(
                sensitivity_id="location_changed_file_only",
                label="Changed-file alerts only",
                family=family,
                alerts=changed,
                population=population,
                available=changed_available,
                filter_definition=changed_filter_definition,
                notes=changed_note,
            )
        )
    return rows, rules


def language_rows(
    population: dict[
        str, dict[tuple[str, str, str], dict[str, str]]
    ],
    alerts: list[dict[str, Any]],
    *,
    min_prs: int,
    min_positive_prs: int,
) -> list[dict[str, Any]]:
    languages = sorted(
        {
            clean(row.get("repo_language"))
            for group in GROUPS
            for row in population[group].values()
        }
    )
    records: list[dict[str, Any]] = []
    for family in FAMILIES:
        for language in languages:
            keys_by_group = {
                group: {
                    key
                    for key, row in population[group].items()
                    if clean(row.get("repo_language")) == language
                }
                for group in GROUPS
            }
            selected_by_group = {
                group: [
                    row
                    for row in alerts
                    if row["_family"] == family
                    and row["_group"] == group
                    and row["_key"] in keys_by_group[group]
                ]
                for group in GROUPS
            }
            positive_by_group = {
                group: len({row["_key"] for row in selected_by_group[group]})
                for group in GROUPS
            }
            reasons = []
            for group in GROUPS:
                if len(keys_by_group[group]) < min_prs:
                    reasons.append(f"{group}_pr_n<{min_prs}")
                if positive_by_group[group] < min_positive_prs:
                    reasons.append(
                        f"{group}_positive_pr_n<{min_positive_prs}"
                    )
            supported = not reasons
            for group in GROUPS:
                denominator = len(keys_by_group[group])
                positive = positive_by_group[group]
                low, high = wilson(positive, denominator)
                records.append(
                    {
                        "family": family,
                        "repo_language": language,
                        "group": group,
                        "denominator_pr_n": denominator,
                        "positive_pr_n": positive,
                        "positive_pr_percent": (
                            100 * positive / denominator if denominator else 0
                        ),
                        "positive_pr_wilson_low_percent": 100 * low,
                        "positive_pr_wilson_high_percent": 100 * high,
                        "introduced_alert_n": len(selected_by_group[group]),
                        "alerts_per_100_pr": (
                            100 * len(selected_by_group[group]) / denominator
                            if denominator
                            else 0
                        ),
                        "sufficient_support": str(supported).lower(),
                        "sparse_flag": str(not supported).lower(),
                        "sparse_reason": "|".join(reasons),
                        "min_prs_per_group": min_prs,
                        "min_positive_prs_per_group": min_positive_prs,
                    }
                )
    return records


def ai_alerts_per_changed_kloc_rows(
    population: dict[
        str, dict[tuple[str, str, str], dict[str, str]]
    ],
    alerts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ai_prs = population["ai"]
    strata: list[tuple[str, str, set[tuple[str, str, str]]]] = [
        ("all", "all", set(ai_prs)),
    ]
    for dimension in ("task_type", "repo_language"):
        values = sorted(
            {clean(row.get(dimension)) for row in ai_prs.values()}
        )
        for value in values:
            strata.append(
                (
                    dimension,
                    value,
                    {
                        key
                        for key, row in ai_prs.items()
                        if clean(row.get(dimension)) == value
                    },
                )
            )
    records: list[dict[str, Any]] = []
    for dimension, stratum, keys in strata:
        changed_kloc = [
            nonnegative_float(ai_prs[key].get("changed_kloc")) for key in keys
        ]
        total_kloc = round(sum(changed_kloc), 9)
        zero_kloc = sum(value == 0 for value in changed_kloc)
        for family in FAMILIES:
            alert_n = sum(
                row["_group"] == "ai"
                and row["_family"] == family
                and row["_key"] in keys
                for row in alerts
            )
            records.append(
                {
                    "family": family,
                    "dimension": dimension,
                    "stratum": stratum,
                    "pr_n": len(keys),
                    "zero_changed_kloc_pr_n": zero_kloc,
                    "changed_kloc_total": total_kloc,
                    "introduced_alert_n": alert_n,
                    "alerts_per_changed_kloc": (
                        alert_n / total_kloc if total_kloc > 0 else ""
                    ),
                    "definition": (
                        "introduced alert total / sum(changed_kloc) across "
                        "all AI quality-gated PRs in the stratum"
                    ),
                }
            )
    return records


def scan_success(row: dict[str, str]) -> bool:
    return (
        truthy(row.get("paired"))
        and truthy(row.get("family_metadata_complete"))
        and clean(row.get("comparison_status")).casefold() == "compared"
    )


def attrition_rows(
    by_group: dict[str, list[dict[str, str]]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    stages: list[dict[str, Any]] = []
    reasons: list[dict[str, Any]] = []
    for group in GROUPS:
        candidates = by_group[group]
        successful = [row for row in candidates if scan_success(row)]
        gated = [row for row in candidates if truthy(row.get("quality_gate_pass"))]
        scan_failed = [row for row in candidates if not scan_success(row)]
        post_scan_excluded = [
            row
            for row in candidates
            if scan_success(row) and not truthy(row.get("quality_gate_pass"))
        ]
        stage_values = (
            ("candidate_pool", len(candidates)),
            ("paired_scan_success", len(successful)),
            ("quality_gated_analysis", len(gated)),
            ("scan_not_successful", len(scan_failed)),
            ("post_scan_nonfailure_excluded", len(post_scan_excluded)),
        )
        for stage, count in stage_values:
            stages.append(
                {
                    "group": group,
                    "stage": stage,
                    "pr_n": count,
                    "percent_of_candidate_pool": (
                        100 * count / len(candidates) if candidates else 0
                    ),
                    "role": (
                        "outcome denominator"
                        if stage == "quality_gated_analysis"
                        else "descriptive attrition only"
                    ),
                }
            )
        reason_counts: Counter[tuple[str, str, str, str]] = Counter()
        for row in scan_failed:
            stage = clean(row.get("failure_stage")) or "unspecified"
            comparison = clean(row.get("comparison_status")) or "missing"
            retry = (
                "true" if truthy(row.get("retry_excluded")) else "false"
            )
            exclusion = clean(row.get("exclusion_reason")) or "unspecified"
            reason_counts[(stage, comparison, retry, exclusion)] += 1
        for (stage, comparison, retry, exclusion), count in sorted(
            reason_counts.items()
        ):
            reasons.append(
                {
                    "group": group,
                    "failure_stage": stage,
                    "comparison_status": comparison,
                    "retry_excluded": retry,
                    "exclusion_reason": exclusion,
                    "pr_n": count,
                    "outcome_handling": (
                        "excluded from outcome denominator; not coded as zero"
                    ),
                }
            )
    return stages, reasons


def alert_input_audit(
    population: dict[
        str, dict[tuple[str, str, str], dict[str, str]]
    ],
    alerts: list[dict[str, Any]],
    raw_counts: dict[str, int],
    outside_counts: dict[str, int],
) -> tuple[list[dict[str, Any]], bool]:
    rows = []
    passed = True
    for group in GROUPS:
        for family in FAMILIES:
            expected = sum(
                integer(row.get(f"introduced_{family}_alerts"))
                for row in population[group].values()
            )
            observed = sum(
                row["_group"] == group and row["_family"] == family
                for row in alerts
            )
            conserved = expected == observed
            passed = passed and conserved
            rows.append(
                {
                    "group": group,
                    "family": family,
                    "denominator_pr_n": len(population[group]),
                    "raw_alert_file_row_n": raw_counts[group],
                    "alerts_outside_quality_gated_population_n": outside_counts[
                        group
                    ],
                    "expected_introduced_alert_n": expected,
                    "observed_introduced_alert_n": observed,
                    "count_conservation": str(conserved).lower(),
                }
            )
    return rows, passed


def markdown_table(
    rows: Sequence[dict[str, Any]],
    fields: Sequence[str],
    limit: int | None = None,
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
    expected = validate_population_options(args)
    analysis_path = resolve(args.analysis_pr_level)
    alert_paths = {
        "ai": resolve(args.ai_alerts),
        "human": resolve(args.human_alerts),
    }
    output_dir = resolve(args.output_dir)
    location_rules_path = resolve(args.location_rules)
    pr_files_path = resolve(args.pr_files)

    analysis_fields, analysis_rows = read_csv(analysis_path)
    missing_analysis = REQUIRED_ANALYSIS_FIELDS - set(analysis_fields)
    if missing_analysis:
        raise ValueError(
            f"analysis_pr_level 缺少字段: {sorted(missing_analysis)}"
        )
    population, all_analysis_rows = select_population(analysis_rows, expected)

    alert_fields: dict[str, list[str]] = {}
    raw_alerts: dict[str, list[dict[str, str]]] = {}
    for group in GROUPS:
        fields, rows = read_csv(alert_paths[group])
        missing = REQUIRED_ALERT_FIELDS - set(fields)
        if missing:
            raise ValueError(
                f"{group} introduced_alerts 缺少增强字段: {sorted(missing)}"
            )
        alert_fields[group] = fields
        raw_alerts[group] = rows

    changed_field, changed_field_note = detect_changed_file_field(
        set(alert_fields["ai"]),
        set(alert_fields["human"]),
        args.changed_file_field,
    )
    changed_file_paths: dict[tuple[str, str, str], set[str]] | None = None
    complete_file_keys: set[tuple[str, str, str]] | None = None
    changed_join_audit: list[dict[str, Any]] = []
    if changed_field:
        changed_source = f"alert-level field: {changed_field}"
        changed_filter_definition = f"{changed_field} == true"
    else:
        required_join_fields = {
            "enrichment_available",
            "file_list_complete",
            "changed_files",
        }
        missing_join_fields = required_join_fields - set(analysis_fields)
        if missing_join_fields:
            raise ValueError(
                "changed-file path join requires analysis fields: "
                f"{sorted(missing_join_fields)}"
            )
        (
            changed_file_paths,
            complete_file_keys,
            changed_join_audit,
        ) = load_changed_file_index(
            path=pr_files_path,
            population=population,
        )
        changed_source = "group + repo_name + pr_number + normalized file_path"
        changed_filter_definition = (
            "normalize(alert.file_path) in changed filenames for the same "
            "group/repo_name/pr_number"
        )
    location_rules = load_location_rules(location_rules_path)
    alerts: list[dict[str, Any]] = []
    outside_counts: dict[str, int] = {}
    missing_changed_counts: dict[str, int] = {}
    for group in GROUPS:
        loaded, outside, missing_changed = load_group_alerts(
            group=group,
            rows=raw_alerts[group],
            population=population[group],
            location_rules=location_rules,
            changed_file_field=changed_field,
            changed_file_paths=changed_file_paths,
            complete_file_keys=complete_file_keys,
        )
        alerts.extend(loaded)
        outside_counts[group] = outside
        missing_changed_counts[group] = missing_changed

    changed_available = bool(changed_field) and not any(
        missing_changed_counts.values()
    )
    if changed_file_paths is not None:
        changed_available = not any(missing_changed_counts.values())
        if not changed_available:
            raise ValueError(
                "changed-file path join 无法分类全部 eligible alerts；"
                f"unclassifiable by group={missing_changed_counts}. "
                "不允许把缺失文件列表解释为 not-changed。"
            )
    if changed_field and not changed_available:
        changed_note = (
            f"{changed_field_note}; missing/unparseable values among eligible "
            f"alerts: {missing_changed_counts}"
        )
    elif changed_available:
        if changed_field:
            changed_note = f"{changed_field_note}: {changed_field}"
        else:
            changed_note = (
                "Deterministic exact path join after slash/dot normalization; "
                "path case is preserved. Every eligible alert is classifiable. "
                "Incomplete file-list PRs may remain in the full denominator "
                "only when they have no introduced alerts."
            )
    else:
        changed_note = changed_field_note

    if not changed_join_audit:
        changed_join_audit = [
            {
                "group": group,
                "source": (
                    "alert_level_field" if changed_field else "unavailable"
                ),
                "denominator_pr_n": len(population[group]),
                "complete_file_list_pr_n": "",
                "incomplete_file_list_pr_n": "",
                "expected_changed_file_n_complete_prs": "",
                "observed_changed_file_n_complete_prs": "",
                "included_pr_file_row_n": "",
                "outside_population_pr_file_row_n": "",
                "normalization_collision_n": "",
                "incomplete_list_duplicate_file_row_n": "",
                "incomplete_list_normalization_collision_n": "",
                "complete_list_count_mismatch_pr_n": "",
                "eligible_alert_n": "",
                "changed_file_alert_n": "",
                "not_changed_file_alert_n": "",
                "unclassifiable_alert_n": "",
            }
            for group in GROUPS
        ]
    for row in changed_join_audit:
        group_alerts = [
            alert for alert in alerts if alert["_group"] == row["group"]
        ]
        row["eligible_alert_n"] = len(group_alerts)
        row["changed_file_alert_n"] = sum(
            alert["_in_changed_file"] is True for alert in group_alerts
        )
        row["not_changed_file_alert_n"] = sum(
            alert["_in_changed_file"] is False for alert in group_alerts
        )
        row["unclassifiable_alert_n"] = sum(
            alert["_in_changed_file"] is None for alert in group_alerts
        )

    raw_counts = {group: len(raw_alerts[group]) for group in GROUPS}
    audit_rows, conservation_pass = alert_input_audit(
        population, alerts, raw_counts, outside_counts
    )
    if not conservation_pass:
        raise ValueError(
            "PR-level 与 alert-level introduced family 计数不守恒；"
            "请确认输入为同一冻结 snapshot 的增强 introduced_alerts"
        )

    sensitivity_rows, top_rules = build_sensitivities(
        alerts,
        population,
        changed_available,
        changed_filter_definition,
        changed_note,
    )
    language = language_rows(
        population,
        alerts,
        min_prs=args.min_language_prs_per_group,
        min_positive_prs=args.min_language_positive_prs_per_group,
    )
    ai_kloc_rows = ai_alerts_per_changed_kloc_rows(population, alerts)
    attrition, failure_reasons = attrition_rows(all_analysis_rows)
    field_rows = [
        {
            "sensitivity": "family_separation",
            "available": "true",
            "field_or_source": "is_quality_alert + is_security_alert",
            "detail": "mutually exclusive flags required for every included alert",
        },
        {
            "sensitivity": "precision",
            "available": "true",
            "field_or_source": "precision",
            "detail": "enhanced alert metadata",
        },
        {
            "sensitivity": "problem_severity",
            "available": "true",
            "field_or_source": "problem_severity",
            "detail": "enhanced alert metadata",
        },
        {
            "sensitivity": "production_only",
            "available": "true",
            "field_or_source": "location_class or derived from file_path",
            "detail": str(location_rules_path),
        },
        {
            "sensitivity": "changed_file_only",
            "available": str(changed_available).lower(),
            "field_or_source": changed_source,
            "detail": changed_note,
        },
    ]

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "sensitivity_summary.csv", SUMMARY_FIELDS, sensitivity_rows)
    write_csv(
        output_dir / "top_quality_rules.csv",
        (
            "rank",
            "rule_id",
            "introduced_alert_n",
            "affected_pr_n",
            "alert_percent",
        ),
        top_rules,
    )
    write_csv(
        output_dir / "language_strata.csv",
        (
            "family",
            "repo_language",
            "group",
            "denominator_pr_n",
            "positive_pr_n",
            "positive_pr_percent",
            "positive_pr_wilson_low_percent",
            "positive_pr_wilson_high_percent",
            "introduced_alert_n",
            "alerts_per_100_pr",
            "sufficient_support",
            "sparse_flag",
            "sparse_reason",
            "min_prs_per_group",
            "min_positive_prs_per_group",
        ),
        language,
    )
    write_csv(
        output_dir / "rq1_ai_alerts_per_changed_kloc.csv",
        (
            "family",
            "dimension",
            "stratum",
            "pr_n",
            "zero_changed_kloc_pr_n",
            "changed_kloc_total",
            "introduced_alert_n",
            "alerts_per_changed_kloc",
            "definition",
        ),
        ai_kloc_rows,
    )
    write_csv(
        output_dir / "scan_attrition.csv",
        (
            "group",
            "stage",
            "pr_n",
            "percent_of_candidate_pool",
            "role",
        ),
        attrition,
    )
    write_csv(
        output_dir / "scan_failure_reasons.csv",
        (
            "group",
            "failure_stage",
            "comparison_status",
            "retry_excluded",
            "exclusion_reason",
            "pr_n",
            "outcome_handling",
        ),
        failure_reasons,
    )
    write_csv(
        output_dir / "alert_input_audit.csv",
        (
            "group",
            "family",
            "denominator_pr_n",
            "raw_alert_file_row_n",
            "alerts_outside_quality_gated_population_n",
            "expected_introduced_alert_n",
            "observed_introduced_alert_n",
            "count_conservation",
        ),
        audit_rows,
    )
    write_csv(
        output_dir / "field_availability.csv",
        ("sensitivity", "available", "field_or_source", "detail"),
        field_rows,
    )
    write_csv(
        output_dir / "changed_file_join_audit.csv",
        (
            "group",
            "source",
            "denominator_pr_n",
            "complete_file_list_pr_n",
            "incomplete_file_list_pr_n",
            "expected_changed_file_n_complete_prs",
            "observed_changed_file_n_complete_prs",
            "included_pr_file_row_n",
            "outside_population_pr_file_row_n",
            "normalization_collision_n",
            "incomplete_list_duplicate_file_row_n",
            "incomplete_list_normalization_collision_n",
            "complete_list_count_mismatch_pr_n",
            "eligible_alert_n",
            "changed_file_alert_n",
            "not_changed_file_alert_n",
            "unclassifiable_alert_n",
        ),
        changed_join_audit,
    )

    headline_ids = {
        "baseline",
        "exclude_pooled_top1_quality_rules",
        "exclude_pooled_top5_quality_rules",
        "precision_high_or_very_high",
        "problem_severity_error_or_warning",
        "location_production_only",
        "location_changed_file_only",
    }
    headline = [
        row
        for row in sensitivity_rows
        if row["sensitivity_id"] in headline_ids
    ]
    supported_languages = [
        row
        for row in language
        if row["sufficient_support"] == "true"
    ]
    report = [
        "# Full-cohort RQ1/RQ2 alert sensitivities",
        "",
        "## Analysis policy",
        "",
        f"- Outcome denominator: **{sum(expected.values()):,} PRs** "
        f"(AI {expected['ai']:,}; Human {expected['human']:,}).",
        "- Every quality-gated PR has unit weight and remains in every available "
        "alert-filter sensitivity.",
        "- No PR matching, trimming, propensity score, weighting, common-support "
        "screening, outcome imputation, or outcome model is used.",
        "- Failed scans are reported only in descriptive attrition and are never "
        "coded as zero-alert PRs.",
        "- Quality and Security alerts are classified and reported separately.",
        "",
        "## Alert input conservation",
        "",
        *markdown_table(
            audit_rows,
            (
                "group",
                "family",
                "denominator_pr_n",
                "expected_introduced_alert_n",
                "observed_introduced_alert_n",
                "count_conservation",
            ),
        ),
        "",
        "## Main sensitivity summaries",
        "",
        *markdown_table(
            headline,
            (
                "family",
                "sensitivity_id",
                "group",
                "denominator_pr_n",
                "positive_pr_n",
                "positive_pr_percent",
                "introduced_alert_n",
                "available",
            ),
        ),
        "",
        "## Pooled full-cohort Quality rule ranking",
        "",
        *markdown_table(
            top_rules,
            (
                "rank",
                "rule_id",
                "introduced_alert_n",
                "affected_pr_n",
                "alert_percent",
            ),
            limit=10,
        ),
        "",
        "## Descriptive scan attrition",
        "",
        *markdown_table(
            attrition,
            (
                "group",
                "stage",
                "pr_n",
                "percent_of_candidate_pool",
                "role",
            ),
        ),
        "",
        "## RQ1 AI-only alerts per changed KLOC",
        "",
        (
            "Each rate is the introduced-alert total divided by the sum of "
            "`changed_kloc` across all AI quality-gated PRs in the stratum. "
            "Zero-alert and zero-changed-KLOC PRs remain in the stratum; this "
            "is not the mean of per-PR ratios."
        ),
        "",
        *markdown_table(
            ai_kloc_rows,
            (
                "family",
                "dimension",
                "stratum",
                "pr_n",
                "zero_changed_kloc_pr_n",
                "changed_kloc_total",
                "introduced_alert_n",
                "alerts_per_changed_kloc",
            ),
        ),
        "",
        "## Supported language strata",
        "",
        (
            f"Support requires at least {args.min_language_prs_per_group} PRs "
            "and at least "
            f"{args.min_language_positive_prs_per_group} positive PRs in each "
            "authorship group, evaluated separately by outcome family."
        ),
        "",
        *markdown_table(
            supported_languages,
            (
                "family",
                "repo_language",
                "group",
                "denominator_pr_n",
                "positive_pr_n",
                "positive_pr_percent",
                "introduced_alert_n",
                "sparse_flag",
            ),
        ),
        "",
        "All supported and sparse strata are retained in `language_strata.csv`; "
        "sparse strata are descriptive and must not be extrapolated.",
        "",
        "## Field availability",
        "",
        *markdown_table(
            field_rows,
            ("sensitivity", "available", "field_or_source", "detail"),
        ),
        "",
        "## Changed-file join audit",
        "",
        *markdown_table(
            changed_join_audit,
            (
                "group",
                "source",
                "denominator_pr_n",
                "complete_file_list_pr_n",
                "incomplete_file_list_pr_n",
                "eligible_alert_n",
                "changed_file_alert_n",
                "not_changed_file_alert_n",
                "unclassifiable_alert_n",
            ),
        ),
        "",
    ]
    report_path = output_dir / "report.md"
    write_text(report_path, "\n".join(report))

    output_names = (
        "sensitivity_summary.csv",
        "top_quality_rules.csv",
        "language_strata.csv",
        "rq1_ai_alerts_per_changed_kloc.csv",
        "scan_attrition.csv",
        "scan_failure_reasons.csv",
        "alert_input_audit.csv",
        "field_availability.csv",
        "changed_file_join_audit.csv",
        "report.md",
    )
    script_path = Path(__file__).resolve()
    input_records = {
        "analysis_pr_level": file_record(analysis_path),
        "ai_introduced_alerts": file_record(alert_paths["ai"]),
        "human_introduced_alerts": file_record(alert_paths["human"]),
        "location_rules": file_record(location_rules_path),
        "script": file_record(script_path),
    }
    if changed_file_paths is not None:
        input_records["pr_files"] = file_record(pr_files_path)
    manifest = {
        "schema_version": "1.1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": (
            "synthetic_test"
            if args.allow_nonstandard_population
            else "final_descriptive_sensitivities"
        ),
        "analysis_policy": {
            "quality_gated_pr_denominator": sum(expected.values()),
            "group_denominators": expected,
            "unit_weight_per_pr": 1,
            "pr_matching": False,
            "trimming": False,
            "propensity_score": False,
            "propensity_weighting": False,
            "common_support_screening": False,
            "failed_scan_outcome_imputation": False,
            "failed_scans_treated_as_zero": False,
            "outcome_models_fitted": False,
            "quality_security_reported_separately": True,
            "ai_kloc_rate_definition": (
                "introduced alert total / sum(changed_kloc) across all AI "
                "quality-gated PRs; zero-alert and changed_kloc=0 PRs retained; "
                "not a mean of per-PR ratios"
            ),
        },
        "snapshot_ids": sorted(
            {
                clean(row.get("snapshot_id"))
                for row in analysis_rows
                if clean(row.get("snapshot_id"))
            }
        ),
        "alert_count_conservation_pass": conservation_pass,
        "top_quality_rule_ids": [
            row["rule_id"] for row in top_rules[:5]
        ],
        "changed_file_sensitivity": {
            "available": changed_available,
            "field": changed_field,
            "source": changed_source,
            "detail": changed_note,
            "join_keys": (
                [
                    "group",
                    "repo_name (case-insensitive identity)",
                    "pr_number",
                    "repository-relative path (case-preserving)",
                ]
                if changed_file_paths is not None
                else []
            ),
            "path_normalization": (
                "backslash-to-slash; remove leading ./; POSIX dot-segment "
                "normalization; reject absolute/parent-relative paths; preserve "
                "path case"
                if changed_file_paths is not None
                else ""
            ),
            "coverage_audit": changed_join_audit,
        },
        "language_support_thresholds": {
            "min_prs_per_group": args.min_language_prs_per_group,
            "min_positive_prs_per_group": (
                args.min_language_positive_prs_per_group
            ),
        },
        "inputs": input_records,
        "outputs": [
            {
                "path": name,
                "size": (output_dir / name).stat().st_size,
                "sha256": sha256_file(output_dir / name),
            }
            for name in output_names
        ],
    }
    write_text(
        output_dir / "manifest.json",
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
    )
    print(
        f"已生成全量 alert sensitivities: {output_dir}；"
        f"denominator={sum(expected.values())} "
        f"(ai={expected['ai']}, human={expected['human']})；"
        f"changed_file_available={changed_available}"
    )


if __name__ == "__main__":
    main()
