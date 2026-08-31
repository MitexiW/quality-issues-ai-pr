#!/usr/bin/env python3
"""Select three deterministic, illustrative RQ1 cases from frozen outcomes.

The cases connect aggregate RQ1 profiles to concrete code without estimating
the frequency of code-level mechanisms.  Selection is outcome-frozen and
deterministic:

1. breadth: the rule represented in the most AI PRs, then a median-burden PR;
2. burst: the largest rule-by-PR alert cluster; and
3. correctness: the correctness/reliability rule represented in the most AI
   PRs, then a median-burden PR.

Eligible examples must contain a high/very-high precision alert in production
code and have preserved before/head source directories.  Lexicographic
repository and PR order resolves ties.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from compare_sarif import load_location_rules, location_class


DEFAULT_LOCATION_RULES = ROOT / "config" / "study" / "pr_enrichment_rules.json"
ALLOWED_PRECISION = {"high", "very-high"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts", type=Path, required=True)
    parser.add_argument("--rule-profile", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--location-rules", type=Path, default=DEFAULT_LOCATION_RULES)
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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    materialized = list(rows)
    if not materialized:
        raise ValueError("refuse to write an empty representative-case table")
    fields: list[str] = []
    for row in materialized:
        for field in row:
            if field not in fields:
                fields.append(field)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(materialized)
    temporary.replace(path)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def pr_number_key(value: str) -> tuple[int, str]:
    try:
        return int(float(value)), value
    except ValueError:
        return sys.maxsize, value


def numeric_line(value: Any) -> float:
    try:
        return float(clean(value))
    except ValueError:
        return math.inf


def pr_key(row: dict[str, str]) -> tuple[str, str, str]:
    return clean(row.get("repo_name")), clean(row.get("pr_number")), clean(row.get("case_id"))


def repo_slug(repo_name: str) -> str:
    return repo_name.replace("/", "_")


def source_dirs(repo_root: Path, key: tuple[str, str, str]) -> tuple[Path, Path]:
    repo_name, pr_number, _ = key
    slug = repo_slug(repo_name)
    root = repo_root / slug
    return (
        root / f"{slug}__pr-{pr_number}__before",
        root / f"{slug}__pr-{pr_number}__after",
    )


def validate_alerts(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    required = {
        "alert_id",
        "case_id",
        "group",
        "repo_name",
        "pr_number",
        "base_sha",
        "head_sha",
        "is_quality_alert",
        "rule_id",
        "rule_name",
        "precision",
        "quality_category",
        "file_path",
        "start_line",
        "message",
        "human_disposition",
        "human_notes",
    }
    missing = sorted(required - set(rows[0])) if rows else sorted(required)
    if missing:
        raise ValueError(f"validated alert table missing fields: {missing}")
    identifiers = [clean(row["alert_id"]) for row in rows]
    if not all(identifiers) or len(set(identifiers)) != len(identifiers):
        raise ValueError("alert_id must be complete and unique")
    selected = [
        row
        for row in rows
        if clean(row["group"]).casefold() == "ai"
        and truthy(row["is_quality_alert"])
        and clean(row["human_disposition"]) == "confirmed_valid"
    ]
    if not selected:
        raise ValueError("no final AI Quality alerts found")
    return selected


def profile_by_rule(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    required = {
        "family",
        "task_type",
        "rule_id",
        "rule_name",
        "quality_category",
        "introduced_alert_n",
        "affected_pr_n",
        "alert_percent",
    }
    missing = sorted(required - set(rows[0])) if rows else sorted(required)
    if missing:
        raise ValueError(f"rule profile missing fields: {missing}")
    overall = {
        clean(row["rule_id"]): row
        for row in rows
        if clean(row["family"]) == "quality" and clean(row["task_type"]) == "all"
    }
    if not overall:
        raise ValueError("rule profile has no overall Quality rows")
    return overall


def validate_profile(
    alerts: list[dict[str, str]], profile: dict[str, dict[str, str]]
) -> None:
    by_rule: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in alerts:
        by_rule[clean(row["rule_id"])].append(row)
    if set(by_rule) != set(profile):
        raise ValueError("alert rules and overall rule profile do not have identical coverage")
    for rule_id, rows in by_rule.items():
        expected_alerts = int(profile[rule_id]["introduced_alert_n"])
        expected_prs = int(profile[rule_id]["affected_pr_n"])
        if len(rows) != expected_alerts or len({pr_key(row) for row in rows}) != expected_prs:
            raise ValueError(f"rule-profile mismatch for {rule_id}")


def eligible_pr(
    rows: list[dict[str, str]],
    repo_root: Path,
    location_rules: dict[str, Any],
) -> bool:
    key = pr_key(rows[0])
    before_dir, after_dir = source_dirs(repo_root, key)
    if not before_dir.is_dir() or not after_dir.is_dir():
        return False
    return any(
        clean(row["precision"]).casefold() in ALLOWED_PRECISION
        and location_class(clean(row["file_path"]), location_rules) == "production"
        and (after_dir / clean(row["file_path"])).is_file()
        for row in rows
    )


def group_rule_prs(
    alerts: list[dict[str, str]], rule_id: str
) -> dict[tuple[str, str, str], list[dict[str, str]]]:
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in alerts:
        if clean(row["rule_id"]) == rule_id:
            grouped[pr_key(row)].append(row)
    return grouped


def choose_median_pr(
    alerts: list[dict[str, str]],
    rule_id: str,
    repo_root: Path,
    location_rules: dict[str, Any],
    forbidden: set[tuple[str, str, str]],
) -> tuple[tuple[str, str, str], list[dict[str, str]], float]:
    grouped = group_rule_prs(alerts, rule_id)
    median = float(statistics.median(len(rows) for rows in grouped.values()))
    candidates = [
        (key, rows)
        for key, rows in grouped.items()
        if key not in forbidden and eligible_pr(rows, repo_root, location_rules)
    ]
    if not candidates:
        raise ValueError(f"no eligible preserved source tree for rule {rule_id}")
    key, rows = min(
        candidates,
        key=lambda item: (
            abs(len(item[1]) - median),
            item[0][0].casefold(),
            pr_number_key(item[0][1]),
            item[0][2],
        ),
    )
    return key, rows, median


def choose_representative_alert(
    rows: list[dict[str, str]], location_rules: dict[str, Any]
) -> dict[str, str]:
    eligible = [
        row
        for row in rows
        if clean(row["precision"]).casefold() in ALLOWED_PRECISION
        and location_class(clean(row["file_path"]), location_rules) == "production"
    ]
    if not eligible:
        raise ValueError("selected PR has no eligible representative alert")
    file_counts = Counter(clean(row["file_path"]) for row in eligible)
    target_file = min(file_counts, key=lambda path: (-file_counts[path], path))

    def line_key(row: dict[str, str]) -> tuple[int, str, str]:
        try:
            line = int(float(clean(row["start_line"])))
        except ValueError:
            line = sys.maxsize
        return line, clean(row["message"]), clean(row["alert_id"])

    return min((row for row in eligible if clean(row["file_path"]) == target_file), key=line_key)


def build_case(
    role: str,
    selection_rule: str,
    key: tuple[str, str, str],
    rows: list[dict[str, str]],
    median_rule_pr_alerts: float | None,
    profile: dict[str, dict[str, str]],
    repo_root: Path,
    location_rules: dict[str, Any],
) -> dict[str, Any]:
    representative = choose_representative_alert(rows, location_rules)
    rule_id = clean(representative["rule_id"])
    before_dir, after_dir = source_dirs(repo_root, key)
    relative_file = clean(representative["file_path"])
    before_file = before_dir / relative_file
    after_file = after_dir / relative_file
    return {
        "case_role": role,
        "selection_rule": selection_rule,
        "repo_name": key[0],
        "pr_number": key[1],
        "case_id": key[2],
        "base_sha": clean(representative["base_sha"]),
        "head_sha": clean(representative["head_sha"]),
        "rule_id": rule_id,
        "rule_name": clean(representative["rule_name"]),
        "quality_category": clean(representative["quality_category"]),
        "rule_alert_n": int(profile[rule_id]["introduced_alert_n"]),
        "rule_affected_pr_n": int(profile[rule_id]["affected_pr_n"]),
        "rule_alert_percent": float(profile[rule_id]["alert_percent"]),
        "rule_alerts_in_selected_pr": len(rows),
        "rule_files_in_selected_pr": len({clean(row["file_path"]) for row in rows}),
        "median_rule_alerts_per_positive_pr": median_rule_pr_alerts,
        "representative_alert_id": clean(representative["alert_id"]),
        "representative_precision": clean(representative["precision"]),
        "representative_location": location_class(relative_file, location_rules),
        "representative_file": relative_file,
        "representative_line": clean(representative["start_line"]),
        "representative_message": clean(representative["message"]),
        "representative_human_notes": clean(representative["human_notes"]),
        "representative_file_status": "modified" if before_file.is_file() else "added",
        "before_source_dir": str(before_dir.relative_to(ROOT)),
        "after_source_dir": str(after_dir.relative_to(ROOT)),
    }


def run(args: argparse.Namespace) -> None:
    maximize_csv_field_limit()
    alerts_path = resolve(args.alerts)
    profile_path = resolve(args.rule_profile)
    repo_root = resolve(args.repo_root)
    output_dir = resolve(args.output_dir)
    location_rules_path = resolve(args.location_rules)
    alerts = validate_alerts(read_csv(alerts_path))
    profile = profile_by_rule(read_csv(profile_path))
    validate_profile(alerts, profile)
    location_rules = load_location_rules(location_rules_path)

    breadth_rule = min(
        profile,
        key=lambda rule_id: (-int(profile[rule_id]["affected_pr_n"]), rule_id),
    )
    correctness_rules = [
        rule_id
        for rule_id, row in profile.items()
        if clean(row["quality_category"]) == "correctness_reliability"
    ]
    if not correctness_rules:
        raise ValueError("no correctness/reliability rules found")
    correctness_rule = min(
        correctness_rules,
        key=lambda rule_id: (-int(profile[rule_id]["affected_pr_n"]), rule_id),
    )

    all_rule_prs: list[tuple[str, tuple[str, str, str], list[dict[str, str]]]] = []
    for rule_id in profile:
        for key, rows in group_rule_prs(alerts, rule_id).items():
            if eligible_pr(rows, repo_root, location_rules):
                all_rule_prs.append((rule_id, key, rows))
    if not all_rule_prs:
        raise ValueError("no eligible rule-by-PR groups found")
    burst_rule, burst_key, burst_rows = min(
        all_rule_prs,
        key=lambda item: (
            -len(item[2]),
            item[0],
            item[1][0].casefold(),
            pr_number_key(item[1][1]),
            item[1][2],
        ),
    )

    used: set[tuple[str, str, str]] = set()
    breadth_key, breadth_rows, breadth_median = choose_median_pr(
        alerts, breadth_rule, repo_root, location_rules, used
    )
    used.add(breadth_key)
    used.add(burst_key)
    correctness_key, correctness_rows, correctness_median = choose_median_pr(
        alerts, correctness_rule, repo_root, location_rules, used
    )

    cases = [
        build_case(
            "broad_recurrence",
            "largest affected-PR breadth; eligible PR nearest the rule-specific median alert count; lexical tie-break",
            breadth_key,
            breadth_rows,
            breadth_median,
            profile,
            repo_root,
            location_rules,
        ),
        build_case(
            "within_pr_burst",
            "largest eligible rule-by-PR alert cluster",
            burst_key,
            burst_rows,
            None,
            profile,
            repo_root,
            location_rules,
        ),
        build_case(
            "correctness_pattern",
            "largest correctness affected-PR breadth; eligible PR nearest the rule-specific median alert count; lexical tie-break",
            correctness_key,
            correctness_rows,
            correctness_median,
            profile,
            repo_root,
            location_rules,
        ),
    ]
    if len({(row["repo_name"], row["pr_number"]) for row in cases}) != 3:
        raise ValueError("representative cases must use three distinct PRs")

    output_csv = output_dir / "representative_cases.csv"
    write_csv(output_csv, cases)
    selected_case_alerts: list[dict[str, Any]] = []
    for case, rows in zip(
        cases,
        (breadth_rows, burst_rows, correctness_rows),
        strict=True,
    ):
        for row in sorted(
            rows,
            key=lambda item: (
                clean(item["file_path"]),
                numeric_line(item["start_line"]),
                clean(item["alert_id"]),
            ),
        ):
            selected_case_alerts.append(
                {
                    "case_role": case["case_role"],
                    "repo_name": clean(row["repo_name"]),
                    "pr_number": clean(row["pr_number"]),
                    "case_id": clean(row["case_id"]),
                    "alert_id": clean(row["alert_id"]),
                    "is_representative_alert": (
                        clean(row["alert_id"]) == case["representative_alert_id"]
                    ),
                    "rule_id": clean(row["rule_id"]),
                    "rule_name": clean(row["rule_name"]),
                    "quality_category": clean(row["quality_category"]),
                    "precision": clean(row["precision"]),
                    "location": location_class(clean(row["file_path"]), location_rules),
                    "file_path": clean(row["file_path"]),
                    "start_line": clean(row["start_line"]),
                    "message": clean(row["message"]),
                    "human_notes": clean(row["human_notes"]),
                }
            )
    case_alerts_csv = output_dir / "selected_case_alerts.csv"
    write_csv(case_alerts_csv, selected_case_alerts)
    manifest = {
        "schema_version": 1,
        "status": "final_descriptive_case_selection",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "post-hoc illustrative RQ1 cases; no mechanism-frequency estimand",
        "inputs": {
            "alerts": {"path": str(alerts_path), "sha256": sha256(alerts_path)},
            "rule_profile": {"path": str(profile_path), "sha256": sha256(profile_path)},
            "location_rules": {
                "path": str(location_rules_path),
                "sha256": sha256(location_rules_path),
            },
        },
        "eligibility": {
            "group": "ai",
            "family": "quality",
            "human_disposition": "confirmed_valid",
            "precision": sorted(ALLOWED_PRECISION),
            "location": "production",
            "preserved_before_and_after_source_directories": True,
        },
        "selected_case_n": len(cases),
        "selected_case_ids": [row["case_id"] for row in cases],
        "selected_alert_n": len(selected_case_alerts),
        "outputs": {
            "representative_cases": {
                "path": str(output_csv),
                "sha256": sha256(output_csv),
            },
            "selected_case_alerts": {
                "path": str(case_alerts_csv),
                "sha256": sha256(case_alerts_csv),
            },
        },
    }
    write_json(output_dir / "selection_manifest.json", manifest)
    print(f"RQ1 representative cases selected: {output_csv}")


def main() -> None:
    run(parse_args())


if __name__ == "__main__":
    main()
