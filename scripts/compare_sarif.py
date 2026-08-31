#!/usr/bin/env python3
"""Compare before/after SARIF files and emit separate Quality/Security lifecycles."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlparse

CODEQL_SCRIPTS = Path(__file__).resolve().parent / "codeql"
if str(CODEQL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(CODEQL_SCRIPTS))

from utils import clean_text

DEFAULT_QUALITY_TAXONOMY = (
    Path(__file__).resolve().parents[1]
    / "config"
    / "study"
    / "quality_rule_taxonomy.json"
)
DEFAULT_LOCATION_RULES = (
    Path(__file__).resolve().parents[1]
    / "config"
    / "study"
    / "pr_enrichment_rules.json"
)

ALERT_FIELDS = [
    "repo_name",
    "pr_number",
    "pr_id",
    "agent",
    "language",
    "base_sha",
    "head_sha",
    "codeql_version",
    "query_suite",
    "rule_id",
    "rule_name",
    "result_level",
    "security_severity",
    "problem_severity",
    "rule_tags",
    "rule_kind",
    "is_security_alert",
    "is_quality_alert",
    "alert_category",
    "quality_category",
    "quality_taxonomy_version",
    "severity",
    "precision",
    "cwe",
    "file_path",
    "location_class",
    "start_line",
    "message",
    "fingerprint",
    "match_method",
    "fingerprint_method",
    "fingerprint_ambiguity_n",
    "lifecycle",
]
SUMMARY_FIELDS = [
    "repo_name",
    "pr_number",
    "pr_id",
    "agent",
    "language",
    "base_sha",
    "head_sha",
    "codeql_version",
    "query_suite",
    "before_alerts",
    "after_alerts",
    "introduced_alerts",
    "fixed_alerts",
    "persistent_alerts",
    "before_security_alerts",
    "after_security_alerts",
    "introduced_security_alerts",
    "fixed_security_alerts",
    "persistent_security_alerts",
    "before_quality_alerts",
    "after_quality_alerts",
    "introduced_quality_alerts",
    "fixed_quality_alerts",
    "persistent_quality_alerts",
    "comparison_status",
    "comparison_error",
]


@dataclass
class Alert:
    row: dict[str, str]
    key: tuple[str, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="比较 before/after CodeQL SARIF")
    parser.add_argument("--jobs", default="data/metadata/codeql_jobs.csv")
    parser.add_argument("--output-dir", default="data/results")
    parser.add_argument("--repo", action="append", default=[])
    parser.add_argument("--pr-number", action="append", default=[])
    parser.add_argument(
        "--quality-taxonomy",
        default=str(DEFAULT_QUALITY_TAXONOMY),
        help="基于官方 SARIF rule tags 的 Quality 分类配置",
    )
    parser.add_argument(
        "--location-rules",
        default=str(DEFAULT_LOCATION_RULES),
        help="根据 SARIF file_path 分类 production/test/docs 等位置的规则",
    )
    parser.add_argument(
        "--no-update-jobs",
        action="store_true",
        help="只读 codeql_jobs.csv，不回写 comparison_status（适合隔离重建/演练）",
    )
    parser.add_argument(
        "--omit-persistent-details",
        action="store_true",
        help="保留 persistent 计数，但不写出体积很大的 persistent 告警明细",
    )
    return parser.parse_args()


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temp.replace(path)


def write_jobs(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    write_csv(path, fields, rows)


def normalize_path(value: str) -> str:
    parsed = urlparse(value)
    path = unquote(parsed.path if parsed.scheme == "file" else value)
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def numeric_security_severity(value: Any) -> str:
    """Return a normalized security severity only when it is numeric."""
    text = clean_text(value)
    if not text:
        return ""
    try:
        float(text)
    except ValueError:
        return ""
    return text


def load_quality_taxonomy(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    version = clean_text(payload.get("taxonomy_version"))
    fallback = clean_text(payload.get("fallback_category"))
    categories = payload.get("categories")
    if not version or not fallback or not isinstance(categories, list):
        raise ValueError(f"Quality taxonomy 缺少 version/categories/fallback: {path}")
    normalized: list[dict[str, Any]] = []
    seen_categories: set[str] = set()
    for item in categories:
        if not isinstance(item, dict):
            raise ValueError(f"Quality taxonomy category 不是对象: {path}")
        category = clean_text(item.get("category"))
        tags = {
            clean_text(tag).lower()
            for tag in item.get("any_tags", [])
            if clean_text(tag)
        }
        if not category or not tags or category in seen_categories:
            raise ValueError(f"Quality taxonomy category 非法或重复: {path}")
        seen_categories.add(category)
        normalized.append({"category": category, "any_tags": tags})
    return {
        "taxonomy_version": version,
        "fallback_category": fallback,
        "categories": normalized,
    }


def quality_category(rule_tags: str, taxonomy: dict[str, Any]) -> str:
    tags = {
        clean_text(tag).lower()
        for tag in rule_tags.split("|")
        if clean_text(tag)
    }
    for item in taxonomy["categories"]:
        if tags & item["any_tags"]:
            return str(item["category"])
    return str(taxonomy["fallback_category"])


def load_location_rules(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    required = {"classification_precedence", "path_rules"}
    missing = required - payload.keys()
    if missing:
        raise ValueError(f"位置分类规则缺少字段 {sorted(missing)}: {path}")
    return payload


def location_class(file_path: str, rules: dict[str, Any]) -> str:
    normalized = normalize_path(file_path).strip("/").lower()
    if not normalized:
        return "unknown"
    parts = [part for part in normalized.split("/") if part]
    basename = parts[-1] if parts else ""
    for category in rules["classification_precedence"]:
        if category == "production":
            return category
        definition = rules["path_rules"].get(category, {})
        if any(
            clean_text(segment).lower() in parts
            for segment in definition.get("segments", [])
        ):
            return category
        if any(
            normalized.startswith(clean_text(prefix).lower())
            for prefix in definition.get("prefixes", [])
        ):
            return category
        if basename in {
            clean_text(value).lower()
            for value in definition.get("basenames", [])
        }:
            return category
        if any(
            normalized.endswith(clean_text(suffix).lower())
            for suffix in definition.get("suffixes", [])
        ):
            return category
    return "production"


def rule_metadata(run: dict[str, Any]) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = {}
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    for rule in rules:
        rule_id = clean_text(rule.get("id"))
        properties = rule.get("properties") or {}
        tags = [clean_text(tag) for tag in properties.get("tags", [])]
        security_severity = numeric_security_severity(
            properties.get("security-severity")
        )
        cwes = sorted(
            {
                match.group(1).upper()
                for tag in tags
                if (match := re.search(r"(CWE-\d+)", tag, re.IGNORECASE))
            }
        )
        output[rule_id] = {
            "rule_name": clean_text(
                (rule.get("shortDescription") or {}).get("text")
            )
            or clean_text(rule.get("name")),
            "precision": clean_text(properties.get("precision")),
            "security_severity": security_severity,
            "problem_severity": clean_text(properties.get("problem.severity")),
            "rule_tags": "|".join(tag for tag in tags if tag),
            "rule_kind": clean_text(properties.get("kind"))
            or clean_text(rule.get("kind")),
            "cwe": "|".join(cwes),
        }
    return output


def result_rule_id(result: dict[str, Any], run: dict[str, Any]) -> str:
    rule_id = clean_text(result.get("ruleId"))
    if rule_id:
        return rule_id
    index = result.get("ruleIndex")
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    if isinstance(index, int) and 0 <= index < len(rules):
        return clean_text(rules[index].get("id"))
    return ""


def location(result: dict[str, Any]) -> tuple[str, str]:
    locations = result.get("locations") or []
    if not locations:
        return "", ""
    physical = locations[0].get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    return normalize_path(clean_text(artifact.get("uri"))), clean_text(
        region.get("startLine")
    )


def fingerprint_value(result: dict[str, Any]) -> str:
    fingerprints = result.get("partialFingerprints") or {}
    if not isinstance(fingerprints, dict) or not fingerprints:
        return ""
    normalized = {
        clean_text(key): clean_text(value)
        for key, value in fingerprints.items()
        if clean_text(key) and clean_text(value)
    }
    return json.dumps(normalized, ensure_ascii=True, sort_keys=True)


def load_alerts(
    path: Path,
    context: dict[str, str],
    taxonomy: dict[str, Any],
    location_rules: dict[str, Any],
) -> list[Alert]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if payload.get("version") != "2.1.0":
        raise ValueError(f"不支持的 SARIF 版本: {path}")

    alerts: list[Alert] = []
    for run in payload.get("runs", []):
        metadata = rule_metadata(run)
        for result in run.get("results", []):
            rule_id = result_rule_id(result, run)
            path_value, start_line = location(result)
            message = clean_text((result.get("message") or {}).get("text"))
            fingerprint = fingerprint_value(result)
            rule = metadata.get(rule_id, {})
            result_level = clean_text(result.get("level"))
            security_severity = rule.get("security_severity", "")
            problem_severity = rule.get("problem_severity", "")
            is_security = bool(security_severity)
            category = (
                ""
                if is_security
                else quality_category(rule.get("rule_tags", ""), taxonomy)
            )
            fingerprint_method = "fingerprint" if fingerprint else "fallback"
            row = {
                **context,
                "rule_id": rule_id,
                "rule_name": rule.get("rule_name", ""),
                "result_level": result_level,
                "security_severity": security_severity,
                "problem_severity": problem_severity,
                "rule_tags": rule.get("rule_tags", ""),
                "rule_kind": rule.get("rule_kind", ""),
                "is_security_alert": "true" if is_security else "false",
                "is_quality_alert": "false" if is_security else "true",
                "alert_category": "security" if is_security else "quality",
                "quality_category": category,
                "quality_taxonomy_version": (
                    "" if is_security else taxonomy["taxonomy_version"]
                ),
                # Keep the legacy column for downstream compatibility.  New
                # analyses must use the explicit fields above.
                "severity": result_level
                or security_severity
                or problem_severity,
                "precision": rule.get("precision", ""),
                "cwe": rule.get("cwe", ""),
                "file_path": path_value,
                "location_class": location_class(path_value, location_rules),
                "start_line": start_line,
                "message": message,
                "fingerprint": fingerprint,
                "match_method": fingerprint_method,
                "fingerprint_method": fingerprint_method,
                "fingerprint_ambiguity_n": "1",
                "lifecycle": "",
            }
            if fingerprint:
                key = ("fingerprint", rule_id, fingerprint)
            else:
                key = ("fallback", rule_id, path_value, message)
            alerts.append(Alert(row=row, key=key))
    return alerts


def compare_alerts(
    before: list[Alert],
    after: list[Alert],
) -> tuple[list[Alert], list[Alert], list[Alert]]:
    before_key_counts: dict[tuple[str, ...], int] = defaultdict(int)
    after_key_counts: dict[tuple[str, ...], int] = defaultdict(int)
    for alert in before:
        before_key_counts[alert.key] += 1
    for alert in after:
        after_key_counts[alert.key] += 1
    for alert in (*before, *after):
        alert.row["fingerprint_ambiguity_n"] = str(
            max(before_key_counts[alert.key], after_key_counts[alert.key])
        )

    before_by_key: dict[tuple[str, ...], deque[Alert]] = defaultdict(deque)
    for alert in before:
        before_by_key[alert.key].append(alert)

    introduced: list[Alert] = []
    persistent: list[Alert] = []
    for alert in after:
        matches = before_by_key.get(alert.key)
        if matches:
            matches.popleft()
            persistent.append(alert)
        else:
            introduced.append(alert)

    fixed = [
        alert
        for matches in before_by_key.values()
        for alert in matches
    ]
    return introduced, fixed, persistent


def is_security(alert: Alert) -> bool:
    return alert.row.get("is_security_alert") == "true"


def count_family(alerts: Iterable[Alert], security: bool) -> int:
    return sum(is_security(alert) is security for alert in alerts)


def label_lifecycle(alerts: Iterable[Alert], lifecycle: str) -> None:
    for alert in alerts:
        alert.row["lifecycle"] = lifecycle


def context_for(group: list[dict[str, str]]) -> dict[str, str]:
    first = group[0]
    return {
        "repo_name": first.get("repo_name", ""),
        "pr_number": first.get("pr_number", ""),
        "pr_id": first.get("pr_id", ""),
        "agent": first.get("agent", ""),
        "language": first.get("language", ""),
        "base_sha": first.get("base_sha", ""),
        "head_sha": first.get("head_sha", ""),
        "codeql_version": first.get("codeql_version", ""),
        "query_suite": first.get("query_suite", ""),
    }


def selected(group: list[dict[str, str]], args: argparse.Namespace) -> bool:
    first = group[0]
    if any(
        job.get("retry_excluded", "").strip().lower()
        in {"1", "true", "yes", "y"}
        for job in group
    ):
        return False
    if args.repo and first.get("repo_name") not in args.repo:
        return False
    if args.pr_number and first.get("pr_number") not in args.pr_number:
        return False
    return True


def main() -> None:
    args = parse_args()
    taxonomy = load_quality_taxonomy(Path(args.quality_taxonomy))
    location_rules = load_location_rules(Path(args.location_rules))
    jobs_path = Path(args.jobs)
    fields, jobs = read_csv(jobs_path)
    if "comparison_status" not in fields:
        fields.append("comparison_status")
    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for job in jobs:
        groups[(job.get("repo_name", ""), job.get("pr_number", ""))].append(job)

    summaries: list[dict[str, Any]] = []
    introduced_rows: list[dict[str, str]] = []
    fixed_rows: list[dict[str, str]] = []
    persistent_rows: list[dict[str, str]] = []
    persistent_count = 0
    compared = 0
    failed = 0

    for group in groups.values():
        if not selected(group, args):
            continue
        context = context_for(group)
        summary: dict[str, Any] = {
            **context,
            "before_alerts": "",
            "after_alerts": "",
            "introduced_alerts": "",
            "fixed_alerts": "",
            "persistent_alerts": "",
            "before_security_alerts": "",
            "after_security_alerts": "",
            "introduced_security_alerts": "",
            "fixed_security_alerts": "",
            "persistent_security_alerts": "",
            "before_quality_alerts": "",
            "after_quality_alerts": "",
            "introduced_quality_alerts": "",
            "fixed_quality_alerts": "",
            "persistent_quality_alerts": "",
            "comparison_status": "pending",
            "comparison_error": "",
        }
        by_revision = {job.get("revision"): job for job in group}
        try:
            if set(by_revision) != {"before", "after"}:
                raise ValueError("作业清单缺少 before 或 after")
            before_path = Path(by_revision["before"]["before_sarif"])
            after_path = Path(by_revision["after"]["after_sarif"])
            if not before_path.is_file() or not after_path.is_file():
                summaries.append(summary)
                continue
            before = load_alerts(before_path, context, taxonomy, location_rules)
            after = load_alerts(after_path, context, taxonomy, location_rules)
            introduced, fixed, persistent = compare_alerts(before, after)
            label_lifecycle(introduced, "introduced")
            label_lifecycle(fixed, "fixed")
            label_lifecycle(persistent, "persistent")
            introduced_rows.extend(alert.row for alert in introduced)
            fixed_rows.extend(alert.row for alert in fixed)
            persistent_count += len(persistent)
            if not args.omit_persistent_details:
                persistent_rows.extend(alert.row for alert in persistent)
            summary.update(
                {
                    "before_alerts": len(before),
                    "after_alerts": len(after),
                    "introduced_alerts": len(introduced),
                    "fixed_alerts": len(fixed),
                    "persistent_alerts": len(persistent),
                    "before_security_alerts": count_family(before, True),
                    "after_security_alerts": count_family(after, True),
                    "introduced_security_alerts": count_family(introduced, True),
                    "fixed_security_alerts": count_family(fixed, True),
                    "persistent_security_alerts": count_family(persistent, True),
                    "before_quality_alerts": count_family(before, False),
                    "after_quality_alerts": count_family(after, False),
                    "introduced_quality_alerts": count_family(introduced, False),
                    "fixed_quality_alerts": count_family(fixed, False),
                    "persistent_quality_alerts": count_family(persistent, False),
                    "comparison_status": "compared",
                }
            )
            for job in group:
                job["comparison_status"] = "compared"
            compared += 1
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            error = clean_text(exc)[-1000:]
            summary["comparison_status"] = "failed"
            summary["comparison_error"] = error
            for job in group:
                job["comparison_status"] = "failed"
            failed += 1
        summaries.append(summary)

    output_dir = Path(args.output_dir)
    write_csv(
        output_dir / "pr_security_summary.csv",
        SUMMARY_FIELDS,
        summaries,
    )
    write_csv(
        output_dir / "introduced_alerts.csv",
        ALERT_FIELDS,
        introduced_rows,
    )
    write_csv(output_dir / "fixed_alerts.csv", ALERT_FIELDS, fixed_rows)
    write_csv(
        output_dir / "persistent_alerts.csv",
        ALERT_FIELDS,
        persistent_rows,
    )
    if not args.no_update_jobs:
        write_jobs(jobs_path, fields, jobs)
    persistent_note = (
        f"persistent {persistent_count}（明细已省略）"
        if args.omit_persistent_details
        else f"persistent {len(persistent_rows)}"
    )
    print(
        f"差分完成：PR {compared} 个，失败 {failed} 个；"
        f"introduced {len(introduced_rows)}，fixed {len(fixed_rows)}，"
        f"{persistent_note}"
    )
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
