#!/usr/bin/env python3
"""Compile and validate root-cause cluster decisions."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REVIEW = ROOT / "data/experiments/security-and-quality/study_stars500/reports/ai_quality_root_cause_review_20260831_v1"
DEFAULT_TAXONOMY = ROOT / "config/study/ai_quality_root_cause_taxonomy.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-dir", type=Path, default=DEFAULT_REVIEW)
    parser.add_argument("--scope-prs", type=Path, required=True)
    parser.add_argument(
        "--alerts",
        type=Path,
        help=(
            "optional validated-alert CSV used instead of embedded review packets; "
            "this supports public-artifact recomputation without redistributing "
            "third-party source snippets"
        ),
    )
    parser.add_argument("--decisions", type=Path, required=True, nargs="+")
    parser.add_argument("--taxonomy", type=Path, default=DEFAULT_TAXONOMY)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> list[dict[str, str]]:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            break
        except OverflowError:
            limit //= 10
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
    temporary.replace(path)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def cluster_id(repo: str, pr: str, key: str) -> str:
    return "rccluster-" + hashlib.sha256(f"{repo}\0{pr}\0{key}".encode()).hexdigest()[:20]


def matches(alert: dict[str, str], selector: dict[str, Any]) -> bool:
    allowed = {"rule_id", "file_path", "alert_ids", "exclude_alert_ids"}
    unknown = set(selector) - allowed
    if unknown:
        raise ValueError(f"unknown selector fields: {sorted(unknown)}")
    if selector.get("rule_id") and alert["rule_id"] != selector["rule_id"]:
        return False
    paths = selector.get("file_path")
    if isinstance(paths, str):
        paths = [paths]
    if paths and alert["file_path"] not in paths:
        return False
    if selector.get("alert_ids") and alert["alert_id"] not in selector["alert_ids"]:
        return False
    if alert["alert_id"] in selector.get("exclude_alert_ids", []):
        return False
    return True


def truthy(value: Any) -> bool:
    return str(value).strip().casefold() in {"1", "true", "yes", "y"}


def alerts_from_public_table(
    path: Path,
    scope: set[tuple[str, str]],
) -> dict[tuple[str, str], list[dict[str, str]]]:
    """Load the frozen AI Quality surface without embedded source packets."""

    alerts_by_pr: dict[tuple[str, str], list[dict[str, str]]] = {
        key: [] for key in scope
    }
    for row in read_csv(path):
        pr_key = row.get("repo_name", ""), str(row.get("pr_number", ""))
        if pr_key not in scope or row.get("group") != "ai":
            continue
        is_quality = (
            row.get("issue_domain") == "quality"
            or truthy(row.get("is_quality_alert", ""))
        )
        if not is_quality:
            continue
        alerts_by_pr[pr_key].append(
            {
                "alert_id": row["alert_id"],
                "rule_id": row["rule_id"],
                "rule_name": row.get("rule_name", ""),
                "file_path": row["file_path"],
                "start_line": row.get("start_line", ""),
            }
        )
    missing_prs = sorted(key for key, rows in alerts_by_pr.items() if not rows)
    if missing_prs:
        raise ValueError(
            "validated-alert CSV contains no AI Quality alerts for scope PRs: "
            f"{missing_prs[:5]}"
        )
    return alerts_by_pr


def run(args: argparse.Namespace) -> None:
    review, scope_path = map(resolve, (args.review_dir, args.scope_prs))
    decisions_paths = [resolve(path) for path in args.decisions]
    taxonomy_path, output = resolve(args.taxonomy), resolve(args.output_dir)
    scope_rows = read_csv(scope_path)
    scope = {(row["repo_name"], row["pr_number"]) for row in scope_rows}
    if len(scope) != len(scope_rows):
        raise ValueError("scope PR table contains duplicate repo/PR keys")
    alerts_path = getattr(args, "alerts", None)
    if alerts_path:
        alerts_by_pr = alerts_from_public_table(resolve(alerts_path), scope)
    else:
        alerts_by_pr: dict[tuple[str, str], list[dict[str, str]]] = {}
        for row in scope_rows:
            packet = load_json(review / row["packet_path"])
            alerts = []
            for unit in packet["initial_pr_rule_units"]:
                for alert in unit["alerts"]:
                    alerts.append({**alert, "rule_id": unit["rule_id"], "rule_name": unit["rule_name"]})
            alerts_by_pr[(row["repo_name"], row["pr_number"])] = alerts
    expected_ids = {alert["alert_id"] for alerts in alerts_by_pr.values() for alert in alerts}

    taxonomy = load_json(taxonomy_path)
    category_subs = {
        category["id"]: {sub["id"] for sub in category["submechanisms"]}
        for category in taxonomy["root_cause_categories"]
    }
    dispositions = {item["id"] for item in taxonomy.get("non_category_dispositions", [])}
    decision_documents = [load_json(path) for path in decisions_paths]
    if any(document.get("construct") != taxonomy["construct"] for document in decision_documents):
        raise ValueError("decision construct does not match taxonomy")
    decisions = {"clusters": [cluster for document in decision_documents for cluster in document.get("clusters", [])]}

    cluster_rows: list[dict[str, Any]] = []
    link_rows: list[dict[str, Any]] = []
    linked: dict[str, str] = {}
    seen_keys: set[tuple[str, str, str]] = set()
    for decision in decisions.get("clusters", []):
        repo, pr, key = decision["repo_name"], str(decision["pr_number"]), decision["cluster_key_within_pr"]
        pr_key = repo, pr
        if pr_key not in scope:
            raise ValueError(f"decision outside frozen scope: {repo} #{pr}")
        unique_key = repo, pr, key
        if unique_key in seen_keys:
            raise ValueError(f"duplicate cluster key: {unique_key}")
        seen_keys.add(unique_key)
        category = decision.get("root_cause_category", "")
        disposition = decision.get("disposition", "")
        sub = decision.get("mechanism_subcategory", "")
        if bool(category) == bool(disposition):
            raise ValueError(f"cluster must have exactly one category or disposition: {unique_key}")
        if category:
            if category not in category_subs or sub not in category_subs[category]:
                raise ValueError(f"invalid category/subcategory for {unique_key}: {category}/{sub}")
        elif disposition not in dispositions or sub:
            raise ValueError(f"invalid non-category disposition for {unique_key}")
        selectors = decision.get("selectors", [])
        members = [alert for alert in alerts_by_pr[pr_key] if any(matches(alert, selector) for selector in selectors)]
        if not members:
            raise ValueError(f"cluster selectors matched no alerts: {unique_key}")
        cid = cluster_id(repo, pr, key)
        for alert in members:
            if alert["alert_id"] in linked:
                raise ValueError(f"alert linked more than once: {alert['alert_id']} ({linked[alert['alert_id']]}, {cid})")
            linked[alert["alert_id"]] = cid
            link_rows.append({"alert_id": alert["alert_id"], "root_cause_cluster_id": cid,
                              "repo_name": repo, "pr_number": pr, "rule_id": alert["rule_id"],
                              "file_path": alert["file_path"], "start_line": alert["start_line"]})
        rules = sorted({alert["rule_id"] for alert in members})
        files = sorted({alert["file_path"] for alert in members})
        cluster_rows.append({
            "root_cause_cluster_id": cid, "repo_name": repo, "pr_number": pr,
            "cluster_key_within_pr": key, "alert_n": len(members), "rule_n": len(rules),
            "rules_json": json.dumps(rules), "files_json": json.dumps(files),
            "root_cause_category": category, "mechanism_subcategory": sub, "disposition": disposition,
            "change_operation": decision.get("change_operation", ""),
            "violated_relation": decision.get("violated_relation", ""),
            "cause_statement": decision.get("cause_statement", ""),
            "evidence_summary": decision.get("evidence_summary", ""),
            "confidence": decision.get("confidence", ""),
        })
    missing = sorted(expected_ids - set(linked))
    extra = sorted(set(linked) - expected_ids)
    if missing or extra:
        raise ValueError(f"alert partition is incomplete: missing={len(missing)}, extra={len(extra)}, first_missing={missing[:5]}")
    for row in cluster_rows:
        for field in ("cause_statement", "evidence_summary", "confidence"):
            if not row[field]:
                raise ValueError(f"cluster {row['root_cause_cluster_id']} missing {field}")

    cluster_fields = ["root_cause_cluster_id", "repo_name", "pr_number", "cluster_key_within_pr",
        "alert_n", "rule_n", "rules_json", "files_json", "root_cause_category", "mechanism_subcategory",
        "disposition", "change_operation", "violated_relation", "cause_statement", "evidence_summary",
        "confidence"]
    link_fields = ["alert_id", "root_cause_cluster_id", "repo_name", "pr_number", "rule_id", "file_path", "start_line"]
    cluster_rows.sort(key=lambda row: (row["repo_name"], row["pr_number"], row["cluster_key_within_pr"]))
    link_rows.sort(key=lambda row: row["alert_id"])
    write_csv(output / "root_cause_clusters.csv", cluster_rows, cluster_fields)
    write_csv(output / "alert_cluster_links.csv", link_rows, link_fields)
    manifest = {
        "schema_version": "1.0.0", "status": "compiled_complete_partition",
        "generated_at": datetime.now(timezone.utc).isoformat(), "scope_pr_n": len(scope),
        "alert_n": len(link_rows), "root_cause_cluster_n": len(cluster_rows),
        "initial_pr_rule_n": len({(row["repo_name"], row["pr_number"], row["rule_id"]) for row in link_rows}),
        "split_pr_rule_n": sum(
            len(cluster_ids) > 1
            for cluster_ids in (
                {link["root_cause_cluster_id"] for link in link_rows
                 if (link["repo_name"], link["pr_number"], link["rule_id"]) == key}
                for key in {(row["repo_name"], row["pr_number"], row["rule_id"]) for row in link_rows}
            )
        ),
        "cross_rule_cluster_n": sum(int(row["rule_n"]) > 1 for row in cluster_rows),
        "singleton_alert_cluster_n": sum(int(row["alert_n"]) == 1 for row in cluster_rows),
        "median_alerts_per_cluster": statistics.median(int(row["alert_n"]) for row in cluster_rows),
        "max_alerts_per_cluster": max(int(row["alert_n"]) for row in cluster_rows),
        "category_counts": dict(Counter(row["root_cause_category"] or row["disposition"] for row in cluster_rows)),
        "inputs": {"scope_sha256": sha256(scope_path),
                   "decisions": [{"path": str(path), "sha256": sha256(path)} for path in decisions_paths],
                   "taxonomy_sha256": sha256(taxonomy_path)},
    }
    write_json(output / "manifest.json", manifest)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    run(parse_args())
