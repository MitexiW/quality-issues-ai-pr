#!/usr/bin/env python3
"""Audit a compiled AI-quality root-cause dataset and its boundary recheck."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PROHIBITED_CAUSAL_PHRASES = (
    "the ai forgot",
    "the model forgot",
    "the ai hallucinated",
    "the model hallucinated",
    "the ai did not understand",
    "the model did not understand",
    "the ai was careless",
    "the model was careless",
    "the ai lacked context",
    "the model lacked context",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiled-dir", type=Path, required=True)
    parser.add_argument("--taxonomy", type=Path, default=Path("config/study/ai_quality_root_cause_taxonomy.json"))
    parser.add_argument("--boundary-decisions", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--large-cluster-threshold", type=int, default=5)
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
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def cluster_key(row: dict[str, str]) -> tuple[str, str, str]:
    return row["repo_name"], row["pr_number"], row["cluster_key_within_pr"]


def high_risk_reasons(row: dict[str, str], threshold: int) -> list[str]:
    reasons = []
    if int(row["rule_n"]) > 1:
        reasons.append("cross_rule")
    if int(row["alert_n"]) >= threshold:
        reasons.append("large_cluster")
    if row["confidence"] != "high":
        reasons.append("non_high_confidence")
    return reasons


def load_boundary_decisions(path: Path | None) -> dict[tuple[str, str, str], dict[str, Any]]:
    if path is None:
        return {}
    payload = json.loads(resolve(path).read_text(encoding="utf-8"))
    decisions: dict[tuple[str, str, str], dict[str, Any]] = {}
    for decision in payload.get("reviews", []):
        key = (str(decision["repo_name"]), str(decision["pr_number"]), decision["cluster_key_within_pr"])
        if key in decisions:
            raise ValueError(f"Duplicate boundary decision: {key}")
        if decision.get("outcome") not in {"confirmed", "revised"}:
            raise ValueError(f"Invalid boundary decision outcome for {key}")
        decisions[key] = decision
    return decisions


def run(args: argparse.Namespace) -> None:
    compiled = resolve(args.compiled_dir)
    output = resolve(args.output_dir)
    taxonomy = json.loads(resolve(args.taxonomy).read_text(encoding="utf-8"))
    manifest = json.loads((compiled / "manifest.json").read_text(encoding="utf-8"))
    clusters = read_csv(compiled / "root_cause_clusters.csv")
    links = read_csv(compiled / "alert_cluster_links.csv")

    if len(clusters) != manifest["root_cause_cluster_n"]:
        raise ValueError("Cluster CSV count does not match compiled manifest")
    if len(links) != manifest["alert_n"]:
        raise ValueError("Alert-link CSV count does not match compiled manifest")
    if len({row["root_cause_cluster_id"] for row in clusters}) != len(clusters):
        raise ValueError("Duplicate root_cause_cluster_id")
    if len({row["alert_id"] for row in links}) != len(links):
        raise ValueError("An alert is linked more than once")

    category_to_submechanisms = {
        category["id"]: {item["id"] for item in category["submechanisms"]}
        for category in taxonomy["root_cause_categories"]
    }
    expected_category_n = taxonomy["reporting_policy"]["primary_category_n"]
    if len(category_to_submechanisms) != expected_category_n:
        raise ValueError("Taxonomy does not contain the frozen number of primary categories")

    cluster_by_id = {row["root_cause_cluster_id"]: row for row in clusters}
    link_counts = Counter(row["root_cause_cluster_id"] for row in links)
    mental_state_violations = []
    for row in clusters:
        category = row["root_cause_category"]
        if category not in category_to_submechanisms:
            raise ValueError(f"Unknown root-cause category: {category}")
        if row["mechanism_subcategory"] not in category_to_submechanisms[category]:
            raise ValueError(f"Submechanism/category mismatch: {cluster_key(row)}")
        if link_counts[row["root_cause_cluster_id"]] != int(row["alert_n"]):
            raise ValueError(f"Cluster alert count mismatch: {cluster_key(row)}")
        if not row["cause_statement"].strip() or not row["evidence_summary"].strip():
            raise ValueError(f"Missing causal evidence: {cluster_key(row)}")
        lowered = row["cause_statement"].casefold()
        if any(phrase in lowered for phrase in PROHIBITED_CAUSAL_PHRASES):
            mental_state_violations.append(row["root_cause_cluster_id"])
    unknown_link_ids = sorted(set(link_counts) - set(cluster_by_id))
    if unknown_link_ids:
        raise ValueError(f"Links reference unknown clusters: {unknown_link_ids[:3]}")
    if mental_state_violations:
        raise ValueError(f"Cause statements infer unsupported mental states: {mental_state_violations}")

    decisions = load_boundary_decisions(args.boundary_decisions)
    queue_rows = []
    for row in clusters:
        reasons = high_risk_reasons(row, args.large_cluster_threshold)
        if not reasons:
            continue
        decision = decisions.get(cluster_key(row), {})
        queue_rows.append(
            {
                "root_cause_cluster_id": row["root_cause_cluster_id"],
                "repo_name": row["repo_name"],
                "pr_number": row["pr_number"],
                "cluster_key_within_pr": row["cluster_key_within_pr"],
                "review_reasons": ";".join(reasons),
                "alert_n": row["alert_n"],
                "rule_n": row["rule_n"],
                "root_cause_category": row["root_cause_category"],
                "mechanism_subcategory": row["mechanism_subcategory"],
                "confidence": row["confidence"],
                "audit_outcome": decision.get("outcome", "pending"),
                "audit_basis": decision.get("basis", ""),
                "audit_note": decision.get("note", ""),
            }
        )
    pending = [row for row in queue_rows if row["audit_outcome"] == "pending"]
    if args.boundary_decisions and pending:
        raise ValueError(f"Boundary audit has {len(pending)} unreviewed high-risk clusters")

    rule_category: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"clusters": set(), "alerts": set(), "prs": set()}
    )
    for link in links:
        cluster = cluster_by_id[link["root_cause_cluster_id"]]
        key = link["rule_id"], cluster["root_cause_category"]
        rule_category[key]["clusters"].add(cluster["root_cause_cluster_id"])
        rule_category[key]["alerts"].add(link["alert_id"])
        rule_category[key]["prs"].add((link["repo_name"], link["pr_number"]))
    cross_rows = [
        {
            "rule_id": rule_id,
            "root_cause_category": category,
            "cluster_n": len(values["clusters"]),
            "alert_n": len(values["alerts"]),
            "pr_n": len(values["prs"]),
        }
        for (rule_id, category), values in sorted(rule_category.items())
    ]

    write_csv(
        output / "boundary_audit.csv",
        queue_rows,
        [
            "root_cause_cluster_id", "repo_name", "pr_number", "cluster_key_within_pr",
            "review_reasons", "alert_n", "rule_n", "root_cause_category",
            "mechanism_subcategory", "confidence", "audit_outcome", "audit_basis", "audit_note",
        ],
    )
    write_csv(
        output / "rule_category_crosstab.csv",
        cross_rows,
        ["rule_id", "root_cause_category", "cluster_n", "alert_n", "pr_n"],
    )

    confidence_counts = Counter(row["confidence"] for row in clusters)
    audit_manifest = {
        "schema_version": "1.0.0",
        "status": "complete" if not pending else "pending_boundary_review",
        "structural_checks": "passed",
        "cluster_n": len(clusters),
        "alert_n": len(links),
        "primary_category_n": len(category_to_submechanisms),
        "high_risk_cluster_n": len(queue_rows),
        "reviewed_high_risk_cluster_n": len(queue_rows) - len(pending),
        "pending_high_risk_cluster_n": len(pending),
        "confidence_counts": dict(sorted(confidence_counts.items())),
        "insufficient_evidence_cluster_n": sum(row["disposition"] == "insufficient_evidence" for row in clusters),
        "unsupported_mental_state_statement_n": len(mental_state_violations),
        "inter_rater_reliability_claimed": False,
    }
    output.mkdir(parents=True, exist_ok=True)
    temporary = output / "manifest.json.tmp"
    temporary.write_text(json.dumps(audit_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(output / "manifest.json")
    report_lines = [
        "# AI Quality root-cause dataset audit",
        "",
        f"- Structural status: {audit_manifest['structural_checks']}",
        f"- Alerts linked exactly once: {audit_manifest['alert_n']}",
        f"- Root-cause clusters: {audit_manifest['cluster_n']}",
        f"- Frozen primary categories: {audit_manifest['primary_category_n']}",
        f"- High-risk boundary cases rechecked: {audit_manifest['reviewed_high_risk_cluster_n']} / {audit_manifest['high_risk_cluster_n']}",
        f"- Non-high-confidence clusters retained: {sum(v for k, v in confidence_counts.items() if k != 'high')}",
        f"- Insufficient-evidence dispositions: {audit_manifest['insufficient_evidence_cluster_n']}",
        "",
        "This is a same-reviewer consistency and boundary recheck, not an independent double-coding exercise. No inter-rater reliability statistic is claimed.",
        "",
    ]
    (output / "report.md").write_text("\n".join(report_lines), encoding="utf-8")
    print(json.dumps(audit_manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    run(parse_args())
