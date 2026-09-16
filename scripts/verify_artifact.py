#!/usr/bin/env python3
"""Verify the integrity and headline invariants of the public artifact."""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path


EXPECTED_DISPOSITIONS = {
    "confirmed_valid": 2322,
    "not_valid_issue": 2155,
    "not_pr_introduced": 2127,
    "condition_absent": 520,
}
EXPECTED_ROOT_CAUSE_CATEGORIES = {
    "incomplete_change_coordination": 257,
    "redundant_or_locally_inconsistent_construction": 70,
    "interface_or_contract_mismatch": 16,
    "control_state_or_dataflow_miscomposition": 44,
    "dependency_error_or_resource_mismanagement": 25,
}
EXPECTED_RQ3_INITIAL_PROVENANCE = Counter(
    {"LLM_assistant": 776, "deterministic_rule": 240}
)
EXPECTED_RQ3_FINAL_RELATIONS = Counter(
    {"same_issue": 45, "related_distinct": 187, "no_match": 544, "no_reference": 240}
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="public-artifact root (defaults to the parent of scripts/)",
    )
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            break
        except OverflowError:
            limit //= 10
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def truthy(value: str) -> bool:
    return value.strip().casefold() in {"1", "true", "yes", "y"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def verify_checksums(root: Path) -> int:
    manifest_path = root / "artifact_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("status") == "ready_to_publish", "artifact is not publication-ready")
    require(manifest.get("license_selected") is True, "artifact licenses are not finalized")
    entries = manifest.get("files", [])
    require(entries, "artifact manifest contains no file inventory")
    seen: set[str] = set()
    for entry in entries:
        relative = entry["path"]
        require(relative not in seen, f"duplicate manifest path: {relative}")
        seen.add(relative)
        path = root / relative
        require(path.is_file(), f"missing artifact file: {relative}")
        require(path.stat().st_size == entry["size"], f"size mismatch: {relative}")
        require(sha256(path) == entry["sha256"], f"SHA-256 mismatch: {relative}")
    required_release_files = {
        "LICENSE.md",
        "LICENSES/MIT.txt",
        "LICENSES/CC-BY-4.0.txt",
        "NOTICE.md",
        "docs/RUN_EXPERIMENTS.md",
        "scripts/reproduce_analysis.py",
        "config/study/ai_quality_root_cause_taxonomy.json",
        "config/study/root_cause_decision.json",
        "config/study/ai_quality_root_cause_boundary_audit_v1.json",
        "scripts/analysis/compile_ai_quality_root_cause_annotations.py",
        "scripts/analysis/summarize_ai_quality_root_causes.py",
        "scripts/analysis/audit_ai_quality_root_cause_dataset.py",
        "scripts/summarize_llm_review_run.py",
        "scripts/rq3/summarize_claude_review_example.py",
        "data/manifests/ai_codeql_jobs.csv",
        "data/manifests/human_codeql_jobs.csv",
        "data/manifests/ai_prs.csv",
        "data/manifests/human_prs.csv",
        "data/results/rq3_formal_plan_20260727_v1/formal_cases.csv",
        "data/results/rq3_formal_results_20260729_v1/case_metrics.csv",
        "data/results/rq3_formal_results_20260729_v1/finding_matches.csv",
        "data/results/rq3_formal_worktrees_20260727_v1/worktree_key_public.csv",
        "data/results/rq3_semantic_human_review_v1/author_relation_review.csv",
        "data/results/rq3_semantic_human_review_v1/summary.json",
        "data/results/rq3_semantic_human_review_v1/manifest.json",
        "config/study/model_screening_execution.json",
    }
    require(
        required_release_files <= seen,
        f"missing release documentation: {sorted(required_release_files - seen)}",
    )
    ignored_roots = {".git", ".venv", "outputs", "__pycache__"}
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and not any(part in ignored_roots for part in path.relative_to(root).parts)
        and path.suffix != ".pyc"
    }
    expected = seen | {"artifact_manifest.json", "checksums.sha256"}
    require(
        actual == expected,
        "artifact contains uninventoried or missing files: "
        f"extra={sorted(actual - expected)[:8]} missing={sorted(expected - actual)[:8]}",
    )
    for relative in sorted(seen):
        if relative.endswith(".py"):
            source = (root / relative).read_text(encoding="utf-8")
            ast.parse(source, filename=relative)
    script_reference = re.compile(r"scripts/[A-Za-z0-9_./-]+\.py")
    referenced: set[str] = set()
    for relative in sorted(seen):
        if not (
            relative == "README.md"
            or relative.startswith("docs/")
            or relative.startswith("config/")
        ):
            continue
        path = root / relative
        if path.suffix.lower() not in {".md", ".json", ".yaml", ".yml", ".txt"}:
            continue
        referenced.update(script_reference.findall(path.read_text(encoding="utf-8")))
    missing_references = {
        path
        for path in referenced
        if path not in seen and not path.startswith("scripts/archive/")
    }
    require(
        not missing_references,
        f"documentation/config references missing scripts: {sorted(missing_references)}",
    )
    return len(entries)


def verify_scientific_invariants(root: Path) -> dict[str, int]:
    reports = root / "data/results"
    labels = read_csv(
        reports / "final_human_consensus_20260817_v1/final_alert_labels.csv"
    )
    require(len(labels) == 7124, "final alert census must contain 7,124 rows")
    require(len({row["alert_id"] for row in labels}) == 7124, "alert_id is not unique")
    require(all(row["status"] == "completed" for row in labels), "incomplete final label")
    dispositions = Counter(row["disposition"] for row in labels)
    require(dict(dispositions) == EXPECTED_DISPOSITIONS, "final dispositions changed")

    confirmed = read_csv(
        reports
        / "final_human_confirmed_issue_analysis_20260817_v1/validated_alerts.csv"
    )
    require(len(confirmed) == 2322, "confirmed-alert table must contain 2,322 rows")
    confirmed_ids = {row["alert_id"] for row in confirmed}
    expected_ids = {
        row["alert_id"] for row in labels if row["disposition"] == "confirmed_valid"
    }
    require(confirmed_ids == expected_ids, "confirmed-alert IDs disagree with final labels")
    family_counts = Counter(
        "quality" if truthy(row["is_quality_alert"]) else "security"
        for row in confirmed
    )
    require(family_counts == Counter({"quality": 2194, "security": 128}), "family counts changed")

    prs = read_csv(
        reports
        / "final_human_confirmed_issue_analysis_20260817_v1/analysis_pr_level.csv"
    )
    eligible = [row for row in prs if row["analysis_status"] == "eligible"]
    require(len(eligible) == 5404, "PR analysis population must contain 5,404 rows")
    group_counts = Counter(row["group"] for row in eligible)
    require(group_counts == Counter({"ai": 3087, "human": 2317}), "PR group counts changed")
    affected = Counter(
        row["group"] for row in eligible if truthy(row["validated_quality_any"])
    )
    require(affected == Counter({"human": 264, "ai": 251}), "Quality-positive PR counts changed")

    root_cause_dir = reports / "ai_quality_root_cause_review_20260831_v1"
    clusters = read_csv(root_cause_dir / "full_compiled_v1/root_cause_clusters.csv")
    links = read_csv(root_cause_dir / "full_compiled_v1/alert_cluster_links.csv")
    require(len(clusters) == 412, "RQ1 root-cause table must contain 412 clusters")
    require(len(links) == 775, "RQ1 alert-to-cluster mapping must contain 775 rows")
    require(
        len({row["root_cause_cluster_id"] for row in clusters}) == 412,
        "RQ1 root-cause cluster IDs are not unique",
    )
    require(
        len({row["alert_id"] for row in links}) == 775,
        "RQ1 alert-to-cluster mapping is not one-to-one",
    )
    ai_quality_ids = {
        row["alert_id"]
        for row in confirmed
        if row["group"] == "ai"
        and (
            row.get("issue_domain") == "quality"
            or truthy(row.get("is_quality_alert", ""))
        )
    }
    require(
        {row["alert_id"] for row in links} == ai_quality_ids,
        "RQ1 cluster mapping does not cover exactly the 775 AI Quality alerts",
    )
    root_cause_counts = Counter(row["root_cause_category"] for row in clusters)
    require(
        dict(root_cause_counts) == EXPECTED_ROOT_CAUSE_CATEGORIES,
        "RQ1 root-cause category counts changed",
    )
    audit = json.loads(
        (root_cause_dir / "full_audit_v1/manifest.json").read_text(encoding="utf-8")
    )
    require(audit.get("status") == "complete", "RQ1 boundary audit is incomplete")
    require(audit.get("reviewed_high_risk_cluster_n") == 32, "RQ1 boundary-audit count changed")
    require(audit.get("pending_high_risk_cluster_n") == 0, "RQ1 boundary audit has pending cases")

    ai_pr_manifest = read_csv(root / "data/manifests/ai_prs.csv")
    human_pr_manifest = read_csv(root / "data/manifests/human_prs.csv")
    require(len(ai_pr_manifest) == 3376, "AI selected-PR manifest row count changed")
    require(len(human_pr_manifest) == 2446, "Human selected-PR manifest row count changed")
    require(
        len({row["pr_id"] for row in ai_pr_manifest}) == len(ai_pr_manifest),
        "AI selected-PR manifest contains duplicate PR IDs",
    )
    require(
        len({row["pr_id"] for row in human_pr_manifest}) == len(human_pr_manifest),
        "Human selected-PR manifest contains duplicate PR IDs",
    )
    for group, rows in (("AI", ai_pr_manifest), ("Human", human_pr_manifest)):
        keys = [(row["repo_name"].casefold(), row["pr_number"]) for row in rows]
        require(len(set(keys)) == len(keys), f"{group} selected-PR keys are not unique")
        forbidden = {"pr_title", "pr_body", "task_reason"}
        require(
            not forbidden.intersection(rows[0]),
            f"{group} selected-PR projection contains third-party prose",
        )

    ai_jobs = read_csv(root / "data/manifests/ai_codeql_jobs.csv")
    human_jobs = read_csv(root / "data/manifests/human_codeql_jobs.csv")
    require(len(ai_jobs) == 6752, "AI CodeQL job-manifest row count changed")
    require(len(human_jobs) == 4892, "Human CodeQL job-manifest row count changed")
    require(
        len({row["job_id"] for row in ai_jobs}) == len(ai_jobs),
        "AI CodeQL job IDs are not unique",
    )
    require(
        len({row["job_id"] for row in human_jobs}) == len(human_jobs),
        "Human CodeQL job IDs are not unique",
    )
    for group, manifest_rows, job_rows in (
        ("AI", ai_pr_manifest, ai_jobs),
        ("Human", human_pr_manifest, human_jobs),
    ):
        pr_keys = {(row["repo_name"].casefold(), row["pr_number"]) for row in manifest_rows}
        job_keys = {(row["repo_name"].casefold(), row["pr_number"]) for row in job_rows}
        require(job_keys == pr_keys, f"{group} PR and CodeQL job manifests disagree")
        revisions: dict[tuple[str, str], set[str]] = {}
        for row in job_rows:
            key = (row["repo_name"].casefold(), row["pr_number"])
            revisions.setdefault(key, set()).add(row["revision"])
            require("/home/" not in row.get("build_command", ""), "host path in build command")
        require(
            all(value == {"before", "after"} for value in revisions.values()),
            f"{group} jobs are not exact before/after pairs",
        )
        forbidden = {
            "source_dir", "database_dir", "sarif_path", "before_sarif",
            "after_sarif", "create_command", "analyze_command", "last_error",
            "log_path",
        }
        require(
            not forbidden.intersection(job_rows[0]),
            f"{group} job projection contains private runtime fields",
        )

    rq3_cases = read_csv(reports / "rq3_formal_plan_20260727_v1/formal_cases.csv")
    rq3_case_metrics = read_csv(reports / "rq3_formal_results_20260729_v1/case_metrics.csv")
    rq3_findings = read_csv(reports / "rq3_formal_results_20260729_v1/finding_matches.csv")
    rq3_worktrees = read_csv(
        reports / "rq3_formal_worktrees_20260727_v1/worktree_key_public.csv"
    )
    require(len(rq3_cases) == 267, "RQ3 formal frame must contain 267 cases")
    require(len(rq3_case_metrics) == 267, "RQ3 case metrics must contain 267 cases")
    require(len(rq3_findings) == 1016, "RQ3 structured finding count changed")
    require(len(rq3_worktrees) == 267, "RQ3 worktree identity table must contain 267 cases")
    require(
        {row["case_id"] for row in rq3_cases}
        == {row["case_id"] for row in rq3_case_metrics},
        "RQ3 formal frame and case metrics disagree",
    )
    require(
        {row["case_id"] for row in rq3_cases}
        == {row["case_id"] for row in rq3_worktrees},
        "RQ3 formal frame and worktree identity table disagree",
    )

    semantic_relations = read_csv(
        reports
        / "rq3_semantic_results_20260729_v1"
        / "semantic_finding_relations_public.csv"
    )
    require(len(semantic_relations) == 1016, "RQ3 semantic relation count changed")
    adjudicator_types = Counter(row["adjudicator_type"] for row in semantic_relations)
    require(
        adjudicator_types == EXPECTED_RQ3_INITIAL_PROVENANCE,
        "RQ3 semantic-decision provenance changed",
    )

    author_review = read_csv(
        reports / "rq3_semantic_human_review_v1" / "author_relation_review.csv"
    )
    require(len(author_review) == 1016, "RQ3 author-review count changed")
    review_keys = {(row["case_id"], row["model_finding_id"]) for row in author_review}
    semantic_by_key = {
        (row["case_id"], row["model_finding_id"]): row for row in semantic_relations
    }
    require(len(review_keys) == 1016, "RQ3 author-review keys are not unique")
    require(review_keys == set(semantic_by_key), "RQ3 author review does not cover all findings")
    require(
        all(row["human_review_status"] == "author_confirmed" for row in author_review),
        "RQ3 author review contains an unconfirmed decision",
    )
    require(
        all(row["final_decision_source"] == "author_manual_review" for row in author_review),
        "RQ3 final decision source changed",
    )
    require(
        all(row["reviewer_role"] == "author" for row in author_review),
        "RQ3 reviewer role changed",
    )
    initial_provenance = Counter(row["initial_adjudicator_type"] for row in author_review)
    require(
        initial_provenance == EXPECTED_RQ3_INITIAL_PROVENANCE,
        "RQ3 author-review initial provenance changed",
    )
    initial_fields = {
        "initial_adjudicator_type": "adjudicator_type",
        "initial_codeql_relation": "codeql_relation",
        "initial_matched_reference_ids": "matched_reference_ids",
        "initial_relation_confidence": "relation_confidence",
        "initial_relation_rationale": "relation_rationale",
    }
    for row in author_review:
        initial = semantic_by_key[(row["case_id"], row["model_finding_id"])]
        require(
            all(
                row[review_field] == initial[semantic_field]
                for review_field, semantic_field in initial_fields.items()
            ),
            "RQ3 author review rewrites an initial semantic decision or its provenance",
        )
        require(
            re.fullmatch(r"[0-9a-f]{64}", row["source_row_sha256"]) is not None,
            "RQ3 author review contains an invalid source-row digest",
        )
    final_relations = Counter(row["final_codeql_relation"] for row in author_review)
    require(final_relations == EXPECTED_RQ3_FINAL_RELATIONS, "RQ3 final relation counts changed")

    rq3 = read_csv(reports / "final_human_confirmed_rq3_20260817_v1/group_metrics.csv")
    primary = [row for row in rq3 if row.get("layer") == "human_confirmed_primary"]
    require(sum(int(row["reference_n"]) for row in primary) == 114, "RQ3 reference count changed")
    require(sum(int(row["recovered_n"]) for row in primary) == 20, "RQ3 recovery count changed")

    mechanism_dir = reports / "rq3_all_reference_mechanism_mapping_20260901_v1"
    mechanism_rows = read_csv(mechanism_dir / "reference_mechanism_mapping.csv")
    require(len(mechanism_rows) == 187, "RQ3 mechanism frame must contain 187 references")
    require(
        len({row["reference_id"] for row in mechanism_rows}) == 187,
        "RQ3 mechanism reference IDs are not unique",
    )
    require(
        sum(int(row["semantic_recovered"]) for row in mechanism_rows) == 36,
        "RQ3 mechanism recovery count changed",
    )
    mechanism_counts = Counter(row["rq1_mechanism_category"] for row in mechanism_rows)
    require(
        mechanism_counts
        == Counter(
            {
                "incomplete_change_coordination": 63,
                "dependency_error_or_resource_mismanagement": 55,
                "redundant_or_locally_inconsistent_construction": 38,
                "control_state_or_dataflow_miscomposition": 21,
                "interface_or_contract_mismatch": 10,
            }
        ),
        "RQ3 mechanism category counts changed",
    )

    from analyze_default_review import recovery
    current_refs, current_matches = recovery(reports / 'default_review')
    current_labels = read_csv(reports / 'default_review/human_decisions.csv')
    current_broad = [r for r in current_refs if truthy(r['validated_issue_reference']) and truthy(r['quality_broad_reference'])]
    current_primary = [r for r in current_broad if truthy(r['quality_primary_reference'])]
    require(len(current_labels) == 1106, 'Current default human-label count changed')
    require(sum((r['case_id'], r['reference_id']) in current_matches for r in current_primary) == 21,
            'Current default primary recovery must be 21/114')
    require(sum((r['case_id'], r['reference_id']) in current_matches for r in current_broad) == 37,
            'Current default broad recovery must be 37/187')
    return {
        "alerts": len(labels),
        "confirmed_issues": len(confirmed),
        "prs": len(eligible),
        "rq1_root_cause_clusters": len(clusters),
        "rq3_references": 114,
        "rq3_recovered": 21,
        "rq3_mechanism_references": len(mechanism_rows),
        "rq3_mechanism_recovered": 37,
        "rq3_author_reviewed": len(current_labels),
    }


def main() -> None:
    root = parse_args().root.resolve()
    file_n = verify_checksums(root)
    counts = verify_scientific_invariants(root)
    print(
        "Artifact verification passed: "
        f"files={file_n}, alerts={counts['alerts']}, "
        f"confirmed_issues={counts['confirmed_issues']}, prs={counts['prs']}, "
        f"rq1_clusters={counts['rq1_root_cause_clusters']}, "
        f"rq3={counts['rq3_recovered']}/{counts['rq3_references']}, "
        f"rq3_mechanisms={counts['rq3_mechanism_recovered']}/"
        f"{counts['rq3_mechanism_references']}, "
        f"rq3_author_reviewed={counts['rq3_author_reviewed']}"
    )


if __name__ == "__main__":
    main()
