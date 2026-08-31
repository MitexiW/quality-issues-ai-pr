#!/usr/bin/env python3
"""Independent, post-hoc supplementary analyses of frozen human-confirmed labels.

Never edits the paper, labels, taxonomy, cluster assignments, or primary results.
Run with the project virtualenv; output must be a new or empty directory.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any
import warnings

import numpy as np
import pandas as pd
import scipy
import statsmodels
import statsmodels.api as sm
from statsmodels.genmod.cov_struct import Exchangeable

try:
    from . import fit_rq2_models as primary
except ImportError:
    import fit_rq2_models as primary


ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "data/experiments/security-and-quality/study_stars500/reports"
UNUSED_RULES = ("js/unused-local-variable", "py/unused-import")
OUTCOME = "introduced_quality_any"
COUNT = "introduced_quality_alerts"


def pr_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row["group"]).strip().casefold(),
        str(row["repo_name"]).strip().casefold(),
        primary.normalize_pr_number(row["pr_number"]),
    )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")


def write_rows(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    fields = fields or list(dict.fromkeys(key for row in rows for key in row))
    if not fields:
        raise ValueError(f"Cannot write a schema-less table: {path}")
    primary.write_csv(path, fields, rows)


def confirmed_quality(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    seen = set()
    selected = []
    for row in rows:
        if not row["alert_id"] or row["alert_id"] in seen:
            raise ValueError("Missing or duplicate final alert ID")
        seen.add(row["alert_id"])
        if row["human_disposition"] != "confirmed_valid":
            raise ValueError("Input must contain final human-confirmed labels only")
        if primary.strict_boolean(row["is_quality_alert"], "is_quality_alert"):
            if row["issue_domain"].casefold() != "quality":
                raise ValueError("Conflicting Quality domain flags")
            selected.append(row)
    return selected


def rebuild_outcomes(frame: pd.DataFrame, alerts: list[dict[str, str]], excluded: set[str]) -> pd.DataFrame:
    """Keep the full supplied roster, including PRs with no remaining alerts."""
    records = frame.to_dict("records")
    keys = [pr_key(row) for row in records]
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate PRs in scenario roster")
    roster = set(keys)
    counts: Counter = Counter()
    for alert in alerts:
        key = pr_key(alert)
        if key not in roster:
            raise ValueError(f"Confirmed alert outside full study roster: {key}")
        if alert["rule_id"] not in excluded:
            counts[key] += 1
    result = frame.copy()
    result[COUNT] = [counts[key] for key in keys]
    result[OUTCOME] = (result[COUNT] > 0).astype(int)
    return result


def pooled_rule_ranking(alerts: list[dict[str, str]]) -> list[dict[str, Any]]:
    counts = Counter(row["rule_id"] for row in alerts)
    by_group = Counter((row["rule_id"], pr_key(row)[0]) for row in alerts)
    return [
        {"rank": i, "rule_id": rule, "alert_n": counts[rule],
         "ai_alert_n": by_group[rule, "ai"], "human_alert_n": by_group[rule, "human"],
         "exclude_top1": i == 1, "exclude_top5": i <= 5}
        for i, rule in enumerate(sorted(counts, key=lambda rule: (-counts[rule], rule)), 1)
    ]


def shared_repository_audit(frame: pd.DataFrame) -> list[dict[str, Any]]:
    rows = []
    for repo, subset in frame.groupby(frame["repo_name"].str.casefold(), sort=True):
        counts = subset["group"].value_counts()
        rows.append({"repo_name": repo, "ai_pr_n": int(counts.get("ai", 0)),
                     "human_pr_n": int(counts.get("human", 0)),
                     "shared": counts.get("ai", 0) > 0 and counts.get("human", 0) > 0})
    return rows


def validate_size_transform(analysis_rows: list[dict], design_rows: list[dict]) -> None:
    sources = {pr_key(row): row for row in analysis_rows
               if primary.strict_boolean(row["quality_gate_pass"], "quality_gate_pass")}
    for row in design_rows:
        source = sources[pr_key(row)]
        lines = sum(primary.strict_nonnegative_integer(source[field], field) for field in ("additions", "deletions"))
        if not np.isclose(float(row["changed_kloc"]), lines / 1000, rtol=0, atol=1e-10):
            raise ValueError("Design change size does not equal PR-wide additions + deletions")
        if not np.isclose(float(row["log1p_changed_kloc"]), np.log1p(lines / 1000), rtol=0, atol=1e-10):
            raise ValueError("Design change-size transformation differs from log1p(KLOC)")


def validate_clusters(clusters: list[dict[str, str]], links: list[dict[str, str]],
                      alerts: list[dict[str, str]], category_ids: set[str]) -> None:
    by_cluster = {row["root_cause_cluster_id"]: row for row in clusters}
    by_alert = {row["alert_id"]: row for row in alerts if pr_key(row)[0] == "ai"}
    if len(by_cluster) != len(clusters):
        raise ValueError("Duplicate cluster ID")
    linked = [row["alert_id"] for row in links]
    if len(set(linked)) != len(linked) or set(linked) != set(by_alert):
        raise ValueError("Root-cause links must cover every confirmed AI Quality alert exactly once")
    counts: Counter = Counter()
    rules = defaultdict(set)
    for link in links:
        cluster = by_cluster[link["root_cause_cluster_id"]]
        alert = by_alert[link["alert_id"]]
        for row in (cluster, link):
            if (row["repo_name"].casefold(), primary.normalize_pr_number(row["pr_number"])) != pr_key(alert)[1:]:
                raise ValueError("A root-cause cluster cannot span PRs")
        if link["rule_id"] != alert["rule_id"]:
            raise ValueError("Rule mismatch between final alert and cluster link")
        counts[link["root_cause_cluster_id"]] += 1
        rules[link["root_cause_cluster_id"]].add(link["rule_id"])
    for key, row in by_cluster.items():
        if counts[key] != int(row["alert_n"]) or len(rules[key]) != int(row["rule_n"]):
            raise ValueError(f"Cluster alert/rule counts do not reconcile: {key}")
        if row["root_cause_category"] not in category_ids:
            raise ValueError("Unfrozen root-cause category")


def crosswalk(clusters: list[dict[str, str]], links: list[dict[str, str]],
              dimension: str) -> list[dict[str, Any]]:
    by_cluster = {row["root_cause_cluster_id"]: row for row in clusters}
    cells = defaultdict(list)
    for link in links:
        cluster = by_cluster[link["root_cause_cluster_id"]]
        cells[link["rule_id"], cluster[dimension]].append(link)
    return [
        {"rule_id": rule, dimension: label,
         "cluster_n": len({row["root_cause_cluster_id"] for row in items}),
         "alert_n": len(items),
         "pr_n": len({(row["repo_name"].casefold(), row["pr_number"]) for row in items})}
        for (rule, label), items in sorted(cells.items())
    ]


def root_sensitivity(clusters: list[dict[str, str]], links: list[dict[str, str]],
                     categories: list[dict[str, Any]], excluded: set[str],
                     scenario: str, drop_touched: bool = False) -> tuple[list, list, list]:
    original = defaultdict(list)
    for link in links:
        original[link["root_cause_cluster_id"]].append(link)
    membership, partial = [], []
    for cluster in clusters:
        items = original[cluster["root_cause_cluster_id"]]
        remaining = [row for row in items if row["rule_id"] not in excluded]
        touched = len(remaining) < len(items)
        if drop_touched and touched:
            remaining = []
        row = {"scenario": scenario, "root_cause_cluster_id": cluster["root_cause_cluster_id"],
               "repo_name": cluster["repo_name"], "pr_number": cluster["pr_number"],
               "root_cause_category": cluster["root_cause_category"],
               "original_alert_n": len(items), "remaining_alert_n": len(remaining),
               "retained": bool(remaining), "partially_retained": bool(remaining) and touched,
               "remaining_rules": "|".join(sorted({x["rule_id"] for x in remaining})),
               "excluded_rules": "|".join(sorted({x["rule_id"] for x in items if x["rule_id"] in excluded}))}
        membership.append(row)
        if row["partially_retained"]:
            partial.append(row)
    retained = [row for row in membership if row["retained"]]
    summary = []
    for category in categories:
        items = [row for row in retained if row["root_cause_category"] == category["id"]]
        summary.append({"scenario": scenario, "root_cause_category": category["id"],
                        "category_label": category["label"], "cluster_n": len(items),
                        "alert_n": sum(row["remaining_alert_n"] for row in items),
                        "pr_n": len({(row["repo_name"].casefold(), row["pr_number"]) for row in items}),
                        "cluster_share": len(items) / len(retained) if retained else 0,
                        "total_cluster_n": len(retained),
                        "total_alert_n": sum(row["remaining_alert_n"] for row in retained)})
    return summary, membership, partial


def sample_profile(frame: pd.DataFrame, scenario: str) -> list[dict[str, Any]]:
    rows = []
    for dimension in ("all", "task_type", "repo_language"):
        groups = [("all", frame)] if dimension == "all" else frame.groupby(dimension, sort=True)
        for stratum, subset in groups:
            for group in ("ai", "human"):
                part = subset[subset["group"] == group]
                rows.append({"scenario": scenario, "dimension": dimension, "stratum": stratum,
                             "group": group, "pr_n": len(part), "positive_pr_n": int(part[OUTCOME].sum()),
                             "alert_n": int(part[COUNT].sum()), "repository_n": part["repo_name"].nunique(),
                             "positive_repository_n": part.loc[part[OUTCOME] > 0, "repo_name"].nunique()})
    return rows


def fit_scenario(frame: pd.DataFrame, scenario: str, draws: int, seed: int,
                 ctol: float = 1e-6, start_params: np.ndarray | None = None) -> tuple[Any, dict, list, list]:
    diagnostic = {"scenario": scenario, "pr_n": len(frame),
                  "repository_n": int(frame["repo_name"].nunique()),
                  "positive_pr_n": int(frame[OUTCOME].sum()), "ctol": ctol,
                  "initialization": "default" if start_params is None else "supplied",
                  "status": "pending"}
    zero_strata = [language for language, part in frame.groupby("repo_language")
                   if int(part[OUTCOME].sum()) == 0]
    diagnostic["zero_event_languages"] = "|".join(zero_strata)
    result = None
    effects, coefficients = [], []
    captured = []
    try:
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            model = sm.GEE.from_formula(primary.formula(OUTCOME), groups="repo_name", data=frame,
                                        family=sm.families.Binomial(), cov_struct=Exchangeable())
            result = model.fit(maxiter=500, ctol=ctol, start_params=start_params, cov_type="robust")
            params = np.asarray(result.params, dtype=float)
            covariance = np.asarray(result.cov_params(), dtype=float)
            finite = bool(np.isfinite(params).all() and np.isfinite(covariance).all())
            eigenvalues = np.linalg.eigvalsh((covariance + covariance.T) / 2) if finite else np.array([np.nan])
            dependence = float(np.asarray(result.cov_struct.dep_params))
            diagnostic.update({"converged": bool(result.converged), "finite_parameters_covariance": finite,
                               "minimum_covariance_eigenvalue": float(eigenvalues.min()),
                               "max_abs_coefficient": float(np.abs(params).max()),
                               "dependence_parameter": dependence,
                               "iterations": len(result.fit_history.get("params", [])),
                               "large_coefficients": "|".join(name for name, value in result.params.items() if abs(value) > 20)})
            if result.converged and np.isfinite(params).all():
                probabilities = []
                for ai in (1, 0):
                    counterfactual = frame.copy()
                    counterfactual["ai"] = ai
                    probabilities.append(float(primary.inverse_link(
                        "binary", primary.design_for_prediction(result, counterfactual) @ params).mean()))
                diagnostic["point_risk_difference"] = probabilities[0] - probabilities[1]
            coefficients = [{"scenario": scenario, "term": name, "estimate": float(value),
                             "robust_se": float(result.bse[name])} for name, value in result.params.items()]
            if not result.converged or not finite or not np.isfinite(dependence):
                diagnostic["status"] = "suppressed_invalid_fit"
            else:
                effects = [{"scenario": scenario, **row} for row in primary.standardized_effects(
                    result, frame, "binary", "quality", "supplementary", draws, np.random.default_rng(seed))]
                diagnostic["status"] = "boundary_caution" if zero_strata else "ok"
    except (ValueError, RuntimeError, np.linalg.LinAlgError, FloatingPointError) as error:
        diagnostic.update({"status": "suppressed_fit_or_inference_error", "error": f"{type(error).__name__}: {error}"})
        effects = []
    diagnostic["warnings"] = " | ".join(dict.fromkeys(str(item.message) for item in captured))
    return result, diagnostic, effects, coefficients


def numerical_assessment(rows: list[dict]) -> dict:
    failures = [row["check"] for row in rows if row["status"].startswith("suppressed")]
    points = [row["point_risk_difference"] for row in rows if "point_risk_difference" in row]
    return {"scenario": "shared_repositories", "check_n": len(rows), "failed_checks": failures,
            "status": "inference_not_validated" if failures else "boundary_caution",
            "supports_robustness_claim": False,
            "point_estimate_min": min(points) if points else None,
            "point_estimate_max": max(points) if points else None,
            "reason": ("All-zero Go stratum; stricter fits produced invalid robust covariance. "
                       "Do not promote the default-fit CI to validated robustness evidence." if failures else
                       "All-zero Go stratum remains a nonregular coefficient-inference limitation despite successful numerical checks.")}


def compare_baseline(effects: list[dict], reference: list[dict]) -> dict:
    observed = {(row["task_type"], row["metric"]): row for row in effects}
    expected = {(row["task_type"], row["metric"]): row for row in reference
                if row["family"] == "quality" and row["model"] == "binary"}
    if observed.keys() != expected.keys():
        raise ValueError("Baseline standardized-effect rows do not match primary artifact")
    differences = [abs(float(observed[key][field]) - float(expected[key][field]))
                   for key in expected for field in ("estimate", "ci_low", "ci_high")]
    maximum = max(differences)
    if maximum > 1e-8:
        raise ValueError(f"Baseline reproduction failed: maximum absolute difference {maximum}")
    return {"passed": True, "checked_rows": len(expected), "checked_numbers": len(differences),
            "maximum_absolute_difference": maximum, "tolerance": 1e-8}


def case_evidence(root_dir: Path, clusters: list[dict], inputs: dict[str, Path]) -> list[dict]:
    """Export evidence already present in frozen packets, not new root-cause assignments."""
    selections = {
        "base64-conversion-residue": ("3rdIteration/btcrecover", "599", "btcrecover/addressset.py",
                                      ((24, 24), (53, 57)), ((24, 24), (50, 54))),
        "duplicate-shamir-import-form": ("3rdIteration/btcrecover", "611", "btcrecover/btcrseed.py",
                                        ((116, 124),), ((119, 125),)),
        "removed-modified-files-type-residue": ("patched-codes/patchwork", "1192", "patchwork/steps/FixIssue/typed.py",
                                               ((1, 1), (36, 39)), ((1, 1), (52, 55))),
        "unintegrated-difflib-import": ("patched-codes/patchwork", "1192", "patchwork/steps/FixIssue/FixIssue.py",
                                       ((1, 5),), ((1, 5), (174, 179))),
    }
    rows = []
    for key, (repo, number, file, before_ranges, head_ranges) in selections.items():
        cluster = next(row for row in clusters if row["cluster_key_within_pr"] == key
                       and row["repo_name"] == repo and row["pr_number"] == number)
        slug = repo.replace("/", "_")
        packet_path = root_dir / "review_packets" / f"{slug}__pr-{number}.json"
        packet = json.loads(packet_path.read_text())
        inputs[f"case_packet_{slug}_{number}"] = packet_path
        evidence = next(row for row in packet["relevant_file_evidence"] if row["file_path"] == file)
        if packet["source_status"] != "available" or evidence["patch_status"] != "complete":
            raise ValueError(f"Representative case lacks complete evidence: {key}")
        row = {**cluster, "rule_id": "py/unused-import", "file_path": file,
               "packet_path": str(packet_path.relative_to(ROOT)), "base_sha": packet["base_sha"],
               "head_sha": packet["head_sha"], "patch": evidence["patch"]}
        for revision, ranges in (("before", before_ranges), ("head", head_ranges)):
            suffix = "before" if revision == "before" else "after"
            path = root_dir.parents[1] / "ai/repos" / slug / f"{slug}__pr-{number}__{suffix}" / file
            lines = path.read_text().splitlines()
            row[f"{revision}_excerpts"] = [{"start_line": low, "end_line": high,
                                           "text": "\n".join(lines[low - 1:high])} for low, high in ranges]
            row[f"{revision}_source_path"] = str(path.relative_to(ROOT))
            inputs[f"case_source_{key}_{revision}"] = path
        rows.append(row)
    return rows


def make_report(out: Path, roots: list[dict], heterogeneity: list[dict],
                profiles: list[dict], effects: list[dict], diagnostics: list[dict],
                stability: list[dict], ranking: list[dict], reproduction: dict,
                shared_assessment: dict) -> None:
    lines = ["# Final-label supplementary analyses", "",
             "Post-hoc exploratory analyses; no manuscript, primary outcome, root-cause label, or frozen result was changed.", "",
             "## Root-cause explanatory increment", "",
             f"Of {len(heterogeneity)} CodeQL rules, {sum(row['category_n'] > 1 for row in heterogeneity)} span multiple primary categories and "
             f"{sum(row['mechanism_n'] > 1 for row in heterogeneity)} span multiple finer mechanisms. "
             "Crosswalk rows count unique clusters within each cell; their sum is not a count of independent clusters across rules.", "",
             "| Filter | Remaining alerts | Remaining clusters | Incomplete coordination |",
             "|---|---:|---:|---:|"]
    for row in roots:
        if row["root_cause_category"] == "incomplete_change_coordination":
            lines.append(f"| {row['scenario']} | {row['total_alert_n']} | {row['total_cluster_n']} | {row['cluster_n']} ({row['cluster_share']:.2%}) |")
    lines += ["", "The frozen five categories and cluster assignments are retained. In the main filters, a cross-rule cluster remains if any nonexcluded alert remains. "
              "The drop-touched row is an auxiliary boundary check, not the main filtering convention.", "",
              "The full-set dominance is sensitive to the two named unused rules. These results do not support treating the full-set category distribution as detector-independent.", "",
              "Representative same-rule cases and exact source excerpts are in `representative_cases.json`; the qualitative assignments come from the existing frozen codebook and coding, not from this script.", "",
              "## RQ2: final-human-label robustness", "",
              "The Top 1 and Top 5 exclusions are selected by pooled AI + human final-confirmed Quality alert counts, with lexical rule-ID tie breaking:", ""]
    lines += [f"{row['rank']}. `{row['rule_id']}`: {row['alert_n']} ({row['ai_alert_n']} AI; {row['human_alert_n']} human)." for row in ranking[:5]]
    lines += ["", "Rule exclusions retain the full PR roster and rebuild the binary outcome. Shared repositories are selected by the presence of both authorship groups, not outcomes. "
              "The shared analysis standardizes over its own subset and is not a within-repository fixed-effect estimate.", "",
              "Model: logistic GEE, exchangeable repository correlation, robust sandwich covariance, unit weights.", "",
              "```text", primary.formula(OUTCOME), "```", "",
              "Size = log1p((PR-wide GitHub additions + deletions)/1000). Each fit is standardized over its own pooled PR population. "
              "Intervals use the unchanged primary helper, 2,000 paired coefficient draws (seed 20260623), and percentile limits. No multiplicity-adjusted confirmatory claims are made.", "",
              "| Analysis | AI positive / PRs | Human positive / PRs | Adjusted AI − human, pp (95% CI) | Diagnostic |",
              "|---|---:|---:|---:|---|"]
    for diagnostic in diagnostics:
        scenario = diagnostic["scenario"]
        parts = {row["group"]: row for row in profiles if row["scenario"] == scenario and row["dimension"] == "all"}
        rd = next((row for row in effects if row["scenario"] == scenario and row["task_type"] == "all" and row["metric"] == "risk_difference"), None)
        formatted = f"{100 * rd['estimate']:.2f} ({100 * rd['ci_low']:.2f}, {100 * rd['ci_high']:.2f})" if rd else "suppressed"
        status = diagnostic["status"]
        if scenario == "shared_repositories" and shared_assessment["status"] == "inference_not_validated":
            formatted = f"{100 * rd['estimate']:.2f}; CI not validated" if rd else "suppressed"
            status = shared_assessment["status"]
        lines.append(f"| {scenario} | {parts['ai']['positive_pr_n']}/{parts['ai']['pr_n']} | "
                     f"{parts['human']['positive_pr_n']}/{parts['human']['pr_n']} | {formatted} | {status} |")
    lines += ["", f"Baseline reproduction: {reproduction['checked_numbers']} numbers matched within {reproduction['maximum_absolute_difference']:.3g} (tolerance 1e-8).", "",
              "The shared subset has an all-zero Go outcome stratum. Numerical convergence alone does not establish regular coefficient inference; its Go coefficient is a boundary diagnostic, not an interpretable finite log-odds estimate. "
              "No Go PRs were silently removed. Tightening the convergence tolerance produced non-positive-semidefinite robust covariance in two checks. "
              "The default-fit interval is retained below as a diagnostic only, NOT as validated robustness evidence. All numerical checks, including failed fits, are retained below.", "",
              "| Shared-repository numerical check | Status | Go coefficient | Overall RD, pp | 95% CI, pp |",
              "|---|---|---:|---:|---:|"]
    for row in stability:
        rd = row.get("risk_difference")
        point = row.get("point_risk_difference")
        lines.append(f"| {row['check']} | {row['status']} | {row.get('go_coefficient', '')} | "
                     + (f"{100 * point:.6f} | " if point is not None else "unavailable | ")
                     + (f"{100 * row['ci_low']:.4f}, {100 * row['ci_high']:.4f} |" if rd is not None else "suppressed |"))
    lines += ["", "A small estimate or an interval including zero is not evidence of equivalence or causality. "
              "Rule-filtered analyses change the outcome; restricting repositories also changes the target population. "
              "Stable point estimates under numerical checks do not remove the shared subset's zero-event-stratum limitation.", "",
              "## Artifacts", "",
              "`analysis_manifest.json` records the protocol, input/output hashes, package versions and unchanged manuscript hashes. "
              "CSV files contain full category distributions, crosswalks, partial-cluster membership, PR outcomes, sample profiles, coefficients, standardized effects, and fit diagnostics.", ""]
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports-root", type=Path, default=REPORTS)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--case-evidence", type=Path,
                        help="Released frozen source excerpts; avoids unpublished review packets")
    args = parser.parse_args()
    out = args.output_dir.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError("Use a new or empty output directory; existing results are never overwritten")
    reports = args.reports_root.resolve()
    frozen = reports / "final_human_confirmed_issue_analysis_20260817_v1"
    design = reports / "rq2_design_unweighted_final_20260727_v3"
    root_dir = reports / "ai_quality_root_cause_review_20260831_v1"
    inputs = {"analysis": frozen / "analysis_pr_level.csv", "alerts": frozen / "validated_alerts.csv",
              "snapshot_manifest": frozen / "snapshot_manifest.json", "design": design / "design_weights.csv",
              "design_manifest": design / "design_manifest.json",
              "clusters": root_dir / "full_compiled_v1/root_cause_clusters.csv",
              "links": root_dir / "full_compiled_v1/alert_cluster_links.csv",
              "existing_crosswalk": root_dir / "full_audit_v1/rule_category_crosstab.csv",
              "taxonomy": ROOT / "config/study/ai_quality_root_cause_taxonomy.json",
              "decisions": ROOT / "config/study/root_cause_decision.json",
              "reference_effects": reports / "final_human_confirmed_rq2_models_20260817_v1/standardized_effects.csv",
              "reference_manifest": reports / "final_human_confirmed_rq2_models_20260817_v1/model_manifest.json",
              "primary_script": Path(primary.__file__).resolve(), "script": Path(__file__).resolve()}
    paper_files = sorted((ROOT / "paper/overleaf").glob("*"))
    paper_hashes = {str(path.relative_to(ROOT)): digest(path) for path in paper_files if path.is_file()}
    hashes = {name: digest(path) for name, path in inputs.items()}
    primary.validate_manifests(json.loads(inputs["snapshot_manifest"].read_text()), json.loads(inputs["design_manifest"].read_text()))
    analysis_rows = primary.read_csv(inputs["analysis"])[1]
    design_rows = primary.read_csv(inputs["design"])[1]
    frame = primary.join_inputs(analysis_rows, design_rows)
    validate_size_transform(analysis_rows, design_rows)
    alerts = confirmed_quality(primary.read_csv(inputs["alerts"])[1])
    baseline = rebuild_outcomes(frame, alerts, set())
    if not baseline[[OUTCOME, COUNT]].equals(frame[[OUTCOME, COUNT]]):
        raise ValueError("Rebuilt final-alert outcomes differ from primary frozen snapshot")
    ranking = pooled_rule_ranking(alerts)
    shared_audit = shared_repository_audit(baseline)
    shared = {row["repo_name"] for row in shared_audit if row["shared"]}
    clusters = primary.read_csv(inputs["clusters"])[1]
    links = primary.read_csv(inputs["links"])[1]
    categories = json.loads(inputs["taxonomy"].read_text())["root_cause_categories"]
    validate_clusters(clusters, links, alerts, {row["id"] for row in categories})
    category_crosswalk = crosswalk(clusters, links, "root_cause_category")
    existing = primary.read_csv(inputs["existing_crosswalk"])[1]
    if [{key: str(value) for key, value in row.items()} for row in category_crosswalk] != existing:
        raise ValueError("Recomputed rule/category crosswalk differs from frozen audit")
    mechanism_crosswalk = crosswalk(clusters, links, "mechanism_subcategory")
    heterogeneity = []
    for rule in sorted({row["rule_id"] for row in links}):
        items = [row for row in links if row["rule_id"] == rule]
        heterogeneity.append({"rule_id": rule, "alert_n": len(items),
                              "cluster_n": len({row["root_cause_cluster_id"] for row in items}),
                              "category_n": sum(row["rule_id"] == rule for row in category_crosswalk),
                              "mechanism_n": sum(row["rule_id"] == rule for row in mechanism_crosswalk)})
    root_summaries, memberships, partials = [], [], []
    for scenario, excluded, drop_touched in (
        ("baseline", set(), False), ("exclude_js_unused_local", {UNUSED_RULES[0]}, False),
        ("exclude_two_unused_rules", set(UNUSED_RULES), False),
        ("exclude_two_unused_drop_touched_auxiliary", set(UNUSED_RULES), True),
    ):
        summary, membership, partial = root_sensitivity(clusters, links, categories, excluded, scenario, drop_touched)
        root_summaries.extend(summary)
        memberships.extend(membership)
        partials.extend(partial)
    if args.case_evidence:
        cases = json.loads(args.case_evidence.read_text())
        inputs['released_case_evidence'] = args.case_evidence
    else:
        cases = case_evidence(root_dir, clusters, inputs)
    hashes.update({name: digest(path) for name, path in inputs.items() if name not in hashes})
    # Recorded before any new model results; these are post-hoc, not preregistered.
    protocol = {"status": "post_hoc_exploratory", "draws": 2000, "seed": 20260623,
                "formula": primary.formula(OUTCOME), "weights": "unit",
                "covariance": "robust sandwich", "correlation": "exchangeable; repository clusters",
                "change_size": "log1p((PR-wide additions + deletions)/1000), unchanged design covariate",
                "root_filters": [[], [UNUSED_RULES[0]], list(UNUSED_RULES)],
                "cluster_retention": "any nonexcluded alert; frozen assignments; no reclustering",
                "auxiliary_cluster_retention": "drop every cluster touched by either named unused rule",
                "top_rule_selection": "pooled final-confirmed Quality alert counts; lexical rule-ID tie break",
                "rq2_exclusions": {"exclude_top1": [ranking[0]["rule_id"]], "exclude_top5": [row["rule_id"] for row in ranking[:5]]},
                "shared_selection": "repository contains >=1 analyzable AI PR and >=1 human PR; outcome-blind",
                "standardization": "same pooled PR population as each scenario's fit; paired coefficient draws",
                "shared_numerical_checks": ["default ctol=1e-6", "default ctol=1e-8", "default ctol=1e-10",
                                             "baseline params with Go=-10, ctol=1e-8", "baseline params with Go=-20, ctol=1e-8"],
                "inference_policy": "retain failures, suppress invalid fits/covariances; flag zero-event language strata; no silent removal; shared CIs are not validated if numerical checks fail",
                "scope": "binary Quality outcome only; no manuscript edits; no label/category changes"}
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "analysis_protocol.json", protocol)
    write_rows(out / "pooled_rule_ranking.csv", ranking)
    write_rows(out / "shared_repository_eligibility.csv", shared_audit)
    write_rows(out / "rule_category_crosstab.csv", category_crosswalk)
    write_rows(out / "rule_mechanism_crosstab.csv", mechanism_crosswalk)
    write_rows(out / "rule_heterogeneity.csv", heterogeneity)
    write_rows(out / "root_cause_filter_summary.csv", root_summaries)
    write_rows(out / "root_cause_filter_membership.csv", memberships)
    write_rows(out / "partially_retained_clusters.csv", partials)
    write_json(out / "representative_cases.json", cases)
    scenarios = {"baseline": baseline,
                 "exclude_top1": rebuild_outcomes(frame, alerts, {ranking[0]["rule_id"]}),
                 "exclude_top5": rebuild_outcomes(frame, alerts, {row["rule_id"] for row in ranking[:5]}),
                 "shared_repositories": baseline[baseline["repo_name"].str.casefold().isin(shared)].copy()}
    profiles, effects, diagnostics, coefficients, rosters = [], [], [], [], []
    results = {}
    for scenario, part in scenarios.items():
        print(f"Fitting {scenario}: {len(part)} PRs; {part[OUTCOME].sum()} positive", flush=True)
        profiles.extend(sample_profile(part, scenario))
        rosters.extend({"scenario": scenario, **row} for row in part.to_dict("records"))
        result, diagnostic, fitted_effects, fitted_coefficients = fit_scenario(part, scenario, 2000, 20260623)
        results[scenario] = result
        effects.extend(fitted_effects)
        coefficients.extend(fitted_coefficients)
        diagnostics.append(diagnostic)
        print(json.dumps(diagnostic), flush=True)
        for row in fitted_effects:
            if row["task_type"] == "all" and row["metric"] == "risk_difference":
                print(json.dumps(row), flush=True)
    reproduction = compare_baseline([row for row in effects if row["scenario"] == "baseline"], primary.read_csv(inputs["reference_effects"])[1])
    stability, stability_effects, stability_coefficients = [], [], []
    part = scenarios["shared_repositories"]
    for label, tolerance, go_start in (("default_1e-6", 1e-6, None), ("default_1e-8", 1e-8, None),
                                        ("default_1e-10", 1e-10, None), ("start_Go_minus10", 1e-8, -10),
                                        ("start_Go_minus20", 1e-8, -20)):
        print(f"Shared-repository numerical check: {label}", flush=True)
        if label == "default_1e-6":
            result = results["shared_repositories"]
            diagnostic = next(row for row in diagnostics if row["scenario"] == "shared_repositories")
            fitted_effects = [row for row in effects if row["scenario"] == "shared_repositories"]
            fitted_coefficients = [row for row in coefficients if row["scenario"] == "shared_repositories"]
        else:
            start = None
            if go_start is not None and results["shared_repositories"] is not None:
                start = results["shared_repositories"].params.copy()
                start["C(repo_language)[T.Go]"] = go_start
                start = np.asarray(start, dtype=float)
            result, diagnostic, fitted_effects, fitted_coefficients = fit_scenario(part, label, 2000, 20260623, tolerance, start)
        row = {"check": label, **diagnostic}
        if result is not None:
            row["go_coefficient"] = float(result.params.get("C(repo_language)[T.Go]", np.nan))
        rd = next((x for x in fitted_effects if x["task_type"] == "all" and x["metric"] == "risk_difference"), None)
        if rd:
            row.update({"risk_difference": rd["estimate"], "ci_low": rd["ci_low"], "ci_high": rd["ci_high"]})
        stability.append(row)
        stability_effects.extend({"check": label, **x} for x in fitted_effects)
        stability_coefficients.extend({"check": label, **x} for x in fitted_coefficients)
        print(json.dumps(row), flush=True)
    shared_assessment = numerical_assessment(stability)
    for name, rows in (("scenario_pr_outcomes", rosters), ("sample_profiles", profiles), ("standardized_effects", effects),
                       ("model_diagnostics", diagnostics), ("model_coefficients", coefficients),
                       ("shared_numerical_stability", stability), ("shared_stability_effects", stability_effects),
                       ("shared_stability_coefficients", stability_coefficients)):
        write_rows(out / f"{name}.csv", rows)
    write_json(out / "baseline_reproduction.json", reproduction)
    write_json(out / "shared_inference_assessment.json", shared_assessment)
    make_report(out, root_summaries, heterogeneity, profiles, effects, diagnostics, stability, ranking, reproduction, shared_assessment)
    if any(digest(path) != hashes[name] for name, path in inputs.items()):
        raise RuntimeError("An analysis input changed during execution")
    if any(digest(ROOT / name) != value for name, value in paper_hashes.items()):
        raise RuntimeError("A manuscript file changed during execution")
    manifest = {"generated_at": datetime.now(timezone.utc).isoformat(), "status": "completed",
                "protocol": protocol, "baseline_reproduction": reproduction, "shared_inference_assessment": shared_assessment,
                "inputs": {name: {"path": str(path), "sha256": hashes[name]} for name, path in inputs.items()},
                "paper_unchanged": True, "paper_file_sha256": paper_hashes,
                "packages": {"python": sys.version, "numpy": np.__version__, "pandas": pd.__version__,
                             "scipy": scipy.__version__, "statsmodels": statsmodels.__version__},
                "outputs_sha256": {path.name: digest(path) for path in sorted(out.iterdir()) if path.is_file()}}
    write_json(out / "analysis_manifest.json", manifest)
    print(f"Completed: {out / 'report.md'}", flush=True)


if __name__ == "__main__":
    main()
