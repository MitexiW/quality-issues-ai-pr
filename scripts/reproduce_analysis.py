#!/usr/bin/env python3
"""Recompute released RQ1--RQ3 results from frozen data.

This post-release convenience wrapper does not rerun PR acquisition, CodeQL,
human validation, or live model review.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve()
ROOT = HERE.parents[2] if HERE.parent.name == "replication" else HERE.parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/reproduction"))
    parser.add_argument(
        "--quick",
        action="store_true",
        help="use fewer bootstrap/model draws for an installation smoke test",
    )
    return parser.parse_args()


def run(command: list[str], root: Path, env: dict[str, str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=root, env=env, check=True)


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    output = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    mpl = output / ".matplotlib"
    mpl.mkdir(exist_ok=True)
    env = dict(os.environ)
    env["MPLCONFIGDIR"] = str(mpl)
    python = sys.executable
    reports = root / "data/results"
    analysis = output / "validated-snapshot"
    rq1_bootstrap = "100" if args.quick else "2000"
    rq2_draws = "200" if args.quick else "2000"
    rq3_draws = "1000" if args.quick else "50000"
    root_cause = reports / "ai_quality_root_cause_review_20260831_v1"
    root_cause_compiled = output / "rq1-root-cause-compiled"
    commands = [
        [python, "scripts/verify_artifact.py"],
        [python, "scripts/analyze_default_review.py",
         "--results", str(reports / "default_review"),
         "--output", str(output / "rq3-default")],
        [python, "scripts/analyze_native_skill_recovery.py",
         "--results", str(reports / "native_skill_review"),
         "--output", str(output / "rq3-guided")],
        [python, "scripts/analysis/build_validated_issue_snapshot.py",
         "--raw-snapshot-dir", str(reports / "rq_analysis_final_20260727_v3"),
         "--adjudication-dir", str(root / "data/inputs/alert_assessment"),
         "--human-labels", str(reports / "final_human_consensus_20260817_v1/final_alert_labels.csv"),
         "--derived-snapshot-id", "final_human_confirmed_issue_analysis_20260817_v1",
         "--output-dir", str(analysis)],
        [python, "scripts/run_alert_sensitivities.py",
         "--analysis-pr-level", str(reports / "rq_analysis_final_20260727_v3/analysis_pr_level.csv"),
         "--ai-alerts", str(root / "data/inputs/raw_alerts/ai.csv"),
         "--human-alerts", str(root / "data/inputs/raw_alerts/human.csv"),
         "--pr-files", str(root / "data/inputs/changed_files.csv"),
         "--output-dir", str(output / "raw-sensitivities")],
        [python, "scripts/analysis/prepare_rq2_design.py",
         "--analysis-pr-level", str(analysis / "analysis_pr_level.csv"),
         "--snapshot-manifest", str(analysis / "snapshot_manifest.json"),
         "--output-dir", str(output / "rq2-design")],
        [
            python, "scripts/analysis/summarize_introduced_alerts.py",
            "--alerts", str(analysis / "validated_alerts.csv"),
            "--analysis-pr-level", str(analysis / "analysis_pr_level.csv"),
            "--output-dir", str(output / "rq1-ai"), "--group", "ai",
            "--bootstrap-replicates", rq1_bootstrap, "--seed", "20260623",
            "--status", "final",
        ],
        [
            python, "scripts/analysis/compile_ai_quality_root_cause_annotations.py",
            "--review-dir", str(root_cause),
            "--scope-prs", str(root_cause / "positive_prs_public.csv"),
            "--alerts", str(analysis / "validated_alerts.csv"),
            "--decisions", str(root / "config/study/root_cause_decision.json"),
            "--taxonomy", str(root / "config/study/ai_quality_root_cause_taxonomy.json"),
            "--output-dir", str(root_cause_compiled),
        ],
        [
            python, "scripts/analysis/summarize_ai_quality_root_causes.py",
            "--compiled-dir", str(root_cause_compiled),
            "--output-dir", str(output / "rq1-root-causes"),
            "--scope-label", "complete AI Quality analysis frame",
            "--frequency-estimation-allowed",
        ],
        [
            python, "scripts/analysis/audit_ai_quality_root_cause_dataset.py",
            "--compiled-dir", str(root_cause_compiled),
            "--taxonomy", str(root / "config/study/ai_quality_root_cause_taxonomy.json"),
            "--boundary-decisions", str(root / "config/study/ai_quality_root_cause_boundary_audit_v1.json"),
            "--output-dir", str(output / "rq1-root-cause-audit"),
        ],
        [
            python, "scripts/analysis/summarize_introduced_alerts.py",
            "--alerts", str(analysis / "validated_alerts.csv"),
            "--analysis-pr-level", str(analysis / "analysis_pr_level.csv"),
            "--output-dir", str(output / "rq1-human"), "--group", "human",
            "--bootstrap-replicates", rq1_bootstrap, "--seed", "20260623",
            "--status", "final",
        ],
        [
            python, "scripts/analysis/fit_rq2_models.py",
            "--analysis-pr-level", str(analysis / "analysis_pr_level.csv"),
            "--snapshot-manifest", str(analysis / "snapshot_manifest.json"),
            "--design-weights", str(reports / "rq2_design_unweighted_final_20260727_v3/design_weights.csv"),
            "--design-manifest", str(reports / "rq2_design_unweighted_final_20260727_v3/design_manifest.json"),
            "--output-dir", str(output / "rq2-models"), "--draws", rq2_draws,
            "--seed", "20260623",
        ],
        [
            python, "scripts/analysis/recompute_public_rq3_metrics.py",
            "--joined-references", str(output / "rq3-default/reference_inputs.csv"),
            "--output-dir", str(output / "rq3-metrics"),
            "--bootstrap-draws", rq3_draws, "--seed", "20260623",
        ],
        [
            python, "scripts/analysis/map_all_rq3_references_to_rq1_mechanisms.py",
            "--references", str(output / "rq3-default/reference_inputs.csv"),
            "--strict-mapping", str(reports / "rq3_reference_mechanism_mapping_20260901_v1/reference_mechanism_mapping.csv"),
            "--strict-manifest", str(reports / "rq3_reference_mechanism_mapping_20260901_v1/manifest.json"),
            "--alert-links", str(root_cause / "full_compiled_v1/alert_cluster_links.csv"),
            "--clusters", str(root_cause / "full_compiled_v1/root_cause_clusters.csv"),
            "--output-dir", str(output / "rq3-mechanisms"),
        ],
        [python, "scripts/analysis/analyze_paper_insights.py",
         "--analysis-pr-level", str(analysis / "analysis_pr_level.csv"),
         "--ai-alerts", str(analysis / "validated_alerts.csv"),
         "--human-alerts", str(analysis / "validated_alerts.csv"),
         "--rq3-reference-recovery", str(output / "rq3-default/reference_inputs.csv"),
         "--rq3-finding-relations", str(reports / "rq3_semantic_results_20260729_v1/semantic_finding_relations_public.csv"),
         "--rq3-summary", str(reports / "rq3_semantic_results_20260729_v1/summary.json"),
         "--bootstrap-draws", rq1_bootstrap, "--output-dir", str(output / "insights")],
        [python, "scripts/analysis/analyze_final_label_robustness.py",
         "--reports-root", str(reports), "--output-dir", str(output / "robustness"),
         "--case-evidence", str(reports / "final_human_confirmed_supplementary_robustness_20260907_v2/representative_cases.json")],
    ]
    for command in commands:
        run(command, root, env)
    # Plot only newly computed numerical results, using the historical directory
    # names expected by the plotting script. No frozen result is copied here.
    figure_inputs = output / "figure-inputs"
    for source, target in [
        ("rq1-ai", "final_human_confirmed_rq1_ai_profile_20260820_v2"),
        ("rq2-models", "final_human_confirmed_rq2_models_20260817_v1"),
        ("rq3-metrics", "final_human_confirmed_rq3_20260817_v1"),
    ]:
        shutil.copytree(output / source, figure_inputs / target, dirs_exist_ok=True)
    command = [python, "scripts/analysis/export_paper_tables.py", "--results", str(output),
               "--root", str(root)]
    if args.quick:
        command.append("--quick")
    run(command, root, env)
    commands.append(command)
    command = [python, "scripts/analysis/plot_paper_figures.py",
               "--report-root", str(figure_inputs), "--output-dir", str(output / "figures"),
               "--layout", "wrapped"]
    run(command, root, env)
    commands.append(command)
    manifest = {
        "status": "completed",
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "quick": args.quick,
        "python": sys.version,
        "commands": commands,
        "output_dir": str(output),
    }
    (output / "reproduction_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Reproduction complete: {output}")


if __name__ == "__main__":
    main()
