# Reproducing the results and rerunning the experiment

This repository exposes three different operations. They are not
interchangeable, and only the third one reruns the PR selection and CodeQL experiment.

| Goal | Command | What it does | What it does not do |
|---|---|---|---|
| Check the downloaded package | `python scripts/verify_artifact.py` | Checks released file hashes and fixed result counts | Runs no analysis or experiment |
| Recompute the paper results | `python scripts/reproduce_analysis.py` | Re-runs RQ1--RQ3 statistical analysis and figure generation from the released, frozen tables | Does not download PRs, invoke CodeQL or a model, or repeat human review |
| Rerun PR acquisition and CodeQL analysis | `python scripts/run_codeql_experiment.py ...` | Rebuilds candidates from released metadata, downloads PRs, runs paired CodeQL and compares SARIF | Does not guarantee the historical successful-scan or alert counts |

`scripts/reproduce_analysis.py` is a post-release convenience wrapper. It was
not the command used to collect the study data. It simply invokes the final
analysis scripts in sequence so that artifact users do not need to copy several
long commands. The original study itself was executed in stages: PR selection,
paired CodeQL analysis, contextual validation, human review, and the RQ3 LLM
review experiment.

## 1. Environment

Run commands from the repository root with Python 3.11 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 2. Check that the released package is intact

```bash
python scripts/verify_artifact.py
```

This is a file-integrity check, not an experiment. It verifies every
inventoried SHA-256 hash and the headline invariants: 7,124 final alert
decisions, 2,322 confirmed issues, 5,404 PRs, 412 RQ1 mechanism clusters
covering all 775 confirmed AI Quality alerts, and 20/114 RQ3
Quality-reference recoveries. It also checks the sanitized CodeQL job
manifests, the complete 267-case RQ3 frame, and the author review of all 1,016
RQ3 finding--reference relation decisions.

## 3. Recompute the reported results from frozen data

This level starts from the released final alert decisions and PR-level table.
It corresponds only to the statistical-analysis and plotting stage at the end
of the study. It does not recreate any upstream observation or human judgment.

For a short installation test with reduced bootstrap and model draws:

```bash
python scripts/reproduce_analysis.py --quick
```

For the paper configuration:

```bash
python scripts/reproduce_analysis.py
```

Outputs are written to `outputs/reproduction/`:

| Output | Contents |
|---|---|
| `rq1-ai/` | AI-cohort task, language, change-size, category, location, severity, precision, rule, and concentration profiles |
| `rq1-human/` | Corresponding human-cohort descriptive profiles |
| `rq1-root-cause-compiled/` | Reconstructed 412-cluster partition and the unique mapping of all 775 AI Quality alerts |
| `rq1-root-causes/` | Mechanism-category and submechanism summaries |
| `rq1-root-cause-audit/` | Frozen 32-case boundary audit and consistency checks |
| `rq2-models/` | Repository-clustered GEE coefficients, diagnostics, standardized effects, and task-interaction test |
| `rq3-metrics/` | Raw-reference and human-confirmed semantic-recovery metrics; no new model calls |
| `validated-snapshot/` | Validation outcomes and strata rebuilt from all 7,124 alert rows and final labels |
| `raw-sensitivities/` | Raw-alert exclusions and changed-file/KLOC analyses |
| `rq2-design/` | Recomputed descriptive balance table |
| `insights/` | Concentration, predictive comparison, profile similarity, and category recovery |
| `robustness/` | Final-label RQ1/RQ2 exclusions and shared-repository diagnostics |
| `tables/` | Table 1--6 and S1--S28 numerical data bundles, with CSV and HTML views |
| `figures/` | Vector PDF versions of all statistical figures |
| `reproduction_manifest.json` | Exact commands, Python version, mode, and completion time |

The quick mode only checks that the released analysis code can run in the local
environment. Its reduced bootstrap and simulation counts are not the paper
configuration and its outputs must not be reported. Use the default command to
recompute the paper-configuration estimates.

The post-hoc robustness checks retain their original settings in both modes.
Use a new output directory for a repeat run. The table export compares full-run
results with the frozen statistical CSVs; it is not a typesetting or verbatim
LaTeX-cell test. Figures in the full reproduction command read its newly
computed outputs, whereas the standalone plotting command below reads frozen data.

## 4. Recompute one reported analysis separately

The paths below are relative to the artifact root.

### RQ1: issue characterization

```bash
python scripts/analysis/summarize_introduced_alerts.py \
  --alerts data/results/final_human_confirmed_issue_analysis_20260817_v1/validated_alerts.csv \
  --analysis-pr-level data/results/final_human_confirmed_issue_analysis_20260817_v1/analysis_pr_level.csv \
  --output-dir outputs/rq1-ai \
  --group ai \
  --bootstrap-replicates 2000 \
  --seed 20260623 \
  --status final
```

Replace `--group ai` with `--group human` for the human descriptive profile.

The complete RQ1 mechanism analysis can be rebuilt without publishing raw
repository source or review packets:

```bash
python scripts/analysis/compile_ai_quality_root_cause_annotations.py \
  --review-dir data/results/ai_quality_root_cause_review_20260831_v1 \
  --scope-prs data/results/ai_quality_root_cause_review_20260831_v1/positive_prs_public.csv \
  --alerts data/results/final_human_confirmed_issue_analysis_20260817_v1/validated_alerts.csv \
  --decisions config/study/root_cause_decision.json \
  --taxonomy config/study/ai_quality_root_cause_taxonomy.json \
  --output-dir outputs/rq1-root-cause-compiled

python scripts/analysis/summarize_ai_quality_root_causes.py \
  --compiled-dir outputs/rq1-root-cause-compiled \
  --output-dir outputs/rq1-root-causes \
  --scope-label "complete AI Quality analysis frame" \
  --frequency-estimation-allowed

python scripts/analysis/audit_ai_quality_root_cause_dataset.py \
  --compiled-dir outputs/rq1-root-cause-compiled \
  --taxonomy config/study/ai_quality_root_cause_taxonomy.json \
  --boundary-decisions config/study/ai_quality_root_cause_boundary_audit_v1.json \
  --output-dir outputs/rq1-root-cause-audit
```

These commands reproduce 412 clusters from 316 initial PR--Rule units and a
one-to-one mapping of all 775 confirmed AI Quality alerts.

### RQ2: AI--human comparison

```bash
python scripts/analysis/fit_rq2_models.py \
  --analysis-pr-level data/results/final_human_confirmed_issue_analysis_20260817_v1/analysis_pr_level.csv \
  --snapshot-manifest data/results/final_human_confirmed_issue_analysis_20260817_v1/snapshot_manifest.json \
  --design-weights data/results/rq2_design_unweighted_final_20260727_v3/design_weights.csv \
  --design-manifest data/results/rq2_design_unweighted_final_20260727_v3/design_manifest.json \
  --output-dir outputs/rq2-models \
  --draws 2000 \
  --seed 20260623
```

### RQ3: recovery of human-confirmed references

```bash
python scripts/analysis/recompute_public_rq3_metrics.py \
  --joined-references data/results/final_human_confirmed_rq3_20260817_v1/reference_adjudication_join_public.csv \
  --output-dir outputs/rq3-metrics \
  --bootstrap-draws 50000 \
  --seed 20260623
```

This command re-scores the frozen review/reference relations and makes no API
or model call. It reproduces 20 recoveries among 114 human-confirmed Quality
references. The released relation table records each same-root-cause decision,
its rationale, and whether the initial decision came from a deterministic rule
or LLM-assisted semantic adjudication. The separate
`data/results/rq3_semantic_human_review_v1/author_relation_review.csv` records
one author's manual confirmation of all 1,016 decisions. It deliberately keeps
the initial provenance unchanged (776 LLM-assisted and 240 deterministic),
while recording the author-confirmed final relations separately: 45
`same_issue`, 187 `related_distinct`, 544 `no_match`, and 240 `no_reference`.
This audit layer does not change the final RQ3 result of 20/114.

### Statistical figures

```bash
MPLCONFIGDIR=outputs/.matplotlib \
python scripts/analysis/plot_paper_figures.py \
  --report-root data/results \
  --output-dir outputs/figures
```

## 5. Rerun the PR selection and CodeQL experiment

This is the entry point corresponding to the repository-preparation and CodeQL
stage that produced the raw study measurements. Unlike
`reproduce_analysis.py`, it accesses external repositories and constructs new
before/head databases.

Re-running PR acquisition and paired CodeQL scans requires substantially more
resources:

- CodeQL CLI 2.23.2 and the matching query packs;
- Git and network access to the public repositories;
- a GitHub token in `GH_TOKEN`;
- the dependencies in `requirements-full.txt`;
- enough disk, memory, and time to build two databases per PR.

Install the additional dependencies and confirm the entry point:

```bash
python -m pip install -r requirements-full.txt
codeql version
python scripts/run_codeql_experiment.py --help
```

A bounded setup test (one PR per group, no downloads or scans) is:

```bash
python scripts/run_codeql_experiment.py \
  --output-dir outputs/codeql-smoke \
  --limit-per-group 1 --codeql /path/to/codeql
```

Inspect each group's `prs.csv` and `codeql_jobs.csv` under that directory.
Then set `GH_TOKEN` in the environment and add `--execute` to the same command
to download repositories, run CodeQL and compare SARIF. Start with one worker:
database construction can consume substantial disk space.

See [CODEQL_EXPERIMENT.md](CODEQL_EXPERIMENT.md) for the full run, input metadata, overlap policy,
and historical versus fresh-run counts. The default wrapper never scans code
without `--execute`. Use `--selection-only` when CodeQL is not installed.
Frozen analysis tables remain the inputs for checking exact paper statistics.

## 6. Inspect or repeat the validation and LLM-review stages

The repository includes the validation application, output schemas, prompts,
and RQ3 execution scripts for methodological inspection. The final human
decisions and semantic relations are already frozen in `data/results/`.

```bash
python scripts/manual_alert_review_app.py --help
python scripts/rq3/run_rq3_formal_reviews.py --help
```

These commands expose the same methodological components, but running `--help`
does not repeat the study. Human validation requires reviewer interaction, and
live LLM execution requires a separately supplied provider endpoint and API
key, incurs cost, and may not be bit-for-bit reproducible as hosted models
change. Neither operation is part of `reproduce_analysis.py`; the released
paper results use the frozen human decisions, model outputs, and semantic
relations.
