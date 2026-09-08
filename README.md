# Quality Issues in AI-Authored Pull Requests: A Repository-Scale Empirical Study

This repository is the public code-and-data artifact for an empirical study of
CodeQL-detectable Quality issues in AI-authored and human-authored pull
requests.  It contains the final analysis code, frozen derived data, human
validation decisions, model results, and scripts used to render the paper's
statistical figures.

## Authors

- Qihang Wan — SKLP, Institute of Computing Technology, Chinese Academy of
  Sciences; University of Chinese Academy of Sciences
- Jie Lu — SKLP, Institute of Computing Technology, Chinese Academy of Sciences
- Haofeng Li — SKLP, Institute of Computing Technology, Chinese Academy of Sciences
- Lian Li — SKLP, Institute of Computing Technology, Chinese Academy of
  Sciences; University of Chinese Academy of Sciences

## What is included

- `data/results/`: the final 7,124-alert human-reviewed frame, 2,322 confirmed
  issues, the 5,404-PR analysis table, the 412-cluster RQ1 mechanism analysis,
  RQ2 model outputs, and the complete 267-case RQ3 derived results, including
  both the 114-reference primary analysis and the 187-reference mechanism
  analysis;
- `data/manifests/`: sanitized selected-PR and before/head CodeQL job
  manifests for both cohorts;
- `scripts/codeql/`: the resumable before/after CodeQL pipeline;
- `scripts/analysis/`: final outcome construction and RQ1--RQ3 analyses;
- `scripts/rq3/`: the frozen LLM-review and semantic-matching workflow;
- `config/study/`: query taxonomy, prompts, schemas, and model specification;
- `docs/`: the analysis policy, validation codebook, and review protocols.

The manuscript source and submission files are maintained separately and are
not duplicated in this code-and-data repository. Statistical figures can be
regenerated under `outputs/` using the released scripts and frozen result data.

Intermediate experiments, archived scripts, logs, SARIF, CodeQL databases,
repository worktrees, caches, API credentials, and superseded reports are not
part of this repository.

## Choose what you want to reproduce

These commands serve different purposes:

| Goal | Entry point | Scope |
|---|---|---|
| Check the downloaded package | `python scripts/verify_artifact.py` | File hashes and fixed result counts only; no analysis or experiment |
| Recompute the paper analyses | `python scripts/reproduce_analysis.py` | RQ1--RQ3 statistics from frozen released data and rendering of the published figures; no GitHub, CodeQL, model, or human review |
| Rebuild candidates and rerun CodeQL | `python scripts/run_codeql_experiment.py ...` | Candidate selection from released metadata, followed by PR download, before/head CodeQL and differential alerts; see [CodeQL experiment instructions](docs/CODEQL_EXPERIMENT.md) |

These wrappers were added as public-artifact conveniences. They are not
the historical command sequence used to collect the study data.

To reproduce candidate selection without network access or CodeQL:

```bash
python -m pip install -r requirements-full.txt
python scripts/run_codeql_experiment.py --selection-only
```

This reconstructs the initial 3,377 AI and 2,450 human candidates from the
provided historical selection metadata. The [CodeQL experiment guide](docs/CODEQL_EXPERIMENT.md)
explains overlap exclusion, a small scan, and the full resumable run. Successful
scan and alert counts may differ across environments; frozen-data analysis is
the separate route for reproducing the paper's exact reported numbers.

### Check package integrity

The verifier uses only the Python standard library.

```bash
python scripts/verify_artifact.py
```

Expected headline invariants are 7,124 final alert decisions, 2,322 confirmed
issues (2,194 Quality and 128 Security), 5,404 analyzed PRs, 412 RQ1 root-cause
clusters covering all 775 AI Quality alerts, and 20/114 RQ3 Quality-reference
recoveries in the primary analysis and 36/187 in the secondary mechanism
analysis. The verifier also checks the author-confirmed audit of all 1,016
RQ3 semantic relations. Their initial provenance remains 776
`LLM_assistant` decisions and 240 `deterministic_rule` decisions. One author
then manually reviewed every relation. This RQ3 relation-review layer did not
use independent double annotation, and the release does not contain a
timestamped modification history.

### Recompute reported results from frozen data

After installing `requirements.txt`, run a reduced installation test:

```bash
python scripts/reproduce_analysis.py --quick
```

This wrapper starts from the released alert metadata, final decisions, and
raw PR-level table. It rebuilds validation summaries, RQ1--RQ3 analyses,
rule-exclusion checks, and numerical data for all 34 main/supplementary tables.
It renders the current Fig2--Fig5 from the newly computed results.
It does not download PRs, run
CodeQL, call a model, or repeat human review. Run it without `--quick` to use
the paper's bootstrap and model-draw settings. Open
`outputs/reproduction/tables/index.html` for the numbered table data (CSV and
HTML; not the journal's LaTeX layout). See `docs/TABLES.md` for the table map.
Use a new `--output-dir` for each run; existing post-hoc results are not overwritten.
See
`docs/RUN_EXPERIMENTS.md` for the original experimental stages, individual
analysis commands, and the resource-intensive CodeQL rerun procedure.

## Run model assessment, human validation, or a new RQ3 review

- [Alert assessment and human validation](docs/ALERT_ASSESSMENT.md): prepare
  batches, configure the model, review both retained/excluded queues, and export
  final human labels.
- [RQ3 reviewer experiment](docs/RQ3_REVIEW.md): prepare blinded code, test one
  PR, run the fixed paper cohort, and verify finding/reference relations.

These operations require repository context, human work and, for live model
calls, API access and a budget. They are separate from frozen-data reproduction.
The guides explicitly identify historical count checks and manual steps; they
do not claim that human validation or semantic adjudication is fully automated.

## Recreate the paper figures

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/analysis/plot_paper_figures.py \
  --report-root data/results \
  --output-dir outputs/figures --layout wrapped
```

## Refit the primary RQ2 model

```bash
python scripts/analysis/fit_rq2_models.py \
  --analysis-pr-level data/results/final_human_confirmed_issue_analysis_20260817_v1/analysis_pr_level.csv \
  --snapshot-manifest data/results/final_human_confirmed_issue_analysis_20260817_v1/snapshot_manifest.json \
  --design-weights data/results/rq2_design_unweighted_final_20260727_v3/design_weights.csv \
  --design-manifest data/results/rq2_design_unweighted_final_20260727_v3/design_manifest.json \
  --output-dir outputs/rq2_models \
  --draws 2000 \
  --seed 20260623
```

See `docs/REPRODUCIBILITY.md` for the reproduction levels and
`docs/DATA_DICTIONARY.md` for the released tables.

## Scope

The public data are derived measurements over public pull requests.  They do
not contain cloned repositories, complete source trees, CodeQL databases, or
raw model transcripts.  Re-running repository acquisition and CodeQL scanning
requires GitHub access, the CodeQL CLI, and substantial compute and storage.

## Citation and license

Citation metadata are provided in `CITATION.cff`. Software source code is
released under the MIT License. Original annotations, derived datasets,
tabular results, and documentation are released under CC BY 4.0. See
`LICENSE.md` and `NOTICE.md` for the precise scope and third-party attribution.
