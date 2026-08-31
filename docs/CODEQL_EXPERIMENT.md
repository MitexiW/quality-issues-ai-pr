# Rerunning candidate selection and paired CodeQL

This path reruns the PR selection and CodeQL experiment. It is separate from
`scripts/reproduce_analysis.py`, which recomputes the paper's reported numbers
from frozen observations and human labels.

## 1. Rebuild the candidate pool (offline)

Install `requirements-full.txt`. The supplied `data/inputs/aidev_selection/`
contains the selection-relevant columns of all five cached AIDev tables:
repository, AI/Human PRs, and AI/Human task labels. It is not a preselected PR
list. PR bodies/titles and free-text task explanations are blanked; no selection
field is removed. The source is the historical local AIDev cache, not the
current remote dataset. An immutable remote dataset revision was not recorded,
so the provided metadata is the reproducible input for this selection.

```bash
python scripts/run_codeql_experiment.py --output-dir outputs/codeql_experiment --selection-only
```

This command only filters candidates. It needs no CodeQL installation and
does not contact GitHub or call a model. It produces:

- `ai_candidate_prs.csv`: 3,377 initial AI candidates;
- `human_candidate_prs.csv`: 2,450 initial human candidates;
- `cross_group_overlap.csv`: 15 shared repository/PR identities;
- `*_scan_candidates.csv`: candidates excluding those identities from both groups;

Omit `--selection-only` and supply `--codeql /path/to/codeql` to also prepare
before/head job lists in `ai/` and `human/`. This setup checks the installed
CodeQL version but does not download PRs or scan code.

The filters are stars > 500, eight supported languages, merged/closed PRs,
and feat/fix/refactor task labels, without a change-size filter. Highest
confidence selects the task label when several eligible labels exist.

The fresh run scans 3,362 AI and 2,435 human candidates after overlap exclusion.
These are NOT the historical scan-roster counts of 3,376 and 2,446. Historical
execution reused earlier scans and deduplicated against prior jobs; its final
analysis excluded 11 remaining cross-group identities and other ineligible
cases. Historical manifests remain available under `data/manifests/`. We do not
silently add historical exceptions to the metadata filter to force matching counts.

## 2. Run a bounded experiment, then the full experiment

Use CodeQL CLI 2.23.2 with its compatible query bundle and the
security-and-quality suite. Do not update query packs between before/head scans.
Compiled-language dependencies and build toolchains must be available locally.
Set `GH_TOKEN` in your environment; do not put credentials in files or commands
committed to Git.

Start with one PR per group, in a separate output directory:

```bash
python scripts/run_codeql_experiment.py --output-dir outputs/codeql_experiment-small \
  --limit-per-group 1 --execute --codeql /path/to/codeql
```

To process all candidates prepared in step 1:

```bash
python scripts/run_codeql_experiment.py --output-dir outputs/codeql_experiment \
  --execute --codeql /path/to/codeql --workers 1
```

The entry point calls the released repository preparation, CodeQL and SARIF
comparison scripts. It resolves and records base/head commits from GitHub,
downloads each repository, builds paired databases, runs queries and compares
results. Rerun the same command to resume. Changing the subset requires a new
directory. No historical local experiment directories are searched to exclude
PRs. Source/database cleanup is disabled so failed cases can be inspected.

## 3. Inspect the results rather than assuming the historical counts

Each group directory contains `codeql_jobs.csv` (including terminal states),
`logs/`, `sarif/`, and `results/introduced_alerts.csv`. The introduced-alert rows
are the input to contextual validation, not automatically confirmed issues.
Inspect paired job success and comparison status before forming a study sample;
failed scans must not become zero-alert PRs. Retain exclusion and failure reasons.

PR availability, build dependencies and analysis environment can change the
number of successful pairs and alerts. The fresh run is not expected to produce
exactly 3,087 AI PRs, 2,317 human PRs or 7,124 alerts. For exact reproduction of
the published statistics, use the separate frozen-data analysis command.

Re-running human assessment or an online reviewer is also a separate operation;
the candidate/CodeQL entry point does not fabricate or reuse old human decisions
for newly generated alerts. To use another AIDev snapshot, supply its five tables
with `--metadata-dir`; describe that as a new run, not the historical sample.
