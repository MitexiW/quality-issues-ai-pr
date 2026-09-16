# Running the RQ3 reviewer and evaluating its findings

This guide concerns **new model calls**, not re-scoring frozen outputs. Install
`requirements-full.txt`, run commands from the repository root, and use new
output directories. Do not overwrite `data/results`. Historical model names
below are recorded settings, not guarantees of current provider availability.

## 1. Choose the sample and prepare the code

For the paper's sample, use
`data/results/rq3_formal_plan_20260727_v1/formal_cases.csv` (267 PRs).
The released reference metadata and final human labels are in
`data/results/final_human_confirmed_rq3_20260817_v1/reference_adjudication_join_public.csv`.
Keep this reference file **outside reviewer worktrees**. It is for evaluation,
not a prompt input. It includes historical recovery labels; those labels must
not be used to score a new reviewer run.

The following commands assume the [CodeQL experiment](CODEQL_EXPERIMENT.md)
has supplied Git caches and populated job manifests under
`outputs/codeql_experiment`. For historical cases, verify that all 267 PRs and
their exact recorded base/head commits are present; a fresh scan roster can
differ. Do not replace missing historical cases silently. Missing repositories
or objects must be acquired first; the diff exporter does not download them.

```bash
python scripts/rq3/export_rq3_diffs.py \
  --cases data/results/rq3_formal_plan_20260727_v1/formal_cases.csv \
  --ai-jobs outputs/codeql_experiment/ai/codeql_jobs.csv \
  --human-jobs outputs/codeql_experiment/human/codeql_jobs.csv \
  --ai-cache-dir outputs/codeql_experiment/ai/repos/.cache \
  --human-cache-dir outputs/codeql_experiment/human/repos/.cache \
  --output outputs/rq3-inputs/pr_diffs.jsonl
python scripts/prepare_claude_review_worktrees.py \
  --cases data/results/rq3_formal_plan_20260727_v1/formal_cases.csv \
  --diffs outputs/rq3-inputs/pr_diffs.jsonl \
  --ai-jobs outputs/codeql_experiment/ai/codeql_jobs.csv \
  --human-jobs outputs/codeql_experiment/human/codeql_jobs.csv \
  --ai-cache-dir outputs/codeql_experiment/ai/repos/.cache \
  --human-cache-dir outputs/codeql_experiment/human/repos/.cache \
  --output-dir outputs/rq3-worktrees --workers 1
```

The builder creates neutral, read-only-review worktrees with the base at HEAD
and the complete PR head staged. Inspect `manifest.json`, `worktree_key.csv`
and any `worktree_failures.csv`. Failed builds are not negative review results.
For a smaller worktree test, add `--limit 1` and use a separate output directory.

For **a new sample**, reconstruct the reference frame with
`scripts/rq3/prepare_rq3_frame.py`: explicitly supply `--analysis-pr-level`,
`--snapshot-manifest`, `--frozen-model-specification config/study/model_specification.yaml`,
`--ai-alerts`, `--human-alerts`, `--pr-enrichment`, `--file-enrichment`,
`--cache-dir`, and `--output-dir`. The metadata/enrichment inputs come from the
preceding CodeQL and [assessment](ALERT_ASSESSMENT.md) stages, not arbitrary CSVs.
It emits `pr_pool.csv` and primary, higher-severity and broad reference tables.
The historical filename `quality_strict_reference_alerts.csv` denotes the
higher-severity tier. Select a new sample, for example:

```bash
python scripts/rq3/select_llm_review_cases.py \
  --pr-pool outputs/rq3-frame/pr_pool.csv \
  --silver-findings outputs/rq3-frame/quality_primary_reference_alerts.csv \
  --all-family-findings outputs/rq3-frame/reference_alerts.csv \
  --output outputs/rq3-plan/cases.csv --positive-target 1 \
  --controls-per-positive 1 --split pilot --seed 20260623
```

This also writes `all_case_reference_alerts.csv` for evaluation. Replace the
historical cases/references in subsequent commands with this pair. Freeze the
selection before reviewing; do not select cases based on reviewer success.
New reference conditions still require human validation before reporting
human-confirmed recall.

## 2. Test a single PR without a paid call

Set `RQ3_BASE_URL` and `RQ3_API_KEY` in your environment. Set `REVIEW_CASE_ID`
to a built case ID from `worktree_key.csv` (not an arbitrary PR number).

```bash
python scripts/run_claude_code_review.py \
  --worktree-root outputs/rq3-worktrees --case-id "$REVIEW_CASE_ID" \
  --provider deepseek --base-url "$RQ3_BASE_URL" --api-key-env RQ3_API_KEY \
  --model 'deepseek-v4-pro[1m]' --effort max \
  --max-budget-usd 1 --max-turns 30 --output-dir outputs/rq3-one-case
```

This is preflight only. Add `--execute` only after inspecting it and authorizing
the cost. The example budget/turn limits are smoke-test settings, not a claim
to reproduce the historical execution limits. Record the actual endpoint,
model and limits used. SDK budget limits are not reliable provider-side hard
caps; configure a provider spending limit too. Inspect `review_response.json`
and execution records. Do not rerun a PR merely because its findings are poor.

## 3. Run the paper's fixed 267-case batch

`run_rq3_formal_reviews.py` deliberately requires 267 built cases: 187 positive
and 80 control PRs. It is **not an arbitrary-size batch runner**. The single-case
runner above supports small/new samples without pretending they are this cohort.

Choose `REVIEW_BUDGET_USD`, `REVIEW_MAX_TURNS`, `REVIEW_COST_ESTIMATE_USD`,
`REVIEW_TOTAL_BUDGET_USD` and `REVIEW_AVAILABLE_USD` yourself, after checking
provider pricing/balance. These are numeric environment variables, not secrets.
The three total-budget arguments document authorization and available funds;
do not invent balances or bypass the gate to get a command to run.

```bash
python scripts/rq3/run_rq3_formal_reviews.py \
  --cases data/results/rq3_formal_plan_20260727_v1/formal_cases.csv \
  --references data/results/final_human_confirmed_rq3_20260817_v1/reference_adjudication_join_public.csv \
  --worktree-root outputs/rq3-worktrees --output-dir outputs/rq3-run \
  --provider deepseek --base-url "$RQ3_BASE_URL" --api-key-env RQ3_API_KEY \
  --model 'deepseek-v4-pro[1m]' --effort max \
  --max-budget-usd "$REVIEW_BUDGET_USD" --max-turns "$REVIEW_MAX_TURNS" \
  --planning-cost-per-review-usd "$REVIEW_COST_ESTIMATE_USD" \
  --authorized-run-budget-usd "$REVIEW_TOTAL_BUDGET_USD" \
  --provider-side-remaining-budget-usd "$REVIEW_AVAILABLE_USD"
```

First complete the no-call preflight. To execute, repeat the same configuration
with `--resume --execute --provider-budget-confirmed --execution-case-limit 1`.
Continue with `--resume`; the default execution limit is ten newly started
cases per invocation. Inspect failures before continuing. The reference path
is recorded by the coordinator but is not passed to the reviewer child process.

After completion, generate preliminary location-based matches:

```bash
python scripts/rq3/summarize_rq3_formal_reviews.py \
  --run-dir outputs/rq3-run \
  --cases data/results/rq3_formal_plan_20260727_v1/formal_cases.csv \
  --references data/results/final_human_confirmed_rq3_20260817_v1/reference_adjudication_join_public.csv \
  --output-dir outputs/rq3-results
```

Outputs include `case_metrics.csv`, `finding_matches.csv`, and
`reference_recovery.csv`. These automatic matches are **not final semantic
recall**. `--allow-incomplete` is for failure/progress analysis, not silently
changing the final denominator. This summarizer consumes the formal run ledger;
it cannot directly summarize a folder of standalone single-case runs.

## 4. Match meanings and verify every final relation

```bash
python scripts/rq3/prepare_rq3_semantic_adjudication.py \
  --cases data/results/rq3_formal_plan_20260727_v1/formal_cases.csv \
  --references data/results/final_human_confirmed_rq3_20260817_v1/reference_adjudication_join_public.csv \
  --case-metrics outputs/rq3-results/case_metrics.csv \
  --finding-matches outputs/rq3-results/finding_matches.csv \
  --automatic-reference-recovery outputs/rq3-results/reference_recovery.csv \
  --worktree-key outputs/rq3-worktrees/worktree_key.csv \
  --worktree-root outputs/rq3-worktrees --output-dir outputs/rq3-semantic
```

Read the generated `ADJUDICATION_CODEBOOK.md`, candidate pairs and case packets.
LLM-assisted semantic judgments require a separate assessor session using these
packets; the preparer does **not** call a matcher model. The release does not
provide a one-command hosted semantic-assessor launcher. A human must verify
every final relation, whether initially deterministic or model-assisted.

Write JSONL decisions under `outputs/rq3-semantic/decisions/`. Each decision
identifies `model_finding_id` and `case_id`, and supplies `finding_validity`,
`codeql_relation`, `matched_reference_ids` (a list), `confidence`, `rationale`,
`evidence_paths` (a list), `adjudicator` and `adjudicator_type`. Use the exact
values in the generated codebook. Record human-final decisions as `human`, not
as model judgments. `same_issue` requires matching reference IDs; other
relations use an empty list. Uncertain/incomplete decisions need further review.

```bash
python scripts/rq3/compile_rq3_semantic_adjudication.py \
  --workspace outputs/rq3-semantic
python scripts/rq3/summarize_rq3_semantic_adjudication.py \
  --workspace outputs/rq3-semantic --formal-results outputs/rq3-results \
  --output-dir outputs/rq3-semantic-results
```

Inspect completion status and `semantic_reference_recovery.csv`. For final
human-confirmed recall, join **new** recovery flags to validated reference IDs,
filter to the predeclared tier and divide recovered references by eligible
references. Count each reference once even if several findings recover it.
The positive-PR measure counts PRs with at least one recovered eligible reference.
Use the primary tier for the primary estimate; report higher-severity and broad
analyses separately. Do not copy the historical `semantic_recovered` column
into a new run. For the current combined dataset, run
`python scripts/analyze_default_review.py` to reproduce 21/114 from the released
labels; it is not a scorer for unjoined new reviewer outputs. Historical dated
files retain the original 20/114 result. See [DEFAULT_REVIEW.md](DEFAULT_REVIEW.md).

## What has been checked

The public command-line interfaces and offline input preparation are checked
locally. The tutorials do not imply that a new paid model run, all historical
worktree downloads, or new human assessments have been performed. Frozen-data
reproduction remains available independently through `reproduce_analysis.py`.
