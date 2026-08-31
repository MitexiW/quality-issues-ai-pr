# CodeQL introduced alert model-adjudication protocol

## Purpose and scope

This experiment asks a model to adjudicate every introduced CodeQL
alert in the frozen RQ1/RQ2 analysis roster. It does not replace CodeQL's raw
measurement files and it does not constitute human validation.

The frozen frame contains:

- 7,124 introduced alerts: 2,751 AI and 4,373 Human;
- 6,608 Quality alerts and 516 Security alerts;
- 957 alert-positive PRs: 476 AI and 481 Human;
- 1,963 bounded model batches, each containing at most five alerts from exactly
  one PR.

The frame excludes PRs that failed the already-frozen `quality_gate_pass`
criterion. The preparation command fails closed if these counts change.

## Adjudication contract

For every alert, the model must return:

- whether the reported program condition is present;
- whether it is a meaningful Quality issue in repository context;
- whether the PR introduced the condition;
- its actionability and confidence;
- revision-specific repository-file and line evidence plus a concise rationale.

The model sees the neutral before revision at `HEAD`, with the complete head
revision staged as the pending change. Authorship group, repository name, PR
number, and agent identity are not included in the model prompt. Reviewer
tools are read-only and cannot use the network.

Every evidence item explicitly records `revision=before` or `revision=head`.
The validator reads `before` evidence from `git show HEAD:<path>` and `head`
evidence from the staged working tree. Therefore a file deleted or renamed by
the PR remains valid evidence when it is correctly attributed to `before`.

The strict primary derived indicator is
`model_supported_introduced_issue=1`, which requires all of:

1. `condition_present=yes`;
2. `valid_issue=yes`;
3. `introduced_by_pr=yes`.

`model_supported_actionable_issue=1` additionally requires `must_fix` or
`should_fix`. Uncertain decisions remain explicit and are not silently mapped
to valid or invalid.

## Run the experiment

Run commands from `<ARTIFACT_ROOT>`. The endpoint must implement the
Anthropic Messages/tool-use protocol used by Claude Agent SDK; an endpoint that
only implements OpenAI Chat Completions is not sufficient. In zsh, load the
API key into the current shell without writing it to disk:

```zsh
read -rs 'MODEL_API_KEY?Model API key: '; echo
export MODEL_API_KEY
export CLAUDE_CODE_STREAM_CLOSE_TIMEOUT=180000
```

Supply the exact base URL and model identifier selected for the formal run:

```zsh
nice -n 19 .venv/bin/python scripts/start_codeql_alert_adjudication.py \
  --provider compatible \
  --base-url 'https://YOUR-ENDPOINT/anthropic' \
  --model 'YOUR-MODEL-ID' \
  --api-key-env MODEL_API_KEY \
  --skip-existing-failures
```

It starts a new formal run or resumes the existing one and uses four concurrent
PR workers. Before the full run, ten frozen pilot batches spanning AI/Human
provenance, several languages, and batch sizes must all pass the strict output
and evidence checks. The formal protocol imposes no separate tool-call cap:
the reviewer may make as many read-only inspection calls as needed within the
20-turn SDK limit. Non-read-only tools remain denied. The full invocation
pauses after ten failures instead of consuming the rest of the budget under a
systematic endpoint or protocol failure. It creates the final result tables
automatically after all 1,963 batches complete. Re-running the same command
after an interruption is safe.

The circuit counts independent failure units: a model/output failure counts per
batch, while one PR worktree reconstruction failure counts once even when that
PR contains many alert batches. All affected batches are still marked
`worktree_failed` for complete attrition accounting.
Use `--workers 2` if repository reconstruction causes excessive disk I/O.

The immutable SDK transcript remains the authoritative source for reporting
the accepted result's tool-call count. Hook counters are retained as diagnostic
data, but an otherwise valid response is not rejected merely because it needed
more than 12 inspection calls. `--max-tool-calls N` remains available only for
explicitly bounded diagnostic runs and must not be mixed into the formal run.

The run continues in the existing `formal_run_20260804_v5` directory. On the
first unbounded resume, the launcher archives the bounded configuration under
`protocol_history/`, records the transition in `protocol_amendments.json`, and
retains already completed batches. Subsequent batches use the unbounded
inspection policy. This preserves one result inventory while making the
mid-run protocol amendment auditable; analyses must disclose the amendment and
may compare pre- and post-amendment batches as a sensitivity check.

The run is resumable. With `--skip-existing-failures`, each pending sweep skips
completed batches and leaves all pre-existing `failed`/`worktree_failed`
statuses, attempts, errors, and costs unchanged. New failures still count
toward the ten-failure circuit breaker. Once no retryable pending batch remains,
the launcher stops and requires the deferred failures to be repaired and run
separately without this flag; deferred failures are never represented as
completed. Without the flag, resumption retries every non-completed batch.
A filesystem lock prevents two processes from resuming the same output
directory simultaneously. Scratch worktrees are created just in time and
removed after each PR. The launcher emits a progress heartbeat every 30
seconds. Pressing Ctrl+C terminates the complete child process group, including
active Claude Code CLI processes.

The SDK's reported `total_cost_usd` is recorded for audit, but it might not be
a reliable provider-side spending cap for a compatible third-party endpoint.

## Monitor progress

```zsh
watch -n 10 '.venv/bin/python -c '\''import csv,collections; p="data/experiments/security-and-quality/study_stars500/reports/codeql_alert_adjudication_20260804_v5/formal_run_20260804_v5/batch_status.csv"; r=list(csv.DictReader(open(p))); print(len(r), dict(collections.Counter(x["status"] for x in r)), "cost", sum(float(x["total_cost_usd"] or 0) for x in r))'\'''
```

## Produce the frozen result tables

The formal summarizer refuses to run until all 1,963 batches have status
`completed`:

```zsh
nice -n 19 .venv/bin/python scripts/summarize_codeql_alert_adjudication.py \
  --run-dir data/experiments/security-and-quality/study_stars500/reports/codeql_alert_adjudication_20260804_v5/formal_run_20260804_v5
```

It produces `model_adjudications.csv`, a PR-level summary, a complete batch
audit, a Markdown summary, and a hash manifest under `results/`. A progress
snapshot may be generated with `--allow-incomplete`, but that output is marked
preliminary and cannot be used for formal downstream analysis.

## Interpretation boundary

The exported decisions must be described as model adjudications or
model-supported alerts. Before treating their rates as estimates of real-world
validity in a paper, a provenance-blinded human calibration sample should be
used to quantify model agreement and systematic error. The raw CodeQL results
remain available for sensitivity analysis.
