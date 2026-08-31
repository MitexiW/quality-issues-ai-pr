# Independent Full Re-review of 2,379 Confirmed Alerts

## Purpose

The study uses three distinct reviewer roles:

- Reviewer A reviewed all 2,495 model-retained alerts and classified 2,246 as
  `confirmed_valid`;
- Reviewer B separately reviewed all 4,629 model-excluded alerts and classified
  133 as `confirmed_valid`;
- Reviewer C independently re-evaluates the combined 2,379 alerts.

Reviewer C must not see Reviewer A's or Reviewer B's decisions or notes, the
model judgments, aggregate results, or manuscript claims before finishing this
pass. Repository identity can still be inferred from code and paths, so the
procedure is label-hidden rather than strictly identity-blinded.

This positive-selected re-review estimates the second-reviewer confirmation
rate and identifies disagreements for consensus. It cannot provide a
meaningful Cohen's kappa by itself because every source-reviewer label in this
set is `confirmed_valid`. The separate outcome-stratified 200-alert reliability
audit provides four-way and binary kappa estimates.

## Frozen input

The reviewer-facing input is:

`data/experiments/security-and-quality/study_stars500/reports/manual_validation/independent_full_rereview_2379_v1/sample.csv`

The sealed key is under the sibling `admin/` directory. Do not give that file
or directory to Reviewer C. The preparation manifest hashes both files and
refuses to reuse the frozen study if either source-review state changes.

## Start the review website

From `<ARTIFACT_ROOT>`, run:

```bash
nice -n 19 .venv/bin/python scripts/manual_alert_review_app.py \
  --input data/experiments/security-and-quality/study_stars500/reports/manual_validation/independent_full_rereview_2379_v1/sample.csv \
  --output-dir data/experiments/security-and-quality/study_stars500/reports/manual_validation/independent_full_rereview_2379_v1/review \
  --seed 2026081702 \
  --port 20084 \
  --omit-review-timestamps
```

If port 20084 is already occupied, replace it with another permitted unused
port above 20024. Forward that port through VS Code or SSH and open
`http://127.0.0.1:20084` in the reviewer's browser. Keep the service bound to
localhost; do not use `--allow-remote` without an authenticated reverse proxy.

The SQLite database is resumable. Stopping and rerunning the same command with
the same input, output directory, and seed continues from saved progress.

## Decision codebook

For every alert, inspect the PR diff, before/head source, and any CodeQL trace
or related-file context, then choose exactly one final disposition:

1. `confirmed_valid`: the described condition exists, was introduced by the
   pending PR, and constitutes a meaningful issue in repository context.
2. `condition_absent`: the CodeQL-described program condition does not exist.
3. `not_pr_introduced`: the condition exists but was already present in the
   base revision, or the PR merely moved or exposed it.
4. `not_valid_issue`: the condition exists and was introduced by the PR, but is
   acceptable or non-problematic in the repository context.
5. `uncertain`: available evidence is insufficient. This is temporary only;
   all uncertain, deferred, and flagged items must be resolved before analysis.

Use notes for non-obvious decisions and disagreements. Reviewer C must not ask
Reviewer A or Reviewer B for their decision during the independent pass. Do
not perform consensus while independent labeling is still in progress.

## Completion and analysis

When the website shows `已完成 2379 / 2379`, resolve all flagged or uncertain
items and click `导出 CSV`. Then stop the server and run:

```bash
nice -n 19 .venv/bin/python scripts/analysis/second_reviewer_reliability.py analyze-full
```

This command reads the live SQLite state, verifies all 2,379 IDs and decisions,
and writes:

- `analysis/confirmation_summary.json`;
- `analysis/confirmation_by_stratum.csv`;
- `analysis/disagreements_for_consensus.csv`.

Only after that export should Reviewer C inspect each disagreement together
with the relevant source reviewer: Reviewer A for retained alerts and Reviewer
B for excluded alerts. Record a consensus disposition and concise rationale
without overwriting either reviewer's original decision.

## Final frozen result

The independent pass and consensus are complete. Reviewer C confirmed 2,319
of the 2,379 source-positive alerts and disagreed on 60. Consensus retained 3
of those 60 and rejected 57. To construct the complete final analytical label
frame, run:

```bash
.venv/bin/python scripts/analysis/finalize_full_alert_consensus.py
```

The command verifies the immutable disagreement payload, requires a final
resolution for all 60 IDs, applies the frozen precedence rule, and exports all
7,124 alert labels. The final frame contains 2,322 `confirmed_valid` alerts
(2,194 Quality and 128 Security); all four dispositions sum to 7,124. The
analytical export deliberately omits review timestamps. Its manifest and
output hashes are frozen under
`reports/final_human_consensus_20260817_v1/`.
