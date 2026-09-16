# Default review data

`data/results/default_review/` contains one successful review for each of the
267 PRs, with 1,106 findings and all final human matching labels. It combines
the 252 original valid responses and successful reruns of the 15 invalid
responses. Cases were rerun based on execution status, not review findings.
The new findings underwent human matching before we updated recovery counts.

The directory is the current default-review dataset, not another review arm.
Historical dated directories retain the earlier outputs and label audit.

## Files

- `review_index.csv` and `reviews/`: all selected responses with finding IDs.
- `human_decisions.csv`: one final matching label per finding.
- `case_metrics.csv`: selected model, valid-output status, finding count and
  elapsed time for each PR; no session identifiers or host information.
- `reference_inputs.csv`: reference eligibility and context from the released
  CodeQL frame. The analysis recalculates recovery from the human labels.
- `analysis/`: recalculated metrics and supplementary results.

Reviewer names, timestamps, free-text assessment notes, local execution paths,
credentials and raw SDK transcripts are not included in this export.

```bash
python scripts/analyze_default_review.py
python scripts/analyze_native_skill_recovery.py
```

The first command verifies all 1,106 labels and recomputes reference recovery.
The second reads the same default labels when comparing them with the guided
review. Primary recovery is 21/114 (18.42%) versus 32/114 (28.07%); broad-tier
recovery is 37/187 (19.79%) versus 53/187 (28.34%).

The original human matching used the raw reference inventory. Matching of the
90 new findings used the confirmed broad references. The `reference_scope`
column records this difference. Both recall estimates use the same confirmed
references. Raw-reference and original matching-audit tables still describe
the historical run, because the new findings were not assessed against all raw
references. They must not be read as results from the combined run.

To rerun the reviewer from PR worktrees, follow [RQ3_REVIEW.md](RQ3_REVIEW.md).
Use the default prompt, not the guided Skill. Do not reuse released human
decisions for newly generated findings. The retained logs identify invalid
outputs; we do not assume that all failures were network errors.
