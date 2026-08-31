# Reproducibility guide

The artifact supports three distinct operations.

1. **Package integrity check.** `python scripts/verify_artifact.py` checks
   released hashes and fixed scientific invariants. It runs no analysis.
2. **Reported-result recomputation.** The post-release convenience wrapper
   `python scripts/reproduce_analysis.py` starts from frozen final tables and
   rebuilds validation summaries, reruns RQ1--RQ3 statistics and rule-exclusion
   checks, exports numbered table data, and draws figures from those new results.
   It does not repeat data
   collection, CodeQL, model inference, or human decisions.
3. **Upstream experiment rerun.** The active CodeQL, model-screening,
   manual-review, and LLM-review code is included. A complete rerun requires
   the upstream AIDev data, public GitHub repositories, CodeQL 2.23.2, reviewer
   labor, and a separately configured model endpoint.

The integrity checker and the one-command analysis wrapper were added for the
public artifact; they are not the historical commands used to collect the
study data. The exact stage-by-stage distinction is documented in
`docs/RUN_EXPERIMENTS.md`.

The artifact deliberately excludes runtime products that are unnecessary for
checking the paper results: cloned worktrees, CodeQL databases, SARIF, logs,
caches, model transcripts, failed attempts, smoke tests, and superseded output
versions.  The published unit is therefore a compact analysis artifact, not a
snapshot of the original compute environment.

## Data flow

```text
AIDev/GitHub PRs
  -> paired CodeQL analysis
  -> 7,124 raw differential alerts
  -> complete branch-specific human review
  -> independent re-review of 2,379 initial confirmations
  -> consensus on 60 disagreements
  -> 2,322 final confirmed issues
  -> RQ1 profiles and 412 mechanism clusters, RQ2 GEE, and RQ3 recovery analyses
```

Separately, RQ3 contains 1,016 finding--reference relation decisions. Initial
provenance is preserved as 776 `LLM_assistant` and 240 `deterministic_rule`
decisions; one author subsequently reviewed each relation manually. This RQ3
relation review was not independently double-annotated, and the artifact does
not provide a timestamped modification history. These limitations concern the
RQ3 relation-review layer, not the independent alert re-review shown above.

All model secrets are supplied through environment variables and are not part
of this artifact.
