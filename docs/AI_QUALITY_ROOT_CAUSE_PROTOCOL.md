# AI Quality Issue Root-Cause Analysis Protocol

## Construct and unit of analysis

This study codes the **proximate code-change cause**: the observable operation
performed by a PR, the code relationship or constraint left unsatisfied, and
the anomalous head-revision state that follows. It does not code an AI model's
unobserved cognition. Statements such as “the AI forgot” or “the model did not
understand the API” are inadmissible without direct process evidence.

The final unit is a **root-cause cluster**. A cluster contains the confirmed
alerts in one PR that are attributable to the same observable change mechanism
and the same underlying code relation or invariant. Repository + PR + CodeQL
rule is only the initial review unit.

- Split an initial PR–rule unit when its alerts arise from independent edits,
  change mechanisms, or violated relations/invariants.
- Merge units across rules within the same PR when the same edit and violated
  relation produce multiple rule manifestations.
- Do not merge merely because alerts share a rule, file, or taxonomy label.
- Do not merge causes across PRs. Cross-PR recurrence is reported through the
  taxonomy, not through a shared cluster identifier.

## Evidence ladder

Use the strongest locally available evidence in this order:

1. the PR patch showing the relevant addition, deletion, or replacement;
2. before/head definitions, uses, control flow, and cross-file dependencies;
3. tests, type signatures, configuration, or local conventions that establish
   the violated constraint;
4. PR discussion or generation logs, if separately preserved.

CodeQL's message establishes the detected condition but is not by itself a
root-cause explanation. Existing human notes and model rationales are locating
aids; reviewers must confirm their claims against code evidence.

Each accepted cluster records a causal chain of this form:

> observable change → unmaintained relation/constraint → anomalous head state
> → linked CodeQL manifestation(s)

Example: “The PR replaced the calendar query implementation but retained the
previous hook import; no head-revision reference consumes that import, yielding
the unused-import alert.” This supports `incomplete_cleanup_after_modification`.
If both the import and a wholly new file were added together, with no evidence
of a replaced plan, code `unintegrated_element_in_new_code` instead.

## Coding procedure

1. Review all rules for one PR together, using its JSON evidence packet.
2. Locate every alert in the relevant file patch and before/head excerpts.
3. Draft provisional within-PR clusters before assigning taxonomy categories.
4. Apply the one-mechanism/one-relation test. Split heterogeneous alerts; merge
   cross-rule manifestations only when the shared cause is evidenced.
5. Write a neutral cause statement naming code entities and relationships.
6. Record exact evidence locations and confidence. Use `insufficient_evidence`
   rather than inferring author intent.
7. During axial coding, revise the pilot taxonomy when repeated evidence does
   not fit; preserve an audit trail for category migrations.

## Reporting taxonomy constraint

The paper reports exactly five primary root-cause categories. Finer mechanisms
are retained only as audit sublabels and for explaining representative cases;
they are not additional peer categories in the main frequency analysis. The
five frozen categories are:

1. incomplete change coordination;
2. interface or contract mismatch;
3. control-, state-, or data-flow miscomposition;
4. dependency, error, or resource mismanagement; and
5. redundant or locally inconsistent construction.

The pilot was allowed to refine category definitions and boundaries, but the
full coding stage did not solve poor fit by proliferating primary categories.
A rare candidate mechanism is merged when its central violated relation and
observable change mechanism fit an existing category. `insufficient_evidence`
is an audit disposition rather than
a sixth category and must be reported separately.

The annotation template is intentionally one row per initial PR–rule unit.
Reviewers may duplicate a row to split it and populate only the relevant alert
IDs. To merge rules, use the same `cluster_key_within_pr` on their rows. A
compiler must later enforce that all 775 alert IDs are linked exactly once and
that a cluster key never spans PRs.

## Reliability design

Develop the codebook on a stratified pilot rather than the full frame. The pilot
should include high-frequency maintainability rules, sparse correctness rules,
multi-alert bursts, multi-rule PRs, and multiple languages. Freeze a first
codebook after discussion, independently double-code a disjoint reliability
sample, report agreement before reconciliation, then adjudicate disagreements.

Agreement should be reported separately for (a) alert-to-cluster boundaries and
(b) mechanism-category labels. Exact cluster IDs are reviewer-local, so boundary
agreement should be calculated from pairwise same-cluster decisions within each
PR. Category agreement is calculated only after aligning clusters by their alert
memberships.

For the completed primary coding, the compiler performs an exhaustive
partition check and a same-reviewer boundary recheck covers every cross-rule
cluster, every cluster with at least five alerts, and every non-high-confidence
cluster. This recheck is an internal consistency audit, not independent double
coding, so no inter-rater reliability statistic is claimed from it. The
independent reliability protocol remains a separate replication step when a
second reviewer is available.

## Completed analysis frame

The frozen full analysis contains 775 alerts in 251 PRs and 316 initial
PR–Rule units. Primary coding produced 412 root-cause clusters. The full
compiler confirmed that every alert is linked exactly once; 56 initial
PR–Rule units required splitting and 12 clusters merge manifestations from
more than one rule. The high-risk boundary recheck reviewed 32 of 32 selected
clusters. Four clusters retain medium confidence, and none required the
`insufficient_evidence` disposition.

## Preparation command

```bash
.venv/bin/python scripts/analysis/prepare_ai_quality_root_cause_review.py
```

The command enforces the frozen 775-alert / 251-PR / 316-PR–rule contract and
writes a manifest, the initial review-unit table, an annotation template, and
one evidence packet per positive AI PR. Generated files remain under `data/`.
