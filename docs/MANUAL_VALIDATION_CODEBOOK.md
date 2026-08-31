# CodeQL Alert Manual Validation Codebook

> **Archived optional protocol (2026-07-23):** manual validation is not
> required by the current three-RQ design. This codebook and its samples are retained only for a
> possible exploratory appendix or reviewer-requested audit.

Version: 1.0.0  
Status: archived optional; not a study-readiness gate.

## 1. Unit and single-reviewer workflow

The annotation unit is one CodeQL alert in one PR lifecycle transition
(`introduced` or `fixed`). The reviewer receives the alert, before/after source
or diff, CodeQL message, rule documentation, and relevant build context. The
study has one human reviewer. The reviewer completes a primary pass for every
sampled alert and a delayed, blinded repeat pass for the reliability subset. The
repeat packet is re-randomized, and the primary labels must not be opened during
repeat labeling. The reviewer may use `uncertain`; uncertainty must not be
silently converted to `no`.

Review order:

1. establish whether the alert condition is semantically present in the relevant
   revision;
2. establish whether the target PR caused the introduction/removal;
3. assess whether the lifecycle difference is a fingerprint/build artifact;
4. determine whether the finding is on or causally connected to changed lines;
5. classify location and mechanism;
6. record evidence and confidence.

Differences between the primary and repeat pass are measured before resolution.
They are resolved only in `resolved_labels.csv`; the two original pass files are
immutable after completion. This design measures intra-rater stability, not
inter-rater reliability, and that limitation must be reported explicitly.

## 2. Core labels

### `semantic_valid`

- `yes`: the CodeQL-described condition is present and the rule's security or
  quality semantics apply in the analyzed revision.
- `no`: the condition is absent, infeasible, or materially contradicted by
  context; mere low exploitability is not enough for `no`.
- `uncertain`: available source/build/dependency context cannot decide.

For a fixed alert, judge semantic validity in the before revision. For an
introduced alert, judge it in the after revision.

### `pr_attributable`

- `yes`: a change in the target PR causes the condition to appear or disappear.
- `no`: the difference is caused by unrelated pre-existing code, dependency or
  generated-source variation, build configuration, extraction coverage, or
  another commit outside the target comparison.
- `uncertain`: causal attribution cannot be established from available evidence.

Moving an unchanged alert between files/lines is not PR-attributable creation or
removal.

### `fingerprint_artifact`

- `yes`: the introduced/fixed lifecycle is explained by unstable identity
  matching, ambiguous fallback matching, rename/move, line relocation, changed
  message text, or equivalent before/after alerts that failed to pair.
- `no`: no equivalent opposite-revision alert exists and the lifecycle transition
  reflects a substantive code change.
- `uncertain`: possible counterparts exist but equivalence cannot be resolved.

This label concerns lifecycle identity, not semantic truth. A semantically valid
alert may still be a fingerprint artifact.

### `changed_line_related`

- `yes_direct`: the primary alert location overlaps a changed diff line.
- `yes_causal`: the location is unchanged, but a changed definition, call,
  configuration, or data flow causally creates/removes the condition.
- `no`: no defensible relationship to the PR diff.
- `uncertain`: relationship cannot be determined.

### `location_type`

Use exactly one: `production`, `test`, `docs`, `example`, `generated`, `vendor`,
`build`, or `uncertain`. Apply the frozen rules in
[`config/study/pr_enrichment_rules.json`](../config/study/pr_enrichment_rules.json);
reviewers may choose `uncertain` when repository conventions contradict a path
heuristic.

### `mechanism`

Use the most specific applicable value:

- `validation_or_sanitization`
- `authorization_or_access_control`
- `dataflow_or_taint`
- `resource_lifetime_or_memory`
- `error_handling`
- `concurrency_or_state`
- `api_contract_or_type`
- `configuration_or_dependency`
- `dead_or_unreachable_code`
- `rename_move_or_refactor`
- `generated_or_vendor_change`
- `test_only_change`
- `other`
- `uncertain`

The mechanism describes how the PR introduces/removes the condition, not merely
the rule name. Explain `other` in notes.

### `reviewer_confidence`

- `high`: direct source/diff evidence and rule semantics resolve the decision.
- `medium`: conclusion is more likely than alternatives but relies on some
  inference.
- `low`: evidence is incomplete; consider an `uncertain` core label.

## 3. Derived status

The analysis program derives `confirmed=yes` only when:

```text
semantic_valid == yes
and pr_attributable == yes
and fingerprint_artifact == no
```

Reviewers must not directly label `confirmed`. Any `uncertain` component prevents
confirmation until adjudication.

## 4. Evidence requirements

For every non-obvious decision, record:

- relevant before and after file/hunk;
- source/sink or program condition when applicable;
- why the PR changes the condition;
- any candidate opposite-revision counterpart;
- build, dependency, generated-code, or rename evidence;
- rule documentation consulted.

Do not decide from the PR title, AI/Human label, or alert severity alone. Reviewer
packets should hide authorship group where feasible during semantic assessment.

## 5. Pilot and formal freeze

The pilot contains 20–30 probabilistically selected alerts and is marked
`sample_phase=pilot`. Every pilot alert is labeled twice with a washout period of
at least 14 calendar days. For the formal sample, a frozen-seed stratified subset
of at least 25% is repeated; where the sample permits, this subset contains at
least 30 alerts. After delayed repeat annotation:

1. report raw intra-rater agreement, Cohen's kappa with repository-cluster
   bootstrap interval, and uncertain counts for each core field;
2. inspect and resolve primary/repeat differences without altering either pass;
3. revise ambiguous definitions without altering pilot labels;
4. increment this document's version;
5. freeze the schema and codebook hash, recording both pass dates and washout;
6. generate a new formal sample excluding every pilot `alert_id`.

Formal estimates must retain each row's stratum size, stratum sample size,
selection probability, inverse-probability weight, source file hash, seed, and
sample manifest hash. The paper must not describe this procedure as independent
double coding or report its kappa as inter-rater agreement.
