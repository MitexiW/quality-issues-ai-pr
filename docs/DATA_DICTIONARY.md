# Data dictionary

The current default RQ3 dataset is `data/results/default_review/`: 267 valid
responses and 1,106 final human labels. See [DEFAULT_REVIEW.md](DEFAULT_REVIEW.md).
Dated default-review directories below retain historical outputs and audits.

All released result paths are under `data/results/`.

| Directory | Role |
|---|---|
| `final_human_consensus_20260817_v1` | One final disposition for each of the 7,124 raw differential alerts, plus the 60 consensus resolutions. |
| `final_human_confirmed_issue_analysis_20260817_v1` | The 2,322 confirmed alert rows, the 5,404-PR analysis frame, and outcome-validation aggregates. |
| `final_human_confirmed_rq1_ai_profile_20260820_v2` | AI-cohort Quality/Security profiles by task, language, change size, category, location, severity, precision, and rule. |
| `final_human_confirmed_rq1_human_profile_20260817_v1` | Corresponding human-cohort profiles. |
| `ai_quality_root_cause_review_20260831_v1` | Complete 412-cluster partition of the 775 confirmed AI Quality alerts, alert-to-cluster links, category summaries, and boundary audit. |
| `alert_sensitivities_final_20260727_v2` | Alert-count and changed-KLOC sensitivity analyses reported in the manuscript and supplement. |
| `final_human_confirmed_rq2_models_20260817_v1` | Repository-clustered GEE coefficients, diagnostics, standardized effects, and task-interaction tests. |
| `final_human_confirmed_rq3_20260817_v1` | Final-label re-scoring of the frozen LLM-review experiment. The `*_public.csv` table omits raw source context and diff text while retaining all fields used by the released analyses. |
| `final_human_confirmed_insight_analysis_20260817_v1` | Cross-RQ concentration, similarity, calibration, and recovery summaries. |
| `rq2_design_unweighted_final_20260727_v3` | Outcome-blind, unit-weight full-sample RQ2 roster. |
| `rq_analysis_final_20260727_v3` | Frozen raw before/after analysis frame and attrition audits. |
| `rq3_formal_plan_20260727_v1` | Frozen 267-case RQ3 benchmark frame and selection manifest; raw PR diffs are intentionally omitted. |
| `rq3_formal_run_20260727_v1` | Invocation order and execution-level run manifest for all 267 cases; raw SDK transcripts are intentionally omitted. |
| `rq3_formal_results_20260729_v1` | Per-case execution metrics, 1,016 structured reviewer findings, automatic matches, and reference recovery. |
| `rq3_semantic_results_20260729_v1` | One initial relation decision for each of the 1,016 reviewer findings. The public table records whether that initial relation came from a deterministic rule or LLM-assisted semantic adjudication. |
| `rq3_semantic_human_review_v1` | Manual review by one author of all 1,016 initial semantic-relation decisions. Initial provenance is retained separately: 776 `LLM_assistant` and 240 `deterministic_rule`. This layer has no independent double annotation or timestamped modification history. |
| `rq3_reference_mechanism_mapping_20260901_v1` | Frozen five-category mechanism mapping for the primary 114-reference RQ3 analysis. |
| `rq3_all_reference_mechanism_mapping_20260901_v1` | Frozen five-category mapping and recovery summary for all 187 human-confirmed Quality references in reviewed PRs. |

For RQ3, `author_relation_review.csv` contains one author-confirmed row for
each of the 1,016 relations. The `initial_*` fields preserve the original
decision and provenance; the `final_*` fields record the result after the
author's manual check. The table is an audit snapshot, not a longitudinal
annotation log: it neither represents an independent second annotation nor
records when individual decisions were modified.

Sanitized selected-PR and CodeQL job manifests are stored separately under
`data/manifests/`. They preserve selection/provenance fields, repository/PR
identity, before/head commits, language, CodeQL configuration, and terminal
status while omitting local paths, raw runtime commands, errors, and third-party PR
title/body prose. The small set of manual CodeQL build commands is normalized
to repository-relative commands. PR and job identifiers are unique within a
cohort; use `group + repo_name + pr_number` as the public cross-table identity.

Important fields:

- `alert_id`: stable identifier for one differential CodeQL alert;
- `disposition`: final human decision (`confirmed_valid`,
  `condition_absent`, `not_pr_introduced`, or `not_valid_issue`);
- `source_set`: whether model screening retained or excluded the alert;
- `validated_quality_any`: whether a PR contains at least one final confirmed
  Quality issue;
- `validated_quality_alerts`: number of final confirmed Quality issues in a PR;
- `group`: `ai` or `human` authorship cohort;
- `repo_language`: CodeQL database language, not necessarily the language of
  every changed file;
- `task_type`: `feat`, `fix`, or `refactor`;
- `changed_kloc`: PR-wide additions plus deletions divided by 1,000;
- `root_cause_cluster_id`: stable identifier for one within-PR proximate
  code-change mechanism cluster;
- `root_cause_category`: one of the five frozen RQ1 mechanism categories.

Human notes and public repository/file identifiers are retained for auditability.
The package does not include complete repository source trees or raw API/model
transcripts.

## Inputs for rebuilding the paper tables

`data/inputs/alert_assessment/model_adjudications.csv` contains all 7,124 alerts
with rule metadata and the three original model decisions. Free-text model
responses are omitted. Join `alert_id` to `final_alert_labels.csv` for the
final human decision. These files rebuild the validation snapshot and strata.

`data/inputs/raw_alerts/{ai,human}.csv` and `data/inputs/changed_files.csv`
support the raw-alert filter and changed-file analyses. The latter contains
only PR identities and changed paths, not source code or PR text.

The public RQ3 reference join now includes all three tier flags, rule tags,
before/head commits, file paths, and head-side hunk coordinates. The primary
tier contains 420 raw / 114 confirmed references; the higher-severity tier
(`quality_strict_reference`) contains 151 / 40; the broad tier contains 535 / 187.
The historical `strict_` JSON summary keys are not this higher-severity tier.
Hunk coordinates describe the frozen eligibility decision; rebuilding hunks
from source still requires the public revisions and patches.

`final_human_confirmed_supplementary_robustness_20260907_v2` contains the
RQ1 unused-rule exclusions and RQ2 Top-1/Top-5 exclusions. Shared-repository
inference remains unvalidated and is not robustness evidence. Source excerpts
for the representative cases are provided in `representative_cases.json`.

The human severity summary was corrected on 2026-09-08 from obsolete `unknown`
rows using the released final alert metadata. This changes no human labels,
primary model results, or AI severity results reported in the paper.
