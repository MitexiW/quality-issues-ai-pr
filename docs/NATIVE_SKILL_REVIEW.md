# Root-cause-guided review experiment

The authors ran a native review Skill on the same 267 PRs as RQ3. The final
outputs contain 1,484 findings. Human semantic assessment is complete.
Primary recovery was 21/114 (18.42%) for default review and 32/114 (28.07%)
for the RQ1-guided configuration. Broad-tier recovery was 37/187 (19.79%)
and 53/187 (28.34%). The 114 references remain primary; the 187-reference
set supports secondary root-cause analysis.

## Released data

`data/results/native_skill_review/review_index.csv` maps PRs to final responses
in `reviews/<case_id>/review_response.json`. Each case also includes a Skill
loading audit. We selected the first valid completed review in original/retry
order: 228 from the original run, 16 from retry 1, 22 from retry 2 and one from
retry 3. We did not select reviews based on finding content or reference recovery.

The experiment used `deepseek-v4-pro[1m]`. The index also includes the
requested and reported model fields from the execution records.

We exclude raw SDK conversations, session identifiers, host paths, credentials
and worktree source from the public export. The release includes final outputs,
not the complete history of unsuccessful calls.

Recompute the counts without calling a model:

```bash
python scripts/summarize_native_skill_reviews.py
```

## Reproduce the human-confirmed comparison

`data/results/native_skill_review/human_assessment/` contains the final
finding-level relations, matched reference IDs, baseline reference outcomes,
tier flags, and the frozen root-cause mapping. Reviewer names, timestamps and
free-text notes are omitted. `analysis/` contains the reported comparison tables.

```bash
python scripts/analyze_native_skill_recovery.py
```

This reads the released review responses and human labels, checks complete
finding coverage and within-PR matches, deduplicates matched references, and
writes three CSVs to `outputs/native-skill-recovery/`: reference-level outcomes,
primary/broad and AI/human summaries, and root-cause comparisons. No model calls,
confidence intervals or significance tests are involved. Reruns overwrite these
three generated CSVs; released inputs remain unchanged.

For the primary set, both settings recovered 14 references, guided review alone
recovered 18, default alone recovered seven, and neither recovered 75. Broad-tier
counts are 28, 25, nine and 125, respectively. Root-cause counts reproduce the
paper's Default/Guided/Difference table and the supplementary breakdowns.

Both settings used the same model, reasoning effort, reviewed PRs and repository
context. The follow-up added an explicit Quality scope and RQ1 root-cause checks.
Both released datasets include successful reruns of failed calls. The default
dataset now contains 267 valid reviews; see [DEFAULT_REVIEW.md](DEFAULT_REVIEW.md).
Guided review reported more findings (1,484 versus 1,106).
The added Quality instructions, reporting volume and within-study sample
prevent isolating the causal effect of root-cause checks. The reference inventory
is incomplete as a defect oracle, so unmatched findings do not establish precision.

## Rerun the reviewer

Install `requirements-full.txt` and prepare the historical PR worktrees using
[RQ3_REVIEW.md, Section 1](RQ3_REVIEW.md). Use the same recorded base/head commits.
The reviewer must not receive CodeQL alerts, human labels or authorship metadata.

The experiment used Claude Agent SDK 0.2.128 and bundled Claude Code CLI 2.1.220,
maximum effort. It dispatched
`/code-review` as a user command and required the native `rq3-quality:review`
Skill before code inspection. The plugin and exact launch prompt are in
`config/native_review/`. The runner verifies Skill loading through tool hooks.
The released configuration records the execution parameters needed for reruns.

The public batch launcher is a portable rerun convenience script. It preserves
the experiment's single-case review behavior but does not recreate the original
machine-specific retry directory layout.

Test one prepared PR without a paid call:

```bash
python scripts/run_native_skill_reviews.py \
  --worktree-root outputs/rq3-worktrees \
  --output outputs/native-skill-review --limit 1 --workers 1
```

Set `RQ3_API_KEY` in your shell without putting it in a command argument or file.
Run one paid validation case by adding `--execute --accept-api-charges`.
After checking its Skill audit, run all 267 PRs:

```bash
nohup python -u scripts/run_native_skill_reviews.py \
  --worktree-root outputs/rq3-worktrees \
  --output outputs/native-skill-review --workers 4 \
  --execute --accept-api-charges > outputs/native-skill-review.log 2>&1 &
```

The launcher skips existing valid results and continues after case failures.
Repeat with `--retry-failed` to retry completed failures in new attempt directories.
Inspect interrupted attempts before continuing; do not run two experiments on
the same worktrees at once. API calls incur charges without an SDK dollar cap.
Use provider-side spending controls if needed. Historical model availability
and future responses may differ.

Keep new outputs separate from released data. Use the semantic matching and
human-adjudication procedure in RQ3_REVIEW.md to evaluate them; location matches
or candidate counts alone do not establish recovery.

## Assess and score a new run

Prepare a bundle after all selected cases have valid completed reviews:

```bash
python scripts/prepare_native_skill_assessment.py \
  --run-dir outputs/native-skill-review \
  --cases data/results/rq3_formal_plan_20260727_v1/formal_cases.csv \
  --references data/results/final_human_confirmed_rq3_20260817_v1/reference_adjudication_join_public.csv \
  --root-cause-mapping data/results/native_skill_review/human_assessment/root_cause_mapping.csv \
  --output outputs/native-skill-assessment
```

This example compares a new guided run on the historical PRs with the frozen
default baseline. To compare two new runs or a new PR sample, explicitly supply
that sample's validated reference CSV, its newly adjudicated baseline
`semantic_recovered` flags, and its root-cause mapping. Do not reuse baseline
recovery flags when reporting a new default run. The reference CSV must include
`case_id`, `reference_id`, `group`, `validated_issue_reference`,
`quality_broad_reference`, `quality_primary_reference`, `semantic_recovered`,
and code-location/rule evidence for human inspection.

The preparer rejects missing valid cases and unresolved attempts. It selects the
first valid, Skill-verified attempt in retry order, independently of its findings,
and creates the index/response structure accepted by the scorer. Use a new output
directory to avoid overwriting judgments. View `assessment.html` or
`assessment_packets.json` alongside the original diff and repository worktree;
neither packet includes baseline recovery labels. The HTML is a read-only view,
not an annotation server.

Edit `human_assessment/human_decisions.json`, filling one decision per finding:

- `same_issue`: the finding describes the same underlying condition; provide
  one or more `matched_reference_ids` from that PR.
- `related_distinct`: related code but a different issue; leave IDs empty.
- `no_match`: no matching condition in the supplied references; leave IDs empty.
- `no_reference`: the PR has no confirmed broad-tier references; leave IDs empty.

Do not infer matches from identical lines alone. Leave uncertain judgments blank
until resolved; the scorer rejects incomplete labels. Saving the JSON replaces
its contents; no label history or reviewer identity is required.

```bash
python scripts/analyze_native_skill_recovery.py \
  --results outputs/native-skill-assessment \
  --output outputs/new-native-skill-recovery
```

The scorer validates full finding coverage, matching IDs and PR membership, then
deduplicates references and computes primary/broad, authorship and root-cause
tables plus paired counts. It never fills new judgments from published labels.
