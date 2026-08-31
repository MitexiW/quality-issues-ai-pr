# Blind LLM Quality and Security Alert-Recovery Protocol

Version: 1.5.0
Status: 267-case single-review design frozen before formal model output; 267/267 exact-worktree technical preflights passed

## 1. Measurement target

RQ3 asks whether a versioned Claude Code reviewer can recover CodeQL-detectable
issues from an isolated base-to-head PR change when CodeQL output and prior
review comments are hidden. The reviewer is executed with the Claude Agent SDK,
formerly named the Claude Code SDK.

Introduced CodeQL alerts form the frozen **reference set**. Therefore:

- “recovered” means matched to a hidden CodeQL alert;
- recovery is not proof that the model detected a true defect or vulnerability;
- an unmatched model report is recorded as `unmatched_to_codeql`;
- the study does not report true precision without independent semantic
  adjudication.

Quality and Security are sampled and reported separately. Quality is the primary
family; Security is secondary.

## 2. Cases and controls

A primary positive case is a quality-gated merged PR with at least one
introduced CodeQL Quality alert after the frozen actionability filters.

- Quality primary references require high/very-high CodeQL precision, a
  production changed-file location visible in a unique new-side diff hunk, and
  a rule not tagged `useless-code`. Recommendation severity remains eligible.
- The strict sensitivity additionally requires `problem_severity` warning or
  error. The broad sensitivity restores high/very-high `useless-code`
  references. All tiers reuse the same whole-PR model output.
- Security positives use numeric `security-severity` and retain CWE metadata.
- The primary benchmark requires a changed production file and a reference
  location visible in a unique new-side diff hunk supplied to the model.
- Broader all-path and lower-actionability samples are sensitivity analyses.

A control passes the same scan and metadata gates but has zero introduced
CodeQL Quality alerts under the frozen RQ1/RQ2 outcome. “Control” means
CodeQL-negative for introduced Quality, not issue-free.

The formal benchmark contains all 187 primary-positive PRs (95 AI and 92
Human) plus 80 controls (40 per group), for 267 planned cases before the exact
worktree gate. Controls are selected without inspecting model output:

1. authorship group and task type exactly;
2. preserve the positive task/language mix through deterministic anchor
   selection;
3. prefer the same repository;
4. prefer the same CodeQL database language;
5. minimize `log1p(Changed_KLOC)` and merge-quarter distance.

The historical 40-PR packet pilot is archived as infrastructure provenance and
is not the formal sample design. Paid Flash/Pro infrastructure cases remain
ineligible for performance estimates. No formal case is selected, replaced, or
retried based on observed findings or recovery.

## 3. Blinding and leakage prevention

Each review runs in a separately reconstructed local Git worktree. The worktree
contains the tracked before snapshot as one neutral base commit and the complete
head-snapshot difference as staged pending changes. The neutral base tree and staged
head tree must match the worktree manifest, the changed-file count must be conserved,
and no unstaged or untracked change is permitted. The serialized `git diff --binary`
hash is retained for audit but is not a content-identity gate because Git may choose
different equivalent binary-delta encodings for the same two trees. A tracked absolute
symlink may be replaced in both snapshots by the same deterministic dangling
relative link only when its path and literal target are invariant across the PR;
the original target hash and original trees are recorded. GitHub
per-file patch text is provenance only. Remote URLs, original Git authorship/history, PR
number, group, agent, case/control status, target family, existing human/bot
review comments, SARIF, CodeQL results, rule IDs, CWE identifiers, and hidden
alert locations are unavailable to the reviewer. A randomized case identifier
links the isolated worktree to a separately stored key.

Literal CWE identifiers and references to CodeQL/SARIF are redacted from model
instructions. Authorship, family, case/control status, repository/PR identity,
and reference alerts remain only in a separate key unavailable to the reviewer.

This is metadata blinding, not semantic rewriting. Repository names embedded
in source files and identifiers such as AI SDK or model names that are needed
to understand the change are retained. Residual repository or authorship cues
in code are therefore a validity threat.

## 4. Review workspace and scope

The Claude Code `/code-review` workflow reviews the complete pending Git diff
inside the isolated worktree and may inspect surrounding repository files with
read-only tools. One PR and one repetition form one model invocation. We do not
split a PR into packet-level model invocations, because that would no longer
measure the selected whole-change review workflow.

Workspace construction records hashes of the reviewer-visible before tree, staged
head tree, serialized pending diff,
sanitized worktree manifest, SDK package, bundled Claude Code CLI, prompt, and
review configuration. A PR that cannot be reconstructed or reviewed within the
frozen limits is technical RQ3 attrition, not a negative review. Escaping links,
changed absolute links, missing partial-clone objects, untracked files, and
unexplained before/head tree mismatches are rejected before model execution.

## 5. Models and execution

The selected reviewer is the local `/code-review` workflow invoked through the
Python Claude Agent SDK. The GitHub-oriented `/review <PR>` command is
prohibited because it exposes PR identity, and `/code-review ultra` and the
managed GitHub Code Review service are prohibited because they use a different
remote multi-agent execution surface.

The current environment contains `claude-agent-sdk==0.2.128` with bundled
Claude Code CLI `2.1.220`. The inference provider is frozen as the official
DeepSeek Anthropic-compatible endpoint. Claude Code requests
`deepseek-v4-pro[1m]`, which resolves to the `deepseek-v4-pro` backend, at
effort `max`. The one-case audited-worktree smoke and provider-aware runner
dry-run preflight passed without a model call. All 267 planned cases subsequently
passed the offline audited-worktree preflight without reading the API key or calling
the model. The repetition
count is frozen at one; per-review and total budgets and the provider-side
spend guard remain execution gates. DeepSeek's official
compatibility table states that only `effort` is supported under
`output_config`; `output_config.format` is not supported. Bundled Claude Code
CLI `2.1.220` exposes the typed, read-only `ReportFindings` tool for the local
`/code-review` workflow, but the frozen DeepSeek backend did not issue this
client-side tool in either the Pro or Flash infrastructure call. The preferred
response is exactly one such tool call. If it is absent, the DeepSeek adapter
accepts exactly one fenced `json` block and no other fenced blocks, and its body
must be one JSON array containing the same native finding objects. It validates
all native fields, permits an empty array, and requires each final normalized
path to be present in the pending diff. An absolute path is normalized only
when it resolves below the audited worktree. It performs no JSON repair,
substring search, field synthesis, semantic-label synthesis, or manual
rewriting.
This RQ evaluates that versioned workflow/model
combination rather than comparing model families. Each run records:

Corrected adapter and end-to-end infrastructure smoke runs use
`deepseek-v4-flash` to limit engineering cost. They are permanently excluded
from RQ3 recovery estimates and serve only to validate reporting, artifacts,
recording, matching, resume behavior, and accounting. The planned formal
reviewer remains `deepseek-v4-pro[1m]` resolving to `deepseek-v4-pro`.

- provider and full model identifier;
- Claude Agent SDK and bundled Claude Code CLI versions;
- local review command and effort level;
- access date and model-version information available from the provider;
- system prompt, user prompt, native report contract, and their hashes;
- the original Draft 2020-12 schema hash and provider-specific response
  contract; the CLI-compatible schema hash and deterministic compatibility
  transform are recorded only for providers that receive the CLI schema;
- temperature, seed when supported, and repetition identifier;
- input/output token counts, latency, cost snapshot, errors, and retry count;
- immutable raw response, response source, and validated native tool input.

An absent tool call is not itself a failure when the strict DeepSeek inline
contract passes. Repeated tool calls, an invalid tool payload, multiple fenced
blocks, an invalid fenced array, or neither accepted response form may be
retried only under the manifest rule. An invalid attempt
followed by one valid attempt is one completed invocation; more than one valid
response for the same invocation is an error. Model answers are never manually
rewritten. The incremental SDK message stream, complete raw SDK transcript,
tool-use trace, result metadata, and validated review output are retained even
when result parsing or schema validation fails. Expected invocations come from
the frozen run plan rather than being inferred from whatever output files
happen to exist.

A successful provider call that violates both accepted response forms is a
reviewer outcome, not technical attrition. It remains in the case denominator,
is marked `model_output_valid=false`, receives zero reference recoveries, and is
reported separately in the invalid-output rate. Its prose is not interpreted
and no empty finding array is synthesized. Such a case is never retried.

## 6. Native review output

Each DeepSeek-backed local `/code-review` result is represented as the validated
input of one typed `ReportFindings` call or as one strictly extracted fenced JSON
array containing the same native finding objects. Every stored finding contains
a safe repo-relative path, an optional one-indexed line, a concise defect
summary, and a concrete failure scenario. The prompt requires a changed-file
path, but a reviewer violation is retained as an unmatched outcome and separately
flagged as outside-diff or nonexistent rather than converted into technical
attrition. The CLI may additionally report a
short summary, generic category, or verification verdict. The model may submit
an empty finding list.

The native tool does not require the model to declare the hidden benchmark
family, CodeQL category/CWE, severity, or remediation. Those fields are not
inferred from prose and are not added by the adapter. Family and rule metadata
are attached only after an automatic match to a hidden reference.

## 7. Frozen matching rules

The primary matcher is conservative and deterministic. Before case selection,
primary references must be unique within `(case, normalized path, head-side
alert interval)`; collocated references are excluded from the primary recovery
denominator and retained in an attrition table. A native report recovers a
reference alert only when:

1. normalized repo-relative paths agree;
2. the reported line overlaps the head-side alert interval; and
3. exactly one all-family hidden reference satisfies those location rules.

Duplicate model reports may recover a reference alert only once. Ambiguous
or unlocalized reports remain unmatched in the primary result. The matched
reference, rather than a post-hoc interpretation of model prose, determines
whether a recovery is target-family or off-target-family.

Final machine-readable states are:

- `compatible_location_recovery`;
- `off_target_reference_recovery`;
- `unmatched_to_codeql`;
- `ambiguous_location_candidate`;
- `invalid_or_unlocalized_report`.

## 8. Outcomes

Primary RQ3 outcomes (Quality only, equal PR weight):

- macro-average per-PR Quality reference-alert recovery;
- Quality PR-level hit rate among positive cases;
- Quality file and hunk/line localization accuracy;
- Quality AI--Human recovery difference.

Secondary RQ3 outcomes:

- the corresponding Security recovery, PR-hit, localization, and AI--Human
  difference estimates;
- unmatched reports per PR and per control PR;
- recovery by task, language, Quality category/CWE, and diff-size band;
- token use, latency, and estimated cost.

Repository-cluster bootstrap intervals are used for group and stratum contrasts.
Sparse strata remain descriptive. Results describe recovery under the frozen
model, prompt, packet, and matcher; they are not generalized to all LLM reviewers
or to all latent software defects.

The formal estimand is single-review performance on the frozen benchmark.
Cases have equal
weight: `selection_probability` and `sampling_weight` are sampling-provenance
fields and are not analysis weights. Reports and recoveries from the non-target
family are counted separately and never enter the target-family recovery
denominator or unmatched-report numerator.

## 9. Execution gate

Formal execution starts only after:

1. the Human scan and both-group SARIF rebuild reach the final snapshot;
2. the Quality taxonomy and actionability filters are frozen;
3. cases and controls are selected from that snapshot without model-output
   inspection;
4. pilot repairs are complete and pilot PRs are excluded;
5. inference provider, requested and resolved model IDs, SDK/CLI versions,
   local `/code-review` command, effort, prompt, schema, repetition count of
   one, and matcher manifests are frozen;
6. every isolated worktree passes remote/history leakage, patch-integrity,
   read-only-tool, and network-denial checks.

The immutable run preflight must additionally verify every worktree, patch,
prompt, schema, execution-config, and case-key hash; expand the full
case-by-repetition invocation grid; and show that its conservative worst-case
budget does not exceed the authorized cap. Because the one-case DeepSeek Flash
smoke reported USD 0.919738 despite an SDK `max_budget_usd` value of USD 0.25,
that SDK option is treated as metadata and a best-effort stop signal, not as a
hard custom-provider spending guard. Batch authorization additionally requires
a provider-side total-spend limit and an empirical token/cost envelope frozen
from excluded infrastructure or pilot calls.

The archived manual-validation sample is outside RQ3.
