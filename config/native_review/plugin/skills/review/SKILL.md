---
name: review
description: Review the pending PR using the frozen quality scope and root-cause checks; use before code-review.
---

You are participating in a blinded empirical study of pull-request review.

Use the built-in /code-review workflow to review the complete pending Git diff
in the current repository. The repository contains one neutral baseline commit
and the pull-request change as uncommitted modifications. Review only this
local change and the surrounding local source needed to understand it.

Identify concrete software-quality or security issues introduced by the
pending change. Quality issues include correctness, reliability,
maintainability, performance-efficiency, and portability problems. Report an
issue only when the changed code provides specific evidence; avoid generic
best-practice advice.

Do not:
- infer whether the change was authored by AI or a human;
- look for repository, pull-request, author, or review metadata;
- use the network, a remote, prior reviews, CodeQL/SARIF output, or hidden
  reference alerts;
- edit files, apply fixes, create commits, or change Git state.

Prefer the built-in /code-review ReportFindings mechanism. Use a repo-relative
changed-file path and a changed-file line number when available. The summary
and failure scenario must state the concrete issue and its code evidence.
For behavioral issues, describe the triggering inputs or state. For
maintainability issues, describe the non-behavioral condition and why it
is a meaningful issue in this repository; a runtime failure is not required. If no concrete issue survives review, submit
an empty findings list.

If the client-side ReportFindings tool is unavailable, return exactly one
fenced `json` block and no prose or other fenced block. Its body must be one
JSON array of native finding objects. Each object requires `file`, `summary`,
and `failure_scenario`, and may include a positive integer `line`. Omit `line`
when unavailable, and use `[]` for no findings. This fallback is a transport
representation of the same /code-review result, not a request for additional
analysis.

# Quality review scope

Review the complete pending change and the surrounding source needed to assess it.
Use the existing code-review workflow and its permitted read-only tools.

Include correctness, reliability, maintainability, performance, portability, and
security issues. A meaningful maintainability issue need not cause a runtime
failure. Report a specific condition supported by the before and after code,
not a personal style preference or generic best-practice recommendation.

For each candidate, establish that the condition exists in the final code, that
the pending change introduced it, and why it is an issue in this repository.
Do not report a pre-existing condition merely because its location changed.
Inspect context that could invalidate the candidate before reporting it.

Use the caller's finding schema. In `failure_scenario`, describe either the
inputs or state that cause incorrect behavior, or the concrete non-behavioral
quality condition and its repository-specific consequence. Do not invent a
runtime failure for a maintainability issue. Give a relevant source location
when available; do not invent an edited-line location to satisfy the format.

Do not access detector outputs, reference labels, prior reviews, or authorship
metadata. Do not modify source files or execute the project. An empty finding
list is valid. Do not aim for a particular finding count or category balance.

# Root-cause-guided inspection

Apply the generic quality-review scope supplied by the caller. Use the following
checks where the diff makes them relevant; do not force a finding in each category.
The categories guide inspection, not the final report format.

## Incomplete change coordination

For added definitions, imports, or bindings, locate their intended uses and check
whether the final code connects them to those uses. For removed or replaced
implementations, inspect remaining imports, references, and dependent sites.
Follow affected callers beyond the edited lines. Check for dynamic use, exports,
registration, or other repository conventions before treating an element as unused.

## Redundant or locally inconsistent construction

Inspect adjacent and related operations for duplication, contradictory local
choices, or values overwritten before use. Establish which operation has no
effect or conflicts with another. Distinguish intentional repeated work from
redundancy using the surrounding source and observable effects.

## Control-, state-, or data-flow miscomposition

Trace feasible branches from initialization to use. Check whether changed
conditions, early returns, and assignment order leave a value unavailable,
make a branch unreachable, or cause the wrong value to reach a use. Account for
guards and exceptional paths rather than relying on textual proximity alone.

## Dependency, error, or resource mismanagement

Inspect changed dependency use and the paths through acquisition, failure, and
cleanup. Check whether resources can be released before acquisition or left
unreleased, and whether exceptions are handled at the appropriate boundary.
Use the local ownership and error-handling conventions to assess each candidate.

## Interface or contract mismatch

Compare changed calls and implementations with available declarations and API
contracts. Check argument meanings, return-value assumptions, and compatibility
requirements. Do not infer an API violation from a name or deprecation marker
without establishing its relevance to the actual usage and repository context.

Before reporting, connect the change action to the affected code relation or
constraint and the resulting condition. Describe code evidence, not guesses
about what an AI or developer forgot or misunderstood. Merge duplicate reports
of the same underlying condition; retain distinct conditions even if they occur
on the same line. Do not include category frequencies, known benchmark answers,
or identifiers from development cases in the review.
