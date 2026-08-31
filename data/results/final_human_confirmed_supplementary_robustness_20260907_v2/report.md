# Final-label supplementary analyses

Post-hoc exploratory analyses; no manuscript, primary outcome, root-cause label, or frozen result was changed.

## Root-cause explanatory increment

Of 53 CodeQL rules, 8 span multiple primary categories and 10 span multiple finer mechanisms. Crosswalk rows count unique clusters within each cell; their sum is not a count of independent clusters across rules.

| Filter | Remaining alerts | Remaining clusters | Incomplete coordination |
|---|---:|---:|---:|
| baseline | 775 | 412 | 257 (62.38%) |
| exclude_js_unused_local | 472 | 224 | 80 (35.71%) |
| exclude_two_unused_rules | 360 | 161 | 19 (11.80%) |
| exclude_two_unused_drop_touched_auxiliary | 352 | 156 | 17 (10.90%) |

The frozen five categories and cluster assignments are retained. In the main filters, a cross-rule cluster remains if any nonexcluded alert remains. The drop-touched row is an auxiliary boundary check, not the main filtering convention.

The full-set dominance is sensitive to the two named unused rules. These results do not support treating the full-set category distribution as detector-independent.

Representative same-rule cases and exact source excerpts are in `representative_cases.json`; the qualitative assignments come from the existing frozen codebook and coding, not from this script.

## RQ2: final-human-label robustness

The Top 1 and Top 5 exclusions are selected by pooled AI + human final-confirmed Quality alert counts, with lexical rule-ID tie breaking:

1. `js/unused-local-variable`: 1007 (303 AI; 704 human).
2. `py/unused-import`: 265 (112 AI; 153 human).
3. `js/automatic-semicolon-insertion`: 196 (16 AI; 180 human).
4. `py/unused-local-variable`: 76 (44 AI; 32 human).
5. `java/deprecated-call`: 68 (66 AI; 2 human).

Rule exclusions retain the full PR roster and rebuild the binary outcome. Shared repositories are selected by the presence of both authorship groups, not outcomes. The shared analysis standardizes over its own subset and is not a within-repository fixed-effect estimate.

Model: logistic GEE, exchangeable repository correlation, robust sandwich covariance, unit weights.

```text
introduced_quality_any ~ ai * C(task_type, Treatment(reference='fix')) + log1p_changed_kloc + C(repo_language)
```

Size = log1p((PR-wide GitHub additions + deletions)/1000). Each fit is standardized over its own pooled PR population. Intervals use the unchanged primary helper, 2,000 paired coefficient draws (seed 20260623), and percentile limits. No multiplicity-adjusted confirmatory claims are made.

| Analysis | AI positive / PRs | Human positive / PRs | Adjusted AI − human, pp (95% CI) | Diagnostic |
|---|---:|---:|---:|---|
| baseline | 251/3087 | 264/2317 | -0.94 (-3.36, 1.10) | ok |
| exclude_top1 | 140/3087 | 154/2317 | -0.66 (-2.46, 0.94) | ok |
| exclude_top5 | 91/3087 | 101/2317 | -0.42 (-1.79, 0.68) | ok |
| shared_repositories | 188/2318 | 246/2159 | -1.03; CI not validated | inference_not_validated |

Baseline reproduction: 60 numbers matched within 0 (tolerance 1e-8).

The shared subset has an all-zero Go outcome stratum. Numerical convergence alone does not establish regular coefficient inference; its Go coefficient is a boundary diagnostic, not an interpretable finite log-odds estimate. No Go PRs were silently removed. Tightening the convergence tolerance produced non-positive-semidefinite robust covariance in two checks. The default-fit interval is retained below as a diagnostic only, NOT as validated robustness evidence. All numerical checks, including failed fits, are retained below.

| Shared-repository numerical check | Status | Go coefficient | Overall RD, pp | 95% CI, pp |
|---|---|---:|---:|---:|
| default_1e-6 | boundary_caution | -33.0782317044079 | -1.027124 | -3.4301, 1.1683 |
| default_1e-8 | suppressed_fit_or_inference_error | -36.078231703876824 | -1.027124 | suppressed |
| default_1e-10 | suppressed_fit_or_inference_error | -38.078231703869854 | -1.027124 | suppressed |
| start_Go_minus10 | boundary_caution | -23.933702222253892 | -1.027124 | -3.4376, 1.1699 |
| start_Go_minus20 | boundary_caution | -32.933648551683724 | -1.027124 | -3.4336, 1.1689 |

A small estimate or an interval including zero is not evidence of equivalence or causality. Rule-filtered analyses change the outcome; restricting repositories also changes the target population. Stable point estimates under numerical checks do not remove the shared subset's zero-event-stratum limitation.

## Artifacts

`analysis_manifest.json` records the protocol, input/output hashes, package versions and unchanged manuscript hashes. CSV files contain full category distributions, crosswalks, partial-cluster membership, PR outcomes, sample profiles, coefficients, standardized effects, and fit diagnostics.
