# Full-cohort RQ1/RQ2 alert sensitivities

## Analysis policy

- Outcome denominator: **5,404 PRs** (AI 3,087; Human 2,317).
- Every quality-gated PR has unit weight and remains in every available alert-filter sensitivity.
- No PR matching, trimming, propensity score, weighting, common-support screening, outcome imputation, or outcome model is used.
- Failed scans are reported only in descriptive attrition and are never coded as zero-alert PRs.
- Quality and Security alerts are classified and reported separately.

## Alert input conservation

| group | family | denominator_pr_n | expected_introduced_alert_n | observed_introduced_alert_n | count_conservation |
| --- | --- | --- | --- | --- | --- |
| ai | quality | 3087 | 2506 | 2506 | true |
| ai | security | 3087 | 245 | 245 | true |
| human | quality | 2317 | 4102 | 4102 | true |
| human | security | 2317 | 271 | 271 | true |

## Main sensitivity summaries

| family | sensitivity_id | group | denominator_pr_n | positive_pr_n | positive_pr_percent | introduced_alert_n | available |
| --- | --- | --- | --- | --- | --- | --- | --- |
| quality | baseline | ai | 3087 | 429 | 13.90 | 2506 | true |
| quality | baseline | human | 2317 | 433 | 18.69 | 4102 | true |
| security | baseline | ai | 3087 | 78 | 2.53 | 245 | true |
| security | baseline | human | 2317 | 95 | 4.10 | 271 | true |
| quality | exclude_pooled_top1_quality_rules | ai | 3087 | 307 | 9.94 | 2151 | true |
| quality | exclude_pooled_top1_quality_rules | human | 2317 | 312 | 13.47 | 3167 | true |
| quality | exclude_pooled_top5_quality_rules | ai | 3087 | 259 | 8.39 | 1692 | true |
| quality | exclude_pooled_top5_quality_rules | human | 2317 | 258 | 11.14 | 2014 | true |
| quality | precision_high_or_very_high | ai | 3087 | 409 | 13.25 | 2272 | true |
| quality | precision_high_or_very_high | human | 2317 | 420 | 18.13 | 3899 | true |
| security | precision_high_or_very_high | ai | 3087 | 49 | 1.59 | 103 | true |
| security | precision_high_or_very_high | human | 2317 | 53 | 2.29 | 108 | true |
| quality | problem_severity_error_or_warning | ai | 3087 | 153 | 4.96 | 631 | true |
| quality | problem_severity_error_or_warning | human | 2317 | 165 | 7.12 | 1728 | true |
| security | problem_severity_error_or_warning | ai | 3087 | 78 | 2.53 | 245 | true |
| security | problem_severity_error_or_warning | human | 2317 | 95 | 4.10 | 271 | true |
| quality | location_production_only | ai | 3087 | 358 | 11.60 | 1970 | true |
| quality | location_production_only | human | 2317 | 378 | 16.31 | 2646 | true |
| security | location_production_only | ai | 3087 | 70 | 2.27 | 212 | true |
| security | location_production_only | human | 2317 | 90 | 3.88 | 242 | true |
| quality | location_changed_file_only | ai | 3087 | 350 | 11.34 | 1121 | true |
| quality | location_changed_file_only | human | 2317 | 348 | 15.02 | 2892 | true |
| security | location_changed_file_only | ai | 3087 | 61 | 1.98 | 182 | true |
| security | location_changed_file_only | human | 2317 | 74 | 3.19 | 179 | true |

## Pooled full-cohort Quality rule ranking

| rank | rule_id | introduced_alert_n | affected_pr_n | alert_percent |
| --- | --- | --- | --- | --- |
| 1 | js/unused-local-variable | 1290 | 315 | 19.52 |
| 2 | js/useless-expression | 593 | 17 | 8.97 |
| 3 | js/automatic-semicolon-insertion | 388 | 65 | 5.87 |
| 4 | py/unused-import | 325 | 115 | 4.92 |
| 5 | java/missing-override-annotation | 306 | 12 | 4.63 |
| 6 | js/useless-assignment-to-local | 266 | 31 | 4.03 |
| 7 | java/deprecated-call | 231 | 8 | 3.50 |
| 8 | cpp/unused-static-variable | 226 | 33 | 3.42 |
| 9 | py/cyclic-import | 199 | 50 | 3.01 |
| 10 | py/unsafe-cyclic-import | 197 | 46 | 2.98 |

## Descriptive scan attrition

| group | stage | pr_n | percent_of_candidate_pool | role |
| --- | --- | --- | --- | --- |
| ai | candidate_pool | 3376 | 100.00 | descriptive attrition only |
| ai | paired_scan_success | 3096 | 91.71 | descriptive attrition only |
| ai | quality_gated_analysis | 3087 | 91.44 | outcome denominator |
| ai | scan_not_successful | 280 | 8.29 | descriptive attrition only |
| ai | post_scan_nonfailure_excluded | 9 | 0.27 | descriptive attrition only |
| human | candidate_pool | 2446 | 100.00 | descriptive attrition only |
| human | paired_scan_success | 2325 | 95.05 | descriptive attrition only |
| human | quality_gated_analysis | 2317 | 94.73 | outcome denominator |
| human | scan_not_successful | 121 | 4.95 | descriptive attrition only |
| human | post_scan_nonfailure_excluded | 8 | 0.33 | descriptive attrition only |

## RQ1 AI-only alerts per changed KLOC

Each rate is the introduced-alert total divided by the sum of `changed_kloc` across all AI quality-gated PRs in the stratum. Zero-alert and zero-changed-KLOC PRs remain in the stratum; this is not the mean of per-PR ratios.

| family | dimension | stratum | pr_n | zero_changed_kloc_pr_n | changed_kloc_total | introduced_alert_n | alerts_per_changed_kloc |
| --- | --- | --- | --- | --- | --- | --- | --- |
| quality | all | all | 3087 | 2 | 1154.07 | 2506 | 2.17 |
| security | all | all | 3087 | 2 | 1154.07 | 245 | 0.21 |
| quality | task_type | feat | 1353 | 0 | 779.21 | 1540 | 1.98 |
| security | task_type | feat | 1353 | 0 | 779.21 | 160 | 0.21 |
| quality | task_type | fix | 1427 | 1 | 194.25 | 695 | 3.58 |
| security | task_type | fix | 1427 | 1 | 194.25 | 56 | 0.29 |
| quality | task_type | refactor | 307 | 1 | 180.61 | 271 | 1.50 |
| security | task_type | refactor | 307 | 1 | 180.61 | 29 | 0.16 |
| quality | repo_language | C | 48 | 0 | 6.51 | 245 | 37.63 |
| security | repo_language | C | 48 | 0 | 6.51 | 1 | 0.15 |
| quality | repo_language | C++ | 97 | 0 | 52.19 | 317 | 6.07 |
| security | repo_language | C++ | 97 | 0 | 52.19 | 3 | 0.06 |
| quality | repo_language | Go | 274 | 0 | 65.80 | 0 | 0.00 |
| security | repo_language | Go | 274 | 0 | 65.80 | 4 | 0.06 |
| quality | repo_language | Java | 89 | 0 | 35.86 | 595 | 16.59 |
| security | repo_language | Java | 89 | 0 | 35.86 | 39 | 1.09 |
| quality | repo_language | JavaScript | 149 | 0 | 22.70 | 65 | 2.86 |
| security | repo_language | JavaScript | 149 | 0 | 22.70 | 20 | 0.88 |
| quality | repo_language | Python | 750 | 0 | 221.49 | 798 | 3.60 |
| security | repo_language | Python | 750 | 0 | 221.49 | 36 | 0.16 |
| quality | repo_language | Ruby | 70 | 0 | 74.49 | 33 | 0.44 |
| security | repo_language | Ruby | 70 | 0 | 74.49 | 7 | 0.09 |
| quality | repo_language | TypeScript | 1610 | 2 | 675.02 | 453 | 0.67 |
| security | repo_language | TypeScript | 1610 | 2 | 675.02 | 135 | 0.20 |

## Supported language strata

Support requires at least 50 PRs and at least 5 positive PRs in each authorship group, evaluated separately by outcome family.

| family | repo_language | group | denominator_pr_n | positive_pr_n | positive_pr_percent | introduced_alert_n | sparse_flag |
| --- | --- | --- | --- | --- | --- | --- | --- |
| quality | C++ | ai | 97 | 23 | 23.71 | 317 | false |
| quality | C++ | human | 65 | 20 | 30.77 | 240 | false |
| quality | Java | ai | 89 | 18 | 20.22 | 595 | false |
| quality | Java | human | 71 | 17 | 23.94 | 177 | false |
| quality | JavaScript | ai | 149 | 22 | 14.77 | 65 | false |
| quality | JavaScript | human | 143 | 28 | 19.58 | 312 | false |
| quality | Python | ai | 750 | 173 | 23.07 | 798 | false |
| quality | Python | human | 599 | 157 | 26.21 | 743 | false |
| quality | TypeScript | ai | 1610 | 164 | 10.19 | 453 | false |
| quality | TypeScript | human | 1230 | 188 | 15.28 | 2344 | false |
| security | Python | ai | 750 | 10 | 1.33 | 36 | false |
| security | Python | human | 599 | 11 | 1.84 | 25 | false |
| security | TypeScript | ai | 1610 | 48 | 2.98 | 135 | false |
| security | TypeScript | human | 1230 | 69 | 5.61 | 196 | false |

All supported and sparse strata are retained in `language_strata.csv`; sparse strata are descriptive and must not be extrapolated.

## Field availability

| sensitivity | available | field_or_source | detail |
| --- | --- | --- | --- |
| family_separation | true | is_quality_alert + is_security_alert | mutually exclusive flags required for every included alert |
| precision | true | precision | enhanced alert metadata |
| problem_severity | true | problem_severity | enhanced alert metadata |
| production_only | true | location_class or derived from file_path | <ARTIFACT_ROOT>/config/study/pr_enrichment_rules.json |
| changed_file_only | true | group + repo_name + pr_number + normalized file_path | Deterministic exact path join after slash/dot normalization; path case is preserved. Every eligible alert is classifiable. Incomplete file-list PRs may remain in the full denominator only when they have no introduced alerts. |

## Changed-file join audit

| group | source | denominator_pr_n | complete_file_list_pr_n | incomplete_file_list_pr_n | eligible_alert_n | changed_file_alert_n | not_changed_file_alert_n | unclassifiable_alert_n |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ai | pr_file_path_join | 3087 | 3086 | 1 | 2751 | 1303 | 1448 | 0 |
| human | pr_file_path_join | 2317 | 2317 | 0 | 4373 | 3071 | 1302 | 0 |
