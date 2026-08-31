# Introduced-only RQ1 profile

状态：**final**。本报告只包含 `ai` 组，不得在 Human 批次结束前作为 AI–Human 比较或论文最终结果。

## 数据门禁

- 门禁通过 PR：3,087
- 纳入 introduced alerts：854
- 因 PR 门禁排除的 alerts：1,468
- family 非法 alerts：0
- PR-level 与 alert-level 计数守恒：通过
- Quality：期望 775，观察 775
- Security：期望 79，观察 79

## 总体 introduced 分布

| family | pr_n | introduced_alert_n | affected_pr_n | affected_pr_percent | alerts_per_100_pr | median_per_pr | p95_per_pr | max_per_pr |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| quality | 3087 | 775 | 251 | 8.13 | 25.11 | 0.00 | 1.00 | 74 |
| security | 3087 | 79 | 27 | 0.87 | 2.56 | 0.00 | 0.00 | 20 |

## Repository-cluster 95% intervals

| family | metric | estimate | ci_low | ci_high | repository_n | bootstrap_replicates |
| --- | --- | --- | --- | --- | --- | --- |
| quality | affected_pr_percent | 8.13 | 6.52 | 9.89 | 536 | 2000 |
| quality | alerts_per_100_pr | 25.11 | 18.04 | 34.19 | 536 | 2000 |
| security | affected_pr_percent | 0.87 | 0.55 | 1.22 | 536 | 2000 |
| security | alerts_per_100_pr | 2.56 | 1.19 | 4.48 | 536 | 2000 |

## Task type

| stratum | family | pr_n | introduced_alert_n | affected_pr_n | affected_pr_percent | alerts_per_100_pr | p95_per_pr | max_per_pr |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| feat | quality | 1353 | 544 | 152 | 11.23 | 40.21 | 2.00 | 74 |
| feat | security | 1353 | 59 | 18 | 1.33 | 4.36 | 0.00 | 20 |
| fix | quality | 1427 | 146 | 69 | 4.84 | 10.23 | 0.00 | 10 |
| fix | security | 1427 | 16 | 8 | 0.56 | 1.12 | 0.00 | 7 |
| refactor | quality | 307 | 85 | 30 | 9.77 | 27.69 | 1.00 | 12 |
| refactor | security | 307 | 4 | 1 | 0.33 | 1.30 | 0.00 | 4 |

## Changed-code size bands

| stratum | family | pr_n | introduced_alert_n | affected_pr_n | affected_pr_percent | alerts_per_100_pr | max_per_pr |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 101_1000 | quality | 952 | 410 | 135 | 14.18 | 43.07 | 74 |
| 101_1000 | security | 952 | 29 | 13 | 1.37 | 3.05 | 7 |
| gt_1000 | quality | 171 | 239 | 62 | 36.26 | 139.77 | 36 |
| gt_1000 | security | 171 | 46 | 10 | 5.85 | 26.90 | 20 |
| le_100 | quality | 1964 | 126 | 54 | 2.75 | 6.42 | 11 |
| le_100 | security | 1964 | 4 | 4 | 0.20 | 0.20 | 1 |

The bands are a post-outcome descriptive extension (at most 100, 101--1,000, and more than 1,000 changed code lines), not an estimated threshold effect.

## CodeQL database language

| stratum | family | pr_n | introduced_alert_n | affected_pr_n | affected_pr_percent | alerts_per_100_pr |
| --- | --- | --- | --- | --- | --- | --- |
| C | quality | 48 | 6 | 2 | 4.17 | 12.50 |
| C | security | 48 | 0 | 0 | 0.00 | 0.00 |
| C++ | quality | 97 | 1 | 1 | 1.03 | 1.03 |
| C++ | security | 97 | 1 | 1 | 1.03 | 1.03 |
| Go | quality | 274 | 0 | 0 | 0.00 | 0.00 |
| Go | security | 274 | 0 | 0 | 0.00 | 0.00 |
| Java | quality | 89 | 91 | 8 | 8.99 | 102.25 |
| Java | security | 89 | 0 | 0 | 0.00 | 0.00 |
| JavaScript | quality | 149 | 21 | 9 | 6.04 | 14.09 |
| JavaScript | security | 149 | 0 | 0 | 0.00 | 0.00 |
| Python | quality | 750 | 296 | 94 | 12.53 | 39.47 |
| Python | security | 750 | 13 | 2 | 0.27 | 1.73 |
| Ruby | quality | 70 | 17 | 5 | 7.14 | 24.29 |
| Ruby | security | 70 | 1 | 1 | 1.43 | 1.43 |
| TypeScript | quality | 1610 | 343 | 132 | 8.20 | 21.30 |
| TypeScript | security | 1610 | 64 | 23 | 1.43 | 3.98 |

## Quality categories

| value | introduced_alert_n | affected_pr_n | alert_percent_within_family |
| --- | --- | --- | --- |
| maintainability | 632 | 219 | 81.55 |
| correctness_reliability | 135 | 54 | 17.42 |
| performance_efficiency | 8 | 4 | 1.03 |

## Alert locations

| family | value | introduced_alert_n | affected_pr_n | alert_percent_within_family |
| --- | --- | --- | --- | --- |
| quality | production | 613 | 194 | 79.10 |
| quality | test | 139 | 69 | 17.94 |
| quality | example | 15 | 6 | 1.94 |
| quality | docs | 5 | 4 | 0.65 |
| quality | build | 3 | 1 | 0.39 |
| security | production | 66 | 25 | 83.54 |
| security | example | 12 | 1 | 15.19 |
| security | test | 1 | 1 | 1.27 |

## Problem severity

| family | value | introduced_alert_n | affected_pr_n | alert_percent_within_family |
| --- | --- | --- | --- | --- |
| quality | recommendation | 639 | 216 | 82.45 |
| quality | warning | 95 | 48 | 12.26 |
| quality | error | 41 | 19 | 5.29 |
| security | error | 52 | 16 | 65.82 |
| security | warning | 27 | 17 | 34.18 |

## Zero-aware PR issue-count distribution

| family | issue_count_bin | pr_n | pr_percent | introduced_alert_n | alert_percent_within_family |
| --- | --- | --- | --- | --- | --- |
| quality | 0 | 2836 | 91.87 | 0 | 0.00 |
| quality | 1 | 129 | 4.18 | 129 | 16.65 |
| quality | 2_3 | 63 | 2.04 | 149 | 19.23 |
| quality | 4_10 | 50 | 1.62 | 294 | 37.94 |
| quality | gt_10 | 9 | 0.29 | 203 | 26.19 |
| security | 0 | 3060 | 99.13 | 0 | 0.00 |
| security | 1 | 16 | 0.52 | 16 | 20.25 |
| security | 2_3 | 6 | 0.19 | 16 | 20.25 |
| security | 4_10 | 3 | 0.10 | 15 | 18.99 |
| security | gt_10 | 2 | 0.06 | 32 | 40.51 |

## Positive-PR breadth

| family | metric | positive_pr_n | single_value_pr_n | single_value_pr_percent | median | p75 | p90 | p95 | max |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| quality | alerts | 251 | 129 | 51.39 | 1.00 | 3.00 | 6.00 | 10.00 | 74 |
| quality | rules | 251 | 209 | 83.27 | 1.00 | 1.00 | 2.00 | 3.00 | 5 |
| quality | categories | 251 | 226 | 90.04 | 1.00 | 1.00 | 1.00 | 2.00 | 3 |
| quality | files | 251 | 183 | 72.91 | 1.00 | 2.00 | 3.00 | 4.50 | 16 |
| security | alerts | 27 | 16 | 59.26 | 1.00 | 3.00 | 5.20 | 10.50 | 20 |
| security | rules | 27 | 19 | 70.37 | 1.00 | 2.00 | 2.00 | 2.70 | 3 |
| security | categories | 27 | 27 | 100.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1 |
| security | files | 27 | 22 | 81.48 | 1.00 | 1.00 | 2.00 | 2.00 | 4 |

## Rule concentration

| family | task_type | introduced_alert_n | distinct_rule_n | top1_alert_percent | top5_alert_percent | top10_alert_percent | hhi | effective_rule_n |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| quality | all | 775 | 53 | 39.10 | 70.58 | 80.13 | 0.19 | 5.31 |
| quality | feat | 544 | 42 | 41.73 | 72.24 | 81.25 | 0.21 | 4.73 |
| quality | fix | 146 | 22 | 41.10 | 83.56 | 91.78 | 0.24 | 4.19 |
| quality | refactor | 85 | 21 | 18.82 | 60.00 | 83.53 | 0.10 | 10.31 |
| security | all | 79 | 18 | 32.91 | 69.62 | 87.34 | 0.16 | 6.36 |
| security | feat | 59 | 14 | 44.07 | 83.05 | 93.22 | 0.26 | 3.92 |
| security | fix | 16 | 8 | 31.25 | 81.25 | 100.00 | 0.20 | 5.12 |
| security | refactor | 4 | 2 | 75.00 | 100.00 | 100.00 | 0.62 | 1.60 |

## Top rules

| family | rank | rule_id | quality_category | introduced_alert_n | affected_pr_n | alert_percent |
| --- | --- | --- | --- | --- | --- | --- |
| quality | 1 | js/unused-local-variable | maintainability | 303 | 119 | 39.10 |
| quality | 2 | py/unused-import | maintainability | 112 | 44 | 14.45 |
| quality | 3 | java/deprecated-call | maintainability | 66 | 1 | 8.52 |
| quality | 4 | py/unused-local-variable | maintainability | 44 | 21 | 5.68 |
| quality | 5 | js/trivial-conditional | correctness_reliability | 22 | 10 | 2.84 |
| quality | 6 | py/cyclic-import | correctness_reliability | 18 | 6 | 2.32 |
| quality | 7 | js/automatic-semicolon-insertion | maintainability | 16 | 9 | 2.06 |
| quality | 8 | py/empty-except | correctness_reliability | 14 | 7 | 1.81 |
| quality | 9 | py/unsafe-cyclic-import | correctness_reliability | 13 | 4 | 1.68 |
| quality | 10 | rb/useless-assignment-to-local | maintainability | 13 | 3 | 1.68 |
| security | 1 | js/log-injection |  | 26 | 7 | 32.91 |
| security | 2 | py/log-injection |  | 12 | 1 | 15.19 |
| security | 3 | js/tainted-format-string |  | 8 | 4 | 10.13 |
| security | 4 | js/indirect-command-line-injection |  | 5 | 3 | 6.33 |
| security | 5 | js/path-injection |  | 4 | 2 | 5.06 |
| security | 6 | js/insecure-temporary-file |  | 4 | 1 | 5.06 |
| security | 7 | js/double-escaping |  | 3 | 3 | 3.80 |
| security | 8 | js/shell-command-constructed-from-input |  | 3 | 3 | 3.80 |
| security | 9 | js/file-system-race |  | 2 | 2 | 2.53 |
| security | 10 | js/command-line-injection |  | 2 | 2 | 2.53 |

## 产物

- `introduced_by_task.csv`：task 分层，包含零告警 PR；
- `introduced_by_language.csv`：CodeQL database language 分层；
- `introduced_by_change_size.csv`：changed-code size 分层，包含零告警 PR；
- `introduced_by_location.csv`：由 SARIF `file_path` 派生的位置类别；
- `quality_category_profile.csv`：Quality taxonomy；
- `severity_profile.csv`、`precision_profile.csv`、`security_cwe_profile.csv`：告警属性；
- `rule_profile.csv`、`rule_concentration.csv`：规则排名与集中度；
- `pr_issue_count_distribution.csv`、`positive_pr_breadth.csv`：零感知的 PR 计数分布与阳性 PR 内部广度；
- `repository_cluster_bootstrap_intervals.csv`：repository-cluster percentile 95% CI；
- `manifest.json`：输入、门禁和守恒记录。
