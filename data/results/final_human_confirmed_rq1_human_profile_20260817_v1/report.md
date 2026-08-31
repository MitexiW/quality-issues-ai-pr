# Introduced-only RQ1 profile

状态：**final**。本报告只包含 `human` 组，不得在 Human 批次结束前作为 AI–Human 比较或论文最终结果。

## 数据门禁

- 门禁通过 PR：2,317
- 纳入 introduced alerts：1,468
- 因 PR 门禁排除的 alerts：854
- family 非法 alerts：0
- PR-level 与 alert-level 计数守恒：通过
- Quality：期望 1,419，观察 1,419
- Security：期望 49，观察 49

## 总体 introduced 分布

| family | pr_n | introduced_alert_n | affected_pr_n | affected_pr_percent | alerts_per_100_pr | median_per_pr | p95_per_pr | max_per_pr |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| quality | 2317 | 1419 | 264 | 11.39 | 61.24 | 0.00 | 2.00 | 186 |
| security | 2317 | 49 | 26 | 1.12 | 2.11 | 0.00 | 0.00 | 8 |

## Repository-cluster 95% intervals

| family | metric | estimate | ci_low | ci_high | repository_n | bootstrap_replicates |
| --- | --- | --- | --- | --- | --- | --- |
| quality | affected_pr_percent | 11.39 | 8.83 | 14.07 | 381 | 2000 |
| quality | alerts_per_100_pr | 61.24 | 39.15 | 89.14 | 381 | 2000 |
| security | affected_pr_percent | 1.12 | 0.64 | 1.67 | 381 | 2000 |
| security | alerts_per_100_pr | 2.11 | 1.02 | 3.31 | 381 | 2000 |

## Task type

| stratum | family | pr_n | introduced_alert_n | affected_pr_n | affected_pr_percent | alerts_per_100_pr | p95_per_pr | max_per_pr |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| feat | quality | 1090 | 1104 | 168 | 15.41 | 101.28 | 4.00 | 186 |
| feat | security | 1090 | 42 | 20 | 1.83 | 3.85 | 0.00 | 8 |
| fix | quality | 1037 | 218 | 75 | 7.23 | 21.02 | 1.00 | 25 |
| fix | security | 1037 | 6 | 5 | 0.48 | 0.58 | 0.00 | 2 |
| refactor | quality | 190 | 97 | 21 | 11.05 | 51.05 | 4.00 | 17 |
| refactor | security | 190 | 1 | 1 | 0.53 | 0.53 | 0.00 | 1 |

## CodeQL database language

| stratum | family | pr_n | introduced_alert_n | affected_pr_n | affected_pr_percent | alerts_per_100_pr |
| --- | --- | --- | --- | --- | --- | --- |
| C | quality | 49 | 4 | 4 | 8.16 | 8.16 |
| C | security | 49 | 0 | 0 | 0.00 | 0.00 |
| C++ | quality | 65 | 0 | 0 | 0.00 | 0.00 |
| C++ | security | 65 | 0 | 0 | 0.00 | 0.00 |
| Go | quality | 118 | 2 | 1 | 0.85 | 1.69 |
| Go | security | 118 | 0 | 0 | 0.00 | 0.00 |
| Java | quality | 71 | 73 | 7 | 9.86 | 102.82 |
| Java | security | 71 | 2 | 1 | 1.41 | 2.82 |
| JavaScript | quality | 143 | 177 | 21 | 14.69 | 123.78 |
| JavaScript | security | 143 | 3 | 2 | 1.40 | 2.10 |
| Python | quality | 599 | 312 | 80 | 13.36 | 52.09 |
| Python | security | 599 | 9 | 5 | 0.83 | 1.50 |
| Ruby | quality | 42 | 1 | 1 | 2.38 | 2.38 |
| Ruby | security | 42 | 4 | 2 | 4.76 | 9.52 |
| TypeScript | quality | 1230 | 850 | 150 | 12.20 | 69.11 |
| TypeScript | security | 1230 | 31 | 16 | 1.30 | 2.52 |

## Quality categories

| value | introduced_alert_n | affected_pr_n | alert_percent_within_family |
| --- | --- | --- | --- |
| maintainability | 1247 | 237 | 87.88 |
| correctness_reliability | 165 | 62 | 11.63 |
| performance_efficiency | 7 | 6 | 0.49 |

## Alert locations

| family | value | introduced_alert_n | affected_pr_n | alert_percent_within_family |
| --- | --- | --- | --- | --- |
| quality | production | 905 | 225 | 63.78 |
| quality | test | 470 | 64 | 33.12 |
| quality | example | 22 | 5 | 1.55 |
| quality | docs | 20 | 3 | 1.41 |
| quality | build | 2 | 2 | 0.14 |
| security | production | 47 | 24 | 95.92 |
| security | docs | 1 | 1 | 2.04 |
| security | example | 1 | 1 | 2.04 |

## Rule concentration

| family | task_type | introduced_alert_n | distinct_rule_n | top1_alert_percent | top5_alert_percent | top10_alert_percent | hhi | effective_rule_n |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| quality | all | 1419 | 60 | 49.61 | 78.15 | 86.96 | 0.28 | 3.60 |
| quality | feat | 1104 | 52 | 52.26 | 80.98 | 89.67 | 0.31 | 3.27 |
| quality | fix | 218 | 26 | 43.58 | 78.90 | 88.99 | 0.24 | 4.14 |
| quality | refactor | 97 | 14 | 32.99 | 75.26 | 94.85 | 0.18 | 5.59 |
| security | all | 49 | 20 | 16.33 | 53.06 | 75.51 | 0.08 | 12.31 |
| security | feat | 42 | 16 | 16.67 | 54.76 | 80.95 | 0.09 | 11.61 |
| security | fix | 6 | 5 | 33.33 | 100.00 | 100.00 | 0.22 | 4.50 |
| security | refactor | 1 | 1 | 100.00 | 100.00 | 100.00 | 1.00 | 1.00 |

## Top rules

| family | rank | rule_id | quality_category | introduced_alert_n | affected_pr_n | alert_percent |
| --- | --- | --- | --- | --- | --- | --- |
| quality | 1 | js/unused-local-variable | maintainability | 704 | 145 | 49.61 |
| quality | 2 | js/automatic-semicolon-insertion | maintainability | 180 | 28 | 12.68 |
| quality | 3 | py/unused-import | maintainability | 153 | 46 | 10.78 |
| quality | 4 | js/useless-assignment-to-local | maintainability | 40 | 12 | 2.82 |
| quality | 5 | py/unused-local-variable | maintainability | 32 | 14 | 2.26 |
| quality | 6 | java/missing-override-annotation | maintainability | 30 | 2 | 2.11 |
| quality | 7 | js/syntax-error | correctness_reliability | 28 | 2 | 1.97 |
| quality | 8 | java/unused-parameter | maintainability | 27 | 3 | 1.90 |
| quality | 9 | js/trivial-conditional | correctness_reliability | 21 | 19 | 1.48 |
| quality | 10 | py/unsafe-cyclic-import | correctness_reliability | 19 | 9 | 1.34 |
| security | 1 | js/polynomial-redos |  | 8 | 2 | 16.33 |
| security | 2 | js/log-injection |  | 7 | 4 | 14.29 |
| security | 3 | py/log-injection |  | 4 | 1 | 8.16 |
| security | 4 | rb/sql-injection |  | 4 | 2 | 8.16 |
| security | 5 | js/file-system-race |  | 3 | 2 | 6.12 |
| security | 6 | js/insecure-temporary-file |  | 3 | 3 | 6.12 |
| security | 7 | js/incomplete-url-substring-sanitization |  | 2 | 2 | 4.08 |
| security | 8 | js/incomplete-sanitization |  | 2 | 1 | 4.08 |
| security | 9 | js/http-to-file-access |  | 2 | 1 | 4.08 |
| security | 10 | js/tainted-format-string |  | 2 | 1 | 4.08 |

## 产物

- `introduced_by_task.csv`：task 分层，包含零告警 PR；
- `introduced_by_language.csv`：CodeQL database language 分层；
- `introduced_by_location.csv`：由 SARIF `file_path` 派生的位置类别；
- `quality_category_profile.csv`：Quality taxonomy；
- `severity_profile.csv`、`precision_profile.csv`、`security_cwe_profile.csv`：告警属性；
- `rule_profile.csv`、`rule_concentration.csv`：规则排名与集中度；
- `repository_cluster_bootstrap_intervals.csv`：repository-cluster percentile 95% CI；
- `manifest.json`：输入、门禁和守恒记录。
