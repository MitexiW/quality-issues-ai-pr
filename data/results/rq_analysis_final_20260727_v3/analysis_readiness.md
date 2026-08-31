# Introduced-Quality-first RQ1–RQ3 数据完整性与分析就绪报告

- Snapshot: `study_stars500_final_20260727_v3`
- Mode: `final`
- RQ1 introduced-alert data ready: **yes**
- RQ1 full ready: **yes**
- RQ2 ready: **yes**
- RQ3 review frame ready: **yes**
- 主结果族：Quality；次级结果族：Security。
- 本报告由只读输入快照生成；不会修改正在运行的实验。

## 当前漏斗

| Group | Manifest PRs | Terminal PRs | Compared PRs | Enhanced metadata | Quality-gated PRs | Enriched gated PRs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AI | 3376 | 3376 | 3096 | 3096 | 3087 | 3087 |
| HUMAN | 2446 | 2446 | 2325 | 2325 | 2317 | 2317 |

## 阻断项

- 无。

## 下一步

1. 冻结 outcome-blind 全量分析名单；所有可比较 PR 等权进入分析。
2. 核验 AI/Human 原始分母后运行 Quality primary / Security secondary RQ2 模型。
3. 从同一 snapshot 构造 RQ3 Quality/Security reference-alert frame。

本快照的 `changed_kloc` 统一定义为 `(GitHub additions + deletions) / 1000`；失败或排除 PR 不要求 enrichment。
