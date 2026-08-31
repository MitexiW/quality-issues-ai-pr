# 原始可分析样本口径

更新日期：2026-07-27

RQ1/RQ2 的正式统计分析直接使用最终快照中的全部原始可分析 PR：

| Group | PR |
| --- | ---: |
| AI | 3,087 |
| Human | 2,317 |
| Total | 5,404 |

这 5,404 个 PR 每个恰好出现一次，分析权重均为 1。任务类型、CodeQL database
language、Changed KLOC 和 merge quarter 只作为结局模型的调整变量；repository
只作为聚类不确定性单位。它们不会改变样本名单或 PR 权重。

候选池共有 5,822 个 PR（AI 3,376、Human 2,446）。候选池与正式分析样本之间的
418 个 PR 缺少可分析的成对 CodeQL 结果，或未通过其他冻结的 eligibility /
analysis-quality gate，只进入 attrition 报告；它们不会被编码为零告警，也不会
进入 RQ1/RQ2 分母。

正式证据链固定为：

- snapshot：`rq_analysis_final_20260727_v3`；
- roster：`rq2_design_unweighted_final_20260727_v3`；
- binary models：`rq2_models_unweighted_final_20260727_v4`；
- full-sample artifact audit：`formal_artifacts_audit_20260727_v1`
  （98 个内容寻址文件、248 项检查、0 失败）；
- CodeQL version evidence：`codeql_versions_final_20260727_v1`。

早期 `rq2_design_final_20260727_v1`、`v2`、`v3` 和
`rq2_models_final_20260727_v1` 是已废弃的设计历史，只用于审计，不得用于论文、
正式结果或敏感性分析。其中旧目录中出现的 4,074、AI 1,812、Human 1,872 等数字
不是本研究的分析样本量。
