# RQ2 outcome-blind full-sample roster

状态：**final_design**。
本阶段不读取、建模或导出任何 introduced-alert outcome。

- 完整协变量 PR：5,404
- Primary design：完整协变量样本，所有 PR 等权（weight = 1）
- Repository：跨仓库比较，仅作为 GEE 聚类单位，不要求来自同仓库
- Primary 保留 PR：5,404 / 5,404
- AI：3,087
- Human：2,317
- 原始数据最大 |SMD|：1.014
- 未进行倾向评分、匹配、重叠加权或 common-support 删除

只有 `source_rq2_ready=true` 的最终冻结快照才能用于论文。若状态为 provisional rehearsal，所有权重与诊断必须丢弃并在最终快照重跑。
