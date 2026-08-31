#!/usr/bin/env python3
# CodeQL pipeline entry point.
"""Summarize before/after CodeQL SARIF diff results for research reporting."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="汇总 CodeQL before/after 差分结果")
    parser.add_argument(
        "--results-dir",
        default="data/experiments/code-scanning/pilot20/results",
    )
    parser.add_argument(
        "--prs",
        default="data/experiments/code-scanning/pilot20/pilot_prs.csv",
    )
    parser.add_argument(
        "--jobs",
        default="data/experiments/code-scanning/pilot20/codeql_jobs.csv",
    )
    parser.add_argument(
        "--output",
        default="data/experiments/code-scanning/pilot20/results/summary.md",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="规则、CWE 和项目列表最多显示多少行。",
    )
    return parser.parse_args()


def read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(path)
    return pd.read_csv(path, keep_default_na=False)


def table_from_counts(series: pd.Series, headers: tuple[str, str], top: int) -> str:
    rows = series.head(top)
    if rows.empty:
        return "无\n"
    lines = [
        f"| {headers[0]} | {headers[1]} |",
        "| --- | ---: |",
    ]
    for key, value in rows.items():
        lines.append(f"| {key or '(empty)'} | {int(value)} |")
    return "\n".join(lines) + "\n"


def grouped_count(frame: pd.DataFrame, column: str) -> pd.Series:
    if frame.empty or column not in frame.columns:
        return pd.Series(dtype="int64")
    return frame[column].astype(str).value_counts()


def cwe_count(frame: pd.DataFrame) -> pd.Series:
    if frame.empty or "cwe" not in frame.columns:
        return pd.Series(dtype="int64")
    counts: dict[str, int] = {}
    for value in frame["cwe"].astype(str):
        for item in value.split("|"):
            item = item.strip()
            if item:
                counts[item] = counts.get(item, 0) + 1
    return pd.Series(counts, dtype="int64").sort_values(ascending=False)


def pr_count_with_alerts(summary: pd.DataFrame, column: str) -> int:
    if summary.empty or column not in summary.columns:
        return 0
    return int((pd.to_numeric(summary[column], errors="coerce").fillna(0) > 0).sum())


def total(summary: pd.DataFrame, column: str) -> int:
    if summary.empty or column not in summary.columns:
        return 0
    return int(pd.to_numeric(summary[column], errors="coerce").fillna(0).sum())


def main() -> None:
    args = parse_args()
    results_dir = Path(args.results_dir)
    output = Path(args.output)

    summary = read_csv(results_dir / "pr_security_summary.csv")
    introduced = read_csv(results_dir / "introduced_alerts.csv")
    fixed = read_csv(results_dir / "fixed_alerts.csv")
    persistent = read_csv(results_dir / "persistent_alerts.csv")
    prs = read_csv(Path(args.prs)) if Path(args.prs).exists() else pd.DataFrame()
    jobs = read_csv(Path(args.jobs)) if Path(args.jobs).exists() else pd.DataFrame()

    compared_prs = int((summary.get("comparison_status", "") == "compared").sum())
    failed_prs = int((summary.get("comparison_status", "") == "failed").sum())
    codeql_versions = sorted(jobs.get("codeql_version", pd.Series(dtype=str)).astype(str).replace("", pd.NA).dropna().unique())
    query_suites = sorted(jobs.get("query_suite", pd.Series(dtype=str)).astype(str).replace("", pd.NA).dropna().unique())

    lines = [
        "# CodeQL before/after 差分结果汇总",
        "",
        "## 总览",
        "",
        "| 指标 | 值 |",
        "| --- | ---: |",
        f"| PR 总数 | {len(summary)} |",
        f"| 已比较 PR | {compared_prs} |",
        f"| 比较失败 PR | {failed_prs} |",
        f"| 引入新告警的 PR | {pr_count_with_alerts(summary, 'introduced_alerts')} |",
        f"| 修复旧告警的 PR | {pr_count_with_alerts(summary, 'fixed_alerts')} |",
        f"| introduced 告警 | {total(summary, 'introduced_alerts')} |",
        f"| fixed 告警 | {total(summary, 'fixed_alerts')} |",
        f"| persistent 告警 | {total(summary, 'persistent_alerts')} |",
        "",
        "## 固定配置",
        "",
        f"- CodeQL 版本：{', '.join(codeql_versions) if codeql_versions else '未记录'}",
        f"- 查询套件：{', '.join(query_suites) if query_suites else '未记录'}",
        "- before revision：GitHub PR `base.sha`",
        "- after revision：GitHub PR `head.sha`",
        "",
    ]

    if total(summary, "introduced_alerts") == 0:
        lines.extend(
            [
                "## Pilot 解释",
                "",
                "本批次没有 observed introduced CodeQL 告警。这只能说明在当前样本、"
                "CodeQL 版本和查询套件下，未检测到 after 新增且 before 不存在的 SARIF 结果；"
                "不能推出 AI PR 没有引入安全问题。",
                "",
            ]
        )

    if not prs.empty:
        lines.extend(
            [
                "## 样本分布",
                "",
                "### Agent",
                "",
                table_from_counts(grouped_count(prs, "agent"), ("Agent", "PR 数"), args.top),
                "### 语言",
                "",
                table_from_counts(grouped_count(prs, "language"), ("语言", "PR 数"), args.top),
                "",
            ]
        )
        if "size_stratum" in prs.columns:
            lines.extend(
                [
                    "### 变更规模",
                    "",
                    table_from_counts(grouped_count(prs, "size_stratum"), ("规模", "PR 数"), args.top),
                    "",
                ]
            )

    lines.extend(
        [
            "## Introduced 告警规则",
            "",
            table_from_counts(grouped_count(introduced, "rule_id"), ("规则", "告警数"), args.top),
            "## Introduced CWE",
            "",
            table_from_counts(cwe_count(introduced), ("CWE", "告警数"), args.top),
            "## Fixed 告警规则",
            "",
            table_from_counts(grouped_count(fixed, "rule_id"), ("规则", "告警数"), args.top),
            "## Persistent 告警规则",
            "",
            table_from_counts(grouped_count(persistent, "rule_id"), ("规则", "告警数"), args.top),
        ]
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"已生成结果汇总: {output}")


if __name__ == "__main__":
    main()
