#!/usr/bin/env python3
# Statistical analysis entry point.
"""Prepare the outcome-blind full-sample roster for RQ2.

This command consumes the PR-level analysis snapshot but deliberately does not
read or export outcome columns.  The primary cross-repository analysis retains
every quality-gated, complete-covariate PR with unit weight.  It performs no
matching, propensity estimation, trimming, common-support filtering, or
outcome-dependent selection.  Repository is the model clustering unit, not an
exact-matching requirement.

By default, the command refuses a snapshot whose manifest does not declare
``rq2_ready=true``.  ``--allow-provisional`` exists only for synthetic tests and
pipeline rehearsals; provisional weights must never be used as study results.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
GROUPS = ("ai", "human")
PRIMARY_DESIGN_NAME = "unweighted_full_sample"
DESIGN_FIELDS = (
    "repo_name",
    "pr_number",
    "group",
    "task_type",
    "repo_language",
    "merged_at",
    "stars",
    "changed_kloc",
    "code_changed_lines",
    "quality_gate_pass",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-pr-level", type=Path, required=True)
    parser.add_argument("--snapshot-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--allow-provisional",
        action="store_true",
        help="仅用于合成测试/流程演练；不得据此报告 AI–Human 结果",
    )
    return parser.parse_args()


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def maximize_csv_field_limit() -> None:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


def clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.casefold() in {"nan", "none", "null", "<na>"} else text


def truthy(value: Any) -> bool:
    return clean(value).casefold() in {"1", "true", "yes", "y"}


def number(value: Any) -> float | None:
    text = clean(value)
    if not text:
        return None
    try:
        parsed = float(text)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def normalize_pr_number(value: Any) -> str:
    text = clean(value)
    try:
        return str(int(float(text)))
    except (TypeError, ValueError):
        return text


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    maximize_csv_field_limit()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), [
            {key: clean(value) for key, value in row.items()} for row in reader
        ]


def write_csv(
    path: Path,
    fields: Sequence[str],
    rows: Iterable[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def calendar_quarter(value: str) -> str:
    text = clean(value)
    if len(text) < 7:
        return ""
    try:
        year = int(text[:4])
        month = int(text[5:7])
    except ValueError:
        return ""
    if not 1 <= month <= 12:
        return ""
    return f"{year}-Q{(month - 1) // 3 + 1}"


def changed_kloc(row: dict[str, str]) -> float | None:
    value = number(row.get("changed_kloc"))
    if value is not None:
        return value if value >= 0 else None
    lines = number(row.get("code_changed_lines"))
    return lines / 1000 if lines is not None and lines >= 0 else None


def prepare_rows(
    rows: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], Counter[str]]:
    prepared: list[dict[str, Any]] = []
    exclusions: Counter[str] = Counter()
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        group = clean(row.get("group")).casefold()
        if group not in GROUPS:
            exclusions["group_out_of_scope"] += 1
            continue
        if not truthy(row.get("quality_gate_pass")):
            exclusions["quality_gate_failed"] += 1
            continue
        key = (
            group,
            clean(row.get("repo_name")).casefold(),
            normalize_pr_number(row.get("pr_number")),
        )
        if key in seen:
            raise ValueError(f"analysis_pr_level 中存在重复 PR: {key}")
        seen.add(key)
        task = clean(row.get("task_type"))
        language = clean(row.get("repo_language")) or clean(row.get("language"))
        kloc = changed_kloc(row)
        stars = number(row.get("stars"))
        quarter = calendar_quarter(clean(row.get("merged_at")))
        missing = []
        if not clean(row.get("repo_name")):
            missing.append("repo")
        if not normalize_pr_number(row.get("pr_number")):
            missing.append("pr_number")
        if not task:
            missing.append("task")
        if not language:
            missing.append("language")
        if kloc is None:
            missing.append("changed_kloc")
        if stars is None or stars < 0:
            missing.append("stars")
        if not quarter:
            missing.append("merge_quarter")
        if missing:
            for field in missing:
                exclusions[f"missing_{field}"] += 1
            exclusions["incomplete_covariates"] += 1
            continue
        prepared.append(
            {
                "repo_name": clean(row.get("repo_name")),
                "pr_number": normalize_pr_number(row.get("pr_number")),
                "group": group,
                "task_type": task,
                "repo_language": language,
                "merge_quarter": quarter,
                "changed_kloc": float(kloc),
                "log1p_changed_kloc": math.log1p(float(kloc)),
                "stars": float(stars),
                "log1p_stars": math.log1p(float(stars)),
            }
        )
    return prepared, exclusions


def support_audits(
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    repo_counts: defaultdict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    exact_counts: defaultdict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for row in rows:
        repo_counts[(row["repo_name"], row["task_type"])][row["group"]] += 1
        exact_counts[(row["task_type"], row["repo_language"])][row["group"]] += 1
    repo_audit = [
        {
            "repo_name": repo,
            "task_type": task,
            "ai_pr_n": counts["ai"],
            "human_pr_n": counts["human"],
            "has_both_groups": counts["ai"] > 0 and counts["human"] > 0,
        }
        for (repo, task), counts in sorted(repo_counts.items())
    ]
    exact_audit = [
        {
            "task_type": task,
            "repo_language": language,
            "ai_pr_n": counts["ai"],
            "human_pr_n": counts["human"],
            "has_both_groups": counts["ai"] > 0 and counts["human"] > 0,
        }
        for (task, language), counts in sorted(exact_counts.items())
    ]
    return repo_audit, exact_audit


def effective_sample_size(weights: np.ndarray) -> float:
    total = float(np.sum(weights))
    squared = float(np.sum(weights**2))
    return total * total / squared if squared else 0.0


def weighted_mean(values: np.ndarray, weights: np.ndarray) -> float:
    return float(np.average(values, weights=weights)) if len(values) else math.nan


def smd(
    values: np.ndarray,
    treatment: np.ndarray,
    weights: np.ndarray,
) -> tuple[float, float, float]:
    selected = {
        group: treatment == indicator for group, indicator in (("ai", 1), ("human", 0))
    }
    means = {
        group: weighted_mean(values[mask], weights[mask])
        for group, mask in selected.items()
    }
    variances = {}
    for group, mask in selected.items():
        group_values = values[mask]
        group_weights = weights[mask]
        mean = means[group]
        variances[group] = weighted_mean((group_values - mean) ** 2, group_weights)
    denominator = math.sqrt((variances["ai"] + variances["human"]) / 2)
    difference = means["ai"] - means["human"]
    standardized = difference / denominator if denominator > 1e-12 else 0.0
    return means["ai"], means["human"], standardized


def balance_records(
    rows: list[dict[str, Any]],
    treatment: np.ndarray,
    retained: np.ndarray,
    overlap_weights: np.ndarray,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    fields: list[tuple[str, str, np.ndarray]] = []
    for field in ("log1p_changed_kloc", "log1p_stars"):
        fields.append(
            (
                field,
                "continuous",
                np.asarray([float(row[field]) for row in rows], dtype=float),
            )
        )
    for field in ("task_type", "repo_language", "merge_quarter"):
        for level in sorted({str(row[field]) for row in rows}):
            fields.append(
                (
                    f"{field}={level}",
                    "indicator",
                    np.asarray([float(row[field] == level) for row in rows]),
                )
            )
    retained_treatment = treatment[retained]
    for name, kind, values in fields:
        before_ai, before_human, before_smd = smd(
            values, treatment, np.ones(len(rows), dtype=float)
        )
        after_ai, after_human, after_smd = smd(
            values[retained],
            retained_treatment,
            overlap_weights[retained],
        )
        records.append(
            {
                "covariate": name,
                "kind": kind,
                "before_ai_mean": before_ai,
                "before_human_mean": before_human,
                "before_smd": before_smd,
                "after_ai_mean": after_ai,
                "after_human_mean": after_human,
                "after_smd": after_smd,
                "after_abs_smd_below_0_1": abs(after_smd) < 0.1,
            }
        )
    return records


def design_records(
    rows: list[dict[str, Any]],
    retained: np.ndarray,
    weights: np.ndarray,
    *,
    design_name: str,
) -> list[dict[str, Any]]:
    # Keep the historical column names for downstream compatibility. In the
    # formal full-sample design, propensity_ai is blank, common_support is true,
    # overlap_weight is exactly 1, and support_exclusion_reason is blank for
    # every row.
    output = []
    for index, row in enumerate(rows):
        exact_stratum = f"{row['task_type']}|{row['repo_language']}"
        output.append(
            {
                **row,
                "design_name": design_name,
                "propensity_ai": "",
                "exact_stratum": exact_stratum,
                "common_support": bool(retained[index]),
                "overlap_weight": weights[index],
                "support_exclusion_reason": (
                    "" if retained[index] else "unsupported_task_language_stratum"
                ),
            }
        )
    return output


def effective_sample_size_records(
    rows: list[dict[str, Any]],
    treatment: np.ndarray,
    retained: np.ndarray,
    weights: np.ndarray,
) -> list[dict[str, Any]]:
    output = []
    for task in ["all", *sorted({row["task_type"] for row in rows})]:
        task_mask = np.asarray(
            [task == "all" or row["task_type"] == task for row in rows]
        )
        for group, indicator in (("ai", 1.0), ("human", 0.0)):
            mask = retained & task_mask & (treatment == indicator)
            selected = weights[mask]
            output.append(
                {
                    "task_type": task,
                    "group": group,
                    "retained_pr_n": int(np.sum(mask)),
                    "weight_sum": float(np.sum(selected)),
                    "effective_sample_size": effective_sample_size(selected),
                    "weight_min": (
                        float(np.min(selected)) if len(selected) else 0
                    ),
                    "weight_max": (
                        float(np.max(selected)) if len(selected) else 0
                    ),
                    "weight_p99": (
                        float(np.percentile(selected, 99))
                        if len(selected)
                        else 0
                    ),
                    "weight_above_10_n": int(np.sum(selected > 10)),
                }
            )
    return output


def balance_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "target_absolute_smd": 0.1,
        "max_before_abs_smd": max(
            abs(row["before_smd"]) for row in rows
        ),
        "max_after_abs_smd": max(
            abs(row["after_smd"]) for row in rows
        ),
        "all_after_abs_smd_below_0_1": all(
            row["after_abs_smd_below_0_1"] for row in rows
        ),
    }


def main() -> None:
    args = parse_args()
    analysis_path = resolve(args.analysis_pr_level)
    manifest_path = resolve(args.snapshot_manifest)
    output_dir = resolve(args.output_dir)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rq2_ready = bool(manifest.get("rq2_ready"))
    if not rq2_ready and not args.allow_provisional:
        raise RuntimeError(
            "snapshot manifest 未声明 rq2_ready=true；拒绝生成正式 RQ2 design。"
        )

    fields, raw_rows = read_csv(analysis_path)
    missing = set(DESIGN_FIELDS) - set(fields)
    if missing:
        raise ValueError(f"analysis_pr_level 缺少 design 字段: {sorted(missing)}")
    rows, exclusions = prepare_rows(raw_rows)
    if not rows or {row["group"] for row in rows} != set(GROUPS):
        raise RuntimeError("完整协变量样本必须同时包含 AI 和 Human")
    repo_audit, exact_audit = support_audits(rows)
    treatment = np.asarray([float(row["group"] == "ai") for row in rows])
    primary_retained = np.ones(len(rows), dtype=bool)
    primary_weights = np.ones(len(rows), dtype=float)
    primary_balance = balance_records(
        rows, treatment, primary_retained, primary_weights
    )
    primary_balance_summary = balance_summary(primary_balance)

    primary_design_rows = design_records(
        rows,
        primary_retained,
        primary_weights,
        design_name=PRIMARY_DESIGN_NAME,
    )
    primary_ess_rows = effective_sample_size_records(
        rows, treatment, primary_retained, primary_weights
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(
        output_dir / "same_repository_task_support.csv",
        ["repo_name", "task_type", "ai_pr_n", "human_pr_n", "has_both_groups"],
        repo_audit,
    )
    write_csv(
        output_dir / "exact_strata_support.csv",
        [
            "task_type",
            "repo_language",
            "ai_pr_n",
            "human_pr_n",
            "has_both_groups",
        ],
        exact_audit,
    )
    write_csv(
        output_dir / "design_weights.csv",
        [
            "repo_name",
            "pr_number",
            "group",
            "task_type",
            "repo_language",
            "merge_quarter",
            "changed_kloc",
            "log1p_changed_kloc",
            "stars",
            "log1p_stars",
            "design_name",
            "propensity_ai",
            "exact_stratum",
            "common_support",
            "overlap_weight",
            "support_exclusion_reason",
        ],
        primary_design_rows,
    )
    write_csv(
        output_dir / "balance.csv",
        [
            "covariate",
            "kind",
            "before_ai_mean",
            "before_human_mean",
            "before_smd",
            "after_ai_mean",
            "after_human_mean",
            "after_smd",
            "after_abs_smd_below_0_1",
        ],
        primary_balance,
    )
    write_csv(
        output_dir / "effective_sample_size.csv",
        [
            "task_type",
            "group",
            "retained_pr_n",
            "weight_sum",
            "effective_sample_size",
            "weight_min",
            "weight_max",
            "weight_p99",
            "weight_above_10_n",
        ],
        primary_ess_rows,
    )
    write_csv(
        output_dir / "covariate_missingness.csv",
        ["reason", "row_n"],
        [{"reason": reason, "row_n": count} for reason, count in exclusions.items()],
    )
    primary_retained_n = int(np.sum(primary_retained))
    output_manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "final_design" if rq2_ready else "provisional_rehearsal",
        "source_snapshot_id": manifest.get("snapshot_id", ""),
        "source_rq2_ready": rq2_ready,
        "outcome_blind": True,
        "design_name": PRIMARY_DESIGN_NAME,
        "primary_design": {
            "method": "unweighted complete-case analysis",
            "selection_rule": "retain every complete-covariate PR",
            "analysis_weight": 1.0,
            "repository_policy": (
                "cross-repository comparison; repository is the clustered "
                "uncertainty unit, not an exact matching variable"
            ),
        },
        "candidate_quality_gated_pr_n": sum(
            truthy(row.get("quality_gate_pass")) for row in raw_rows
        ),
        "complete_covariate_pr_n": len(rows),
        "analysis_pr_n": primary_retained_n,
        # Backward-compatible alias for older readers. No support filtering is
        # performed: this is exactly the full analysis roster.
        "retained_common_support_pr_n": primary_retained_n,
        "retained_ai_pr_n": int(
            np.sum(primary_retained & (treatment == 1))
        ),
        "retained_human_pr_n": int(
            np.sum(primary_retained & (treatment == 0))
        ),
        "same_repository_task_supported_pr_n": sum(
            row["ai_pr_n"] + row["human_pr_n"]
            for row in repo_audit
            if row["has_both_groups"]
        ),
        "balance": primary_balance_summary,
        "inputs": {
            "analysis_pr_level": str(analysis_path),
            "snapshot_manifest": str(manifest_path),
        },
    }
    (output_dir / "design_manifest.json").write_text(
        json.dumps(output_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    report = [
        "# RQ2 outcome-blind full-sample roster",
        "",
        f"状态：**{output_manifest['status']}**。",
        "本阶段不读取、建模或导出任何 introduced-alert outcome。",
        "",
        f"- 完整协变量 PR：{len(rows):,}",
        "- Primary design：完整协变量样本，所有 PR 等权（weight = 1）",
        "- Repository：跨仓库比较，仅作为 GEE 聚类单位，不要求来自同仓库",
        f"- Primary 保留 PR：{primary_retained_n:,} / {len(rows):,}",
        f"- AI：{output_manifest['retained_ai_pr_n']:,}",
        f"- Human：{output_manifest['retained_human_pr_n']:,}",
        f"- 原始数据最大 |SMD|："
        f"{output_manifest['balance']['max_before_abs_smd']:.3f}",
        "- 每个可分析 PR 恰好保留一次，分析权重固定为 1",
        "",
        "只有 `source_rq2_ready=true` 的最终冻结快照才能用于论文。"
        "若状态为 provisional rehearsal，所有权重与诊断必须丢弃并在最终快照重跑。",
        "",
    ]
    (output_dir / "report.md").write_text("\n".join(report), encoding="utf-8")
    print(f"已生成 RQ2 outcome-blind design: {output_dir}")
    print(
        f"complete={len(rows)} primary_retained={primary_retained_n} "
        f"max_raw_abs_smd={output_manifest['balance']['max_before_abs_smd']:.4f}"
    )


if __name__ == "__main__":
    main()
