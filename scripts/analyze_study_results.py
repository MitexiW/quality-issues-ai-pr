#!/usr/bin/env python3
"""Audit and summarize the frozen AI/Human CodeQL study results for RQ1–RQ3.

The command is deliberately read-only with respect to experiment inputs.  It
writes a consistent analysis snapshot under ``reports/`` and clearly labels a
snapshot provisional whenever the Human run, SARIF metadata migration, or PR
size enrichment is incomplete.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STUDY_ROOT = Path(
    "data/experiments/security-and-quality/study_stars500"
)
DEFAULT_ENRICHMENT_RELATIVE = Path("reports/pr_enrichment/pr_enrichment.csv")
DEFAULT_ENRICHMENT_MANIFEST_RELATIVE = Path(
    "reports/pr_enrichment/snapshot_manifest.json"
)
GROUPS = ("ai", "human")
ALLOWED_LANGUAGES = {
    "C",
    "C++",
    "Go",
    "Java",
    "JavaScript",
    "Python",
    "Ruby",
    "TypeScript",
}
ALLOWED_TASK_TYPES = {"fix", "feat", "refactor"}
SELECTION_EXCLUSION_REASONS = {
    "stars_missing",
    "stars_below_500",
    "language_out_of_scope",
    "task_type_out_of_scope",
    "cross_group_overlap",
}
TERMINAL_JOB_STATUSES = {
    "completed",
    "prepare_failed",
    "database_failed",
    "analysis_failed",
}
FAMILY_COUNT_FIELDS = (
    "before_security_alerts",
    "after_security_alerts",
    "introduced_security_alerts",
    "fixed_security_alerts",
    "persistent_security_alerts",
    "before_quality_alerts",
    "after_quality_alerts",
    "introduced_quality_alerts",
    "fixed_quality_alerts",
    "persistent_quality_alerts",
)
SIZE_FIELDS = (
    "total_changed_files",
    "total_changed_lines",
    "code_changed_files",
    "code_changed_lines",
)
ANALYSIS_FIELDS = (
    "snapshot_id",
    "analysis_status",
    "group",
    "repo_name",
    "pr_number",
    "pr_id",
    "agent",
    "repo_language",
    "task_type",
    "stars",
    "forks",
    "merged_at",
    "enrichment_available",
    "additions",
    "deletions",
    "changed_lines",
    "changed_files",
    "file_list_complete",
    "enrichment_source",
    "enrichment_fetched_at",
    "total_changed_files",
    "total_changed_lines",
    "code_changed_files",
    "code_changed_lines",
    "changed_kloc",
    "base_sha",
    "head_sha",
    "codeql_version",
    "query_suite",
    "build_mode",
    "before_alerts",
    "after_alerts",
    "introduced_alerts",
    "fixed_alerts",
    "persistent_alerts",
    *FAMILY_COUNT_FIELDS,
    "introduced_security_any",
    "fixed_security_any",
    "net_security_count",
    "introduced_quality_any",
    "fixed_quality_any",
    "net_quality_count",
    "retry_excluded",
    "paired",
    "family_metadata_complete",
    "group_overlap",
    "quality_gate_pass",
    "comparison_status",
    "job_statuses",
    "failure_stage",
    "failure_reason",
    "exclusion_reason",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-root", type=Path, default=DEFAULT_STUDY_ROOT)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--ai-results-dir",
        type=Path,
        help="覆盖 AI results 输入目录（用于隔离重解析演练）",
    )
    parser.add_argument(
        "--human-results-dir",
        type=Path,
        help="覆盖 Human results 输入目录（用于冻结结果或隔离演练）",
    )
    parser.add_argument(
        "--enrichment-csv",
        type=Path,
        help=(
            "统一 GitHub PR enrichment；默认 "
            "<study-root>/reports/pr_enrichment/pr_enrichment.csv"
        ),
    )
    parser.add_argument(
        "--enrichment-manifest",
        type=Path,
        help=(
            "enrichment 上游 manifest；默认 "
            "<study-root>/reports/pr_enrichment/snapshot_manifest.json"
        ),
    )
    parser.add_argument(
        "--mode",
        choices=("provisional", "final"),
        default="provisional",
        help="final 模式在主分析（RQ1/RQ2）门禁未通过时返回非零状态",
    )
    parser.add_argument("--snapshot-id")
    parser.add_argument("--read-retries", type=int, default=3)
    return parser.parse_args()


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def maximize_csv_field_limit() -> None:
    limit = sys.maxsize
    while limit > 0:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


def clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"nan", "none", "null", "<na>"} else text


def truthy(value: Any) -> bool:
    return clean(value).casefold() in {"1", "true", "yes", "y"}


def normalize_number(value: Any) -> str:
    text = clean(value)
    try:
        return str(int(float(text)))
    except (TypeError, ValueError):
        return text


def pr_key(row: dict[str, str]) -> tuple[str, str]:
    return clean(row.get("repo_name")).casefold(), normalize_number(
        row.get("pr_number")
    )


def enrichment_key(row: dict[str, str]) -> tuple[str, str, str]:
    return (
        clean(row.get("group")).casefold(),
        clean(row.get("repo_name")).casefold(),
        normalize_number(row.get("pr_number")),
    )


def file_identity(path: Path) -> tuple[int, int, int]:
    stat = path.stat()
    return stat.st_ino, stat.st_size, stat.st_mtime_ns


def read_stable_csv(
    path: Path, retries: int
) -> tuple[tuple[str, ...], list[dict[str, str]]]:
    maximize_csv_field_limit()
    last_error = ""
    for attempt in range(max(1, retries)):
        before = file_identity(path)
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fields = tuple(reader.fieldnames or ())
            rows = [
                {key: clean(value) for key, value in row.items()}
                for row in reader
            ]
        after = file_identity(path)
        if before == after:
            return fields, rows
        last_error = f"读取期间文件发生变化: {path}"
        if attempt + 1 < retries:
            time.sleep(0.2)
    raise RuntimeError(last_error)


def write_csv(path: Path, fields: Sequence[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temp.replace(path)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(text, encoding="utf-8")
    temp.replace(path)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def git_revision() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def integer(value: Any) -> int | None:
    text = clean(value).replace(",", "")
    if not text:
        return None
    try:
        return int(float(text))
    except ValueError:
        return None


def enrichment_size(row: dict[str, str] | None) -> dict[str, Any]:
    if not row:
        return {
            "enrichment_available": "false",
            "additions": "",
            "deletions": "",
            "changed_lines": "",
            "changed_files": "",
            "file_list_complete": "",
            "enrichment_source": "",
            "enrichment_fetched_at": "",
            "changed_kloc": "",
        }
    additions = integer(row.get("additions"))
    deletions = integer(row.get("deletions"))
    if additions is None or deletions is None or additions < 0 or deletions < 0:
        raise ValueError(
            "enrichment additions/deletions 缺失或非法: "
            f"{row.get('group')} {row.get('repo_name')}#{row.get('pr_number')}"
        )
    changed_lines = additions + deletions
    reported_lines = integer(row.get("changed_lines"))
    if reported_lines is not None and reported_lines != changed_lines:
        raise ValueError(
            "enrichment changed_lines 与 additions+deletions 不守恒: "
            f"{row.get('group')} {row.get('repo_name')}#{row.get('pr_number')}"
        )
    reported_kloc = clean(row.get("changed_kloc"))
    if reported_kloc:
        try:
            kloc = float(reported_kloc)
        except ValueError as exc:
            raise ValueError(
                f"enrichment changed_kloc 非数值: {reported_kloc}"
            ) from exc
        if not math.isclose(
            kloc,
            changed_lines / 1000,
            rel_tol=0,
            abs_tol=5e-7,
        ):
            raise ValueError(
                "enrichment changed_kloc 与 additions+deletions 不守恒: "
                f"{row.get('group')} {row.get('repo_name')}#{row.get('pr_number')}"
            )
    return {
        "enrichment_available": "true",
        "additions": additions,
        "deletions": deletions,
        "changed_lines": changed_lines,
        "changed_files": row.get("changed_files", ""),
        "file_list_complete": row.get("file_list_complete", ""),
        "enrichment_source": row.get("source", ""),
        "enrichment_fetched_at": row.get("fetched_at", ""),
        "changed_kloc": f"{changed_lines / 1000:.6f}",
    }


def pair_jobs(rows: list[dict[str, str]]) -> dict[tuple[str, str], list[dict[str, str]]]:
    output: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        output[pr_key(row)].append(row)
    return output


def index_unique(
    rows: list[dict[str, str]], label: str
) -> tuple[dict[tuple[str, str], dict[str, str]], list[tuple[str, str]]]:
    output: dict[tuple[str, str], dict[str, str]] = {}
    duplicates: list[tuple[str, str]] = []
    for row in rows:
        key = pr_key(row)
        if key in output:
            duplicates.append(key)
        output[key] = row
    if any(not key[0] or not key[1] for key in output):
        raise ValueError(f"{label} 含空 repo_name/pr_number")
    return output, duplicates


def index_enrichment(
    rows: list[dict[str, str]],
) -> tuple[
    dict[tuple[str, str, str], dict[str, str]],
    list[tuple[str, str, str]],
]:
    output: dict[tuple[str, str, str], dict[str, str]] = {}
    duplicates: list[tuple[str, str, str]] = []
    for row in rows:
        key = enrichment_key(row)
        if key in output:
            duplicates.append(key)
        output[key] = row
    if any(not all(key) for key in output):
        raise ValueError("pr_enrichment.csv 含空 group/repo_name/pr_number")
    return output, duplicates


def job_pair_complete(jobs: list[dict[str, str]]) -> bool:
    by_revision = {row.get("revision"): row for row in jobs}
    return (
        set(by_revision) == {"before", "after"}
        and all(row.get("status") == "completed" for row in by_revision.values())
    )


def job_pair_terminal(jobs: list[dict[str, str]]) -> bool:
    if any(truthy(row.get("retry_excluded")) for row in jobs):
        return True
    return bool(jobs) and all(
        row.get("status") in TERMINAL_JOB_STATUSES for row in jobs
    )


def common_value(rows: list[dict[str, str]], field: str) -> str:
    values = {clean(row.get(field)) for row in rows if clean(row.get(field))}
    return next(iter(values)) if len(values) == 1 else "|".join(sorted(values))


def failure_stage(jobs: list[dict[str, str]]) -> str:
    statuses = {row.get("status", "") for row in jobs}
    if "prepare_failed" in statuses:
        return "prepare"
    if "database_failed" in statuses:
        return "database"
    if "analysis_failed" in statuses:
        return "analysis"
    return ""


def failure_reason(jobs: list[dict[str, str]]) -> str:
    errors = [clean(row.get("last_error")) for row in jobs if clean(row.get("last_error"))]
    if not errors:
        return ""
    text = " | ".join(dict.fromkeys(errors)).casefold()
    if any(term in text for term in ("timed out", "timeout", "超时")):
        return "timeout"
    if any(term in text for term in ("github.com", "ssl", "connection", "network")):
        return "network"
    if any(term in text for term in ("not found", "找不到", "404")):
        return "repo_or_pr_unavailable"
    if "larger than the limit" in text or "2gib" in text:
        return "result_too_large"
    if "build" in text or "建库" in text:
        return "build_error"
    return "other"


def family_metadata_complete(summary: dict[str, str] | None) -> bool:
    return bool(summary) and all(integer(summary.get(field)) is not None for field in FAMILY_COUNT_FIELDS)


def family_counts_conserve(summary: dict[str, str]) -> bool:
    if not family_metadata_complete(summary):
        return False
    equations = (
        ("before_alerts", "before_security_alerts", "before_quality_alerts"),
        ("after_alerts", "after_security_alerts", "after_quality_alerts"),
        ("introduced_alerts", "introduced_security_alerts", "introduced_quality_alerts"),
        ("fixed_alerts", "fixed_security_alerts", "fixed_quality_alerts"),
        ("persistent_alerts", "persistent_security_alerts", "persistent_quality_alerts"),
    )
    return all(
        integer(summary.get(total))
        == integer(summary.get(security)) + integer(summary.get(quality))  # type: ignore[operator]
        for total, security, quality in equations
    )


def derive_family_values(row: dict[str, Any], family: str) -> None:
    introduced = integer(row.get(f"introduced_{family}_alerts"))
    fixed = integer(row.get(f"fixed_{family}_alerts"))
    if introduced is None or fixed is None:
        row[f"introduced_{family}_any"] = ""
        row[f"fixed_{family}_any"] = ""
        row[f"net_{family}_count"] = ""
        return
    row[f"introduced_{family}_any"] = int(introduced > 0)
    row[f"fixed_{family}_any"] = int(fixed > 0)
    row[f"net_{family}_count"] = introduced - fixed


def build_analysis_rows(
    snapshot_id: str,
    group: str,
    prs: list[dict[str, str]],
    jobs: list[dict[str, str]],
    summaries: list[dict[str, str]],
    overlap: set[tuple[str, str]],
    enrichment_index: dict[tuple[str, str, str], dict[str, str]],
) -> tuple[list[dict[str, Any]], list[tuple[str, str]], list[tuple[str, str]]]:
    pr_index, pr_duplicates = index_unique(prs, f"{group}/prs.csv")
    summary_index, summary_duplicates = index_unique(
        summaries, f"{group}/results/pr_security_summary.csv"
    )
    jobs_by_pr = pair_jobs(jobs)
    output: list[dict[str, Any]] = []
    for key, pr in pr_index.items():
        pair = jobs_by_pr.get(key, [])
        summary = summary_index.get(key)
        enrichment = enrichment_index.get((group, *key))
        size = enrichment_size(enrichment)
        excluded = any(truthy(job.get("retry_excluded")) for job in pair)
        paired = job_pair_complete(pair)
        metadata_complete = family_metadata_complete(summary)
        overlap_flag = key in overlap
        compared = clean((summary or {}).get("comparison_status"))
        reasons: list[str] = []
        stars = integer(pr.get("stars"))
        if stars is None:
            reasons.append("stars_missing")
        elif stars < 500:
            reasons.append("stars_below_500")
        if pr.get("language") not in ALLOWED_LANGUAGES:
            reasons.append("language_out_of_scope")
        if pr.get("task_type") not in ALLOWED_TASK_TYPES:
            reasons.append("task_type_out_of_scope")
        if overlap_flag:
            reasons.append("cross_group_overlap")
        if excluded:
            reasons.append("retry_excluded")
        if not paired:
            reasons.append("before_after_not_completed")
        if compared != "compared":
            reasons.append(f"comparison_{compared or 'missing'}")
        if not metadata_complete:
            reasons.append("family_metadata_missing")
        if summary and metadata_complete and not family_counts_conserve(summary):
            reasons.append("family_count_conservation_failed")
        quality_gate = not reasons
        row: dict[str, Any] = {
            "snapshot_id": snapshot_id,
            "analysis_status": "eligible" if quality_gate else "excluded",
            "group": group,
            "repo_name": pr.get("repo_name", ""),
            "pr_number": normalize_number(pr.get("pr_number")),
            "pr_id": pr.get("pr_id", ""),
            "agent": pr.get("agent", ""),
            "repo_language": pr.get("language", ""),
            "task_type": pr.get("task_type", ""),
            "stars": pr.get("stars", ""),
            "forks": pr.get("forks", ""),
            "merged_at": (enrichment or {}).get("merged_at", "")
            or pr.get("merged_at", ""),
            **size,
            **{field: pr.get(field, "") for field in SIZE_FIELDS},
            "base_sha": (summary or {}).get("base_sha", "") or common_value(pair, "base_sha"),
            "head_sha": (summary or {}).get("head_sha", "") or common_value(pair, "head_sha"),
            "codeql_version": (summary or {}).get("codeql_version", "") or common_value(pair, "codeql_version"),
            "query_suite": (summary or {}).get("query_suite", "") or common_value(pair, "query_suite"),
            "build_mode": common_value(pair, "build_mode"),
            "retry_excluded": str(excluded).lower(),
            "paired": str(paired).lower(),
            "family_metadata_complete": str(metadata_complete).lower(),
            "group_overlap": str(overlap_flag).lower(),
            "quality_gate_pass": str(quality_gate).lower(),
            "comparison_status": compared or "missing",
            "job_statuses": "|".join(sorted(Counter(job.get("status", "") for job in pair).elements())),
            "failure_stage": failure_stage(pair),
            "failure_reason": failure_reason(pair),
            "exclusion_reason": ";".join(reasons),
        }
        for field in (
            "before_alerts",
            "after_alerts",
            "introduced_alerts",
            "fixed_alerts",
            "persistent_alerts",
            *FAMILY_COUNT_FIELDS,
        ):
            row[field] = (summary or {}).get(field, "")
        derive_family_values(row, "security")
        derive_family_values(row, "quality")
        output.append(row)
    return output, pr_duplicates, summary_duplicates


def wilson(successes: int, total: int) -> tuple[float, float]:
    if total == 0:
        return math.nan, math.nan
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = proportion + z * z / (2 * total)
    margin = z * math.sqrt(
        proportion * (1 - proportion) / total + z * z / (4 * total * total)
    )
    return (centre - margin) / denominator, (centre + margin) / denominator


def percentile(values: list[int], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return math.nan
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def descriptive_record(
    rows: list[dict[str, Any]], group: str, family: str, task_type: str = "all"
) -> dict[str, Any]:
    selected = [
        row
        for row in rows
        if row["group"] == group
        and truthy(row["quality_gate_pass"])
        and (task_type == "all" or row["task_type"] == task_type)
    ]
    introduced = [integer(row[f"introduced_{family}_alerts"]) or 0 for row in selected]
    introduced_any = sum(value > 0 for value in introduced)
    introduced_ci = wilson(introduced_any, len(selected))
    return {
        "group": group,
        "family": family,
        "task_type": task_type,
        "pr_n": len(selected),
        "repo_n": len({row["repo_name"].casefold() for row in selected}),
        "introduced_count": sum(introduced),
        "introduced_any_n": introduced_any,
        "introduced_any_proportion": introduced_any / len(selected) if selected else "",
        "introduced_any_ci_low": introduced_ci[0] if selected else "",
        "introduced_any_ci_high": introduced_ci[1] if selected else "",
        "introduced_mean": statistics.fmean(introduced) if introduced else "",
        "introduced_median": statistics.median(introduced) if introduced else "",
        "introduced_p25": percentile(introduced, 0.25) if introduced else "",
        "introduced_p75": percentile(introduced, 0.75) if introduced else "",
        "introduced_p90": percentile(introduced, 0.90) if introduced else "",
        "introduced_max": max(introduced) if introduced else "",
        "introduced_zero_proportion": sum(value == 0 for value in introduced) / len(introduced) if introduced else "",
        "introduced_per_100_pr": 100 * sum(introduced) / len(selected) if selected else "",
    }


def check_record(
    check_id: str,
    group: str,
    passed: bool,
    severity: str,
    count: int,
    denominator: int,
    detail: str,
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "group": group,
        "passed": str(passed).lower(),
        "severity": severity,
        "count": count,
        "denominator": denominator,
        "detail": detail,
    }


def markdown_report(
    snapshot_id: str,
    mode: str,
    rows: list[dict[str, Any]],
    checks: list[dict[str, Any]],
    rq1_introduced_ready: bool,
    rq1_ready: bool,
    rq2_ready: bool,
    rq3_frame_ready: bool,
) -> str:
    blockers = [row for row in checks if row["severity"] == "blocker" and row["passed"] == "false"]
    lines = [
        "# Introduced-Quality-first RQ1–RQ3 数据完整性与分析就绪报告",
        "",
        f"- Snapshot: `{snapshot_id}`",
        f"- Mode: `{mode}`",
        f"- RQ1 introduced-alert data ready: **{'yes' if rq1_introduced_ready else 'no'}**",
        f"- RQ1 full ready: **{'yes' if rq1_ready else 'no'}**",
        f"- RQ2 ready: **{'yes' if rq2_ready else 'no'}**",
        f"- RQ3 review frame ready: **{'yes' if rq3_frame_ready else 'no'}**",
        "- 主结果族：Quality；次级结果族：Security。",
        "- 本报告由只读输入快照生成；不会修改正在运行的实验。",
        "",
        "## 当前漏斗",
        "",
        "| Group | Manifest PRs | Terminal PRs | Compared PRs | Enhanced metadata | Quality-gated PRs | Enriched gated PRs |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for group in GROUPS:
        selected = [row for row in rows if row["group"] == group]
        terminal = sum(
            row["comparison_status"] in {"compared", "failed"}
            or bool(row["failure_stage"])
            or truthy(row["retry_excluded"])
            for row in selected
        )
        lines.append(
            f"| {group.upper()} | {len(selected)} | {terminal} | "
            f"{sum(row['comparison_status'] == 'compared' for row in selected)} | "
            f"{sum(truthy(row['family_metadata_complete']) for row in selected)} | "
            f"{sum(truthy(row['quality_gate_pass']) for row in selected)} | "
            f"{sum(truthy(row['quality_gate_pass']) and truthy(row['enrichment_available']) for row in selected)} |"
        )
    lines.extend(["", "## 阻断项", ""])
    if blockers:
        lines.extend(
            f"- `{row['check_id']}` ({row['group']}): {row['detail']}"
            for row in blockers
        )
    else:
        lines.append("- 无。")
    lines.extend(["", "## 下一步", ""])
    if rq2_ready:
        lines.extend(
            [
                "1. 冻结 outcome-blind 全量分析名单；所有可比较 PR 等权进入分析。",
                "2. 核验 AI/Human 原始分母后运行 Quality primary / Security secondary RQ2 模型。",
                "3. 从同一 snapshot 构造 RQ3 Quality/Security reference-alert frame。",
                "",
                "本快照的 `changed_kloc` 统一定义为 "
                "`(GitHub additions + deletions) / 1000`；失败或排除 PR 不要求 enrichment。",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "1. 仅处理上方 blocker，不得用 provisional snapshot 报告 AI–Human 效应。",
                "2. 所有 quality-gated PR 必须具有统一 GitHub additions+deletions。",
                "3. RQ2 内 Quality 与 Security 始终分开建模和报告。",
                "",
            ]
        )
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    study_root = resolve(args.study_root)
    output_dir = resolve(
        args.output_dir or study_root / "reports" / "rq_analysis"
    )
    generated_at = datetime.now(timezone.utc)
    snapshot_id = args.snapshot_id or generated_at.strftime("%Y%m%dT%H%M%SZ")

    datasets: dict[str, dict[str, Any]] = {}
    input_paths: list[Path] = []
    enrichment_path = resolve(
        args.enrichment_csv or study_root / DEFAULT_ENRICHMENT_RELATIVE
    )
    if not enrichment_path.is_file():
        raise SystemExit(f"缺少统一 PR enrichment: {enrichment_path}")
    enrichment_fields, enrichment_rows = read_stable_csv(
        enrichment_path, args.read_retries
    )
    required_enrichment_fields = {
        "group",
        "repo_name",
        "pr_number",
        "additions",
        "deletions",
        "changed_kloc",
    }
    missing_enrichment_fields = required_enrichment_fields - set(
        enrichment_fields
    )
    if missing_enrichment_fields:
        raise SystemExit(
            "PR enrichment 缺少字段: "
            f"{sorted(missing_enrichment_fields)}"
        )
    enrichment_index, enrichment_duplicates = index_enrichment(enrichment_rows)
    if enrichment_duplicates:
        raise SystemExit(
            f"PR enrichment 含重复 group/repo/PR: {enrichment_duplicates[:5]}"
        )
    input_paths.append(enrichment_path)
    enrichment_manifest_path = resolve(
        args.enrichment_manifest
        or study_root / DEFAULT_ENRICHMENT_MANIFEST_RELATIVE
    )
    if enrichment_manifest_path.is_file():
        input_paths.append(enrichment_manifest_path)
    for provenance_path in (
        Path(__file__).resolve(),
        ROOT / "config" / "study" / "model_specification.yaml",
        ROOT / "config" / "study" / "quality_rule_taxonomy.json",
        ROOT / "config" / "study" / "pr_enrichment_rules.json",
    ):
        if provenance_path.is_file():
            input_paths.append(provenance_path)
    for group in GROUPS:
        group_root = study_root / group
        results_override = getattr(args, f"{group}_results_dir")
        results_dir = (
            resolve(results_override)
            if results_override is not None
            else group_root / "results"
        )
        paths = {
            "prs": group_root / "prs.csv",
            "jobs": group_root / "codeql_jobs.csv",
            "summary": results_dir / "pr_security_summary.csv",
        }
        for path in paths.values():
            if not path.is_file():
                raise SystemExit(f"缺少输入文件: {path}")
            input_paths.append(path)
        datasets[group] = {}
        for name, path in paths.items():
            fields, rows = read_stable_csv(path, args.read_retries)
            datasets[group][name] = rows
            datasets[group][f"{name}_fields"] = fields

    pr_indexes = {
        group: index_unique(datasets[group]["prs"], f"{group}/prs.csv")[0]
        for group in GROUPS
    }
    overlap = set(pr_indexes["ai"]) & set(pr_indexes["human"])
    overlap_rows = [
        {
            "repo_name": pr_indexes["ai"][key]["repo_name"],
            "pr_number": key[1],
            "ai_pr_id": pr_indexes["ai"][key].get("pr_id", ""),
            "human_pr_id": pr_indexes["human"][key].get("pr_id", ""),
            "decision": "exclude_both_primary_analysis",
            "reason": "same repository and PR number appears in both authorship groups",
        }
        for key in sorted(overlap)
    ]

    analysis_rows: list[dict[str, Any]] = []
    duplicate_info: dict[str, tuple[list[tuple[str, str]], list[tuple[str, str]]]] = {}
    for group in GROUPS:
        rows, pr_duplicates, summary_duplicates = build_analysis_rows(
            snapshot_id,
            group,
            datasets[group]["prs"],
            datasets[group]["jobs"],
            datasets[group]["summary"],
            overlap,
            enrichment_index,
        )
        analysis_rows.extend(rows)
        duplicate_info[group] = pr_duplicates, summary_duplicates

    checks: list[dict[str, Any]] = []
    attrition: list[dict[str, Any]] = []
    configuration: list[dict[str, Any]] = []
    eligibility: list[dict[str, Any]] = []
    groups_terminal: dict[str, bool] = {}
    groups_enhanced: dict[str, bool] = {}
    groups_size_complete: dict[str, bool] = {}
    for group in GROUPS:
        group_rows = [row for row in analysis_rows if row["group"] == group]
        jobs_by_pr = pair_jobs(datasets[group]["jobs"])
        terminal_n = sum(job_pair_terminal(jobs_by_pr.get(pr_key_value, [])) for pr_key_value in pr_indexes[group])
        compared_n = sum(row["comparison_status"] == "compared" for row in group_rows)
        enhanced_n = sum(truthy(row["family_metadata_complete"]) for row in group_rows if row["comparison_status"] == "compared")
        gate_n = sum(truthy(row["quality_gate_pass"]) for row in group_rows)
        gate_rows = [
            row for row in group_rows if truthy(row["quality_gate_pass"])
        ]
        size_n = sum(
            truthy(row["enrichment_available"]) and bool(row["changed_kloc"])
            for row in gate_rows
        )
        complete_file_list_n = sum(
            truthy(row["file_list_complete"]) for row in gate_rows
        )
        eligibility_reasons = Counter(
            reason
            for row in group_rows
            for reason in row["exclusion_reason"].split(";")
            if reason in SELECTION_EXCLUSION_REASONS
        )
        for reason, count in sorted(eligibility_reasons.items()):
            eligibility.append(
                {
                    "group": group,
                    "decision": "exclude",
                    "reason": reason,
                    "pr_n": count,
                }
            )
        eligible_metadata_n = sum(
            not any(
                reason in SELECTION_EXCLUSION_REASONS
                for reason in row["exclusion_reason"].split(";")
            )
            for row in group_rows
        )
        eligibility.append(
            {
                "group": group,
                "decision": "retain",
                "reason": "primary_metadata_eligible",
                "pr_n": eligible_metadata_n,
            }
        )
        groups_terminal[group] = terminal_n == len(group_rows)
        groups_enhanced[group] = enhanced_n == compared_n and compared_n > 0
        groups_size_complete[group] = size_n == gate_n and gate_n > 0
        for stage, count, note in (
            ("manifest_prs", len(group_rows), "prs.csv"),
            ("terminal_prs", terminal_n, "all jobs terminal or retry_excluded"),
            ("compared_prs", compared_n, "pr_security_summary comparison_status=compared"),
            ("enhanced_metadata_prs", enhanced_n, "explicit Security/Quality family counts"),
            ("quality_gate_prs", gate_n, "primary analysis eligible"),
            (
                "enriched_quality_gate_prs",
                size_n,
                "quality-gated PRs with GitHub additions+deletions",
            ),
        ):
            attrition.append({"group": group, "stage": stage, "pr_n": count, "note": note})
        checks.extend(
            [
                check_record("experiment_terminal", group, groups_terminal[group], "blocker", terminal_n, len(group_rows), "所有 PR 作业必须进入终态"),
                check_record("enhanced_family_metadata", group, groups_enhanced[group], "blocker", enhanced_n, compared_n, "所有已比较 PR 必须具有互斥且穷尽的 Security/Quality 计数"),
                check_record("changed_size_complete", group, groups_size_complete[group], "blocker", size_n, gate_n, "所有 quality-gated PR 必须具有统一 GitHub additions+deletions 口径的 Changed KLOC"),
                check_record(
                    "enrichment_file_list_complete",
                    group,
                    complete_file_list_n == gate_n,
                    "info",
                    complete_file_list_n,
                    gate_n,
                    "文件列表完整性仅影响文件级派生敏感性，不影响 PR-level Changed KLOC",
                ),
                check_record("unique_manifest_pr", group, not duplicate_info[group][0], "blocker", len(duplicate_info[group][0]), len(group_rows), "repo_name+pr_number 在 prs.csv 中必须唯一"),
                check_record("unique_summary_pr", group, not duplicate_info[group][1], "blocker", len(duplicate_info[group][1]), len(datasets[group]["summary"]), "repo_name+pr_number 在 summary 中必须唯一"),
            ]
        )
        config_counter = Counter(
            (
                row["codeql_version"],
                row["query_suite"],
                row["repo_language"],
                row["build_mode"],
            )
            for row in group_rows
            if row["comparison_status"] == "compared"
        )
        for (version, suite, language, build_mode), count in sorted(config_counter.items()):
            configuration.append(
                {
                    "group": group,
                    "codeql_version": version,
                    "query_suite": suite,
                    "language": language,
                    "build_mode": build_mode,
                    "pr_n": count,
                }
            )

    checks.append(
        check_record(
            "cross_group_overlap_resolved",
            "both",
            True,
            "info",
            len(overlap),
            len(analysis_rows),
            f"发现 {len(overlap)} 个重叠 PR；主分析数据已从两组同时排除并写入审计表",
        )
    )
    # RQ1 is an AI-only descriptive question and can become analysis-ready
    # independently of the still-running Human batch. RQ2 requires both
    # authorship groups. RQ3 case construction is delayed until the same final
    # frame used by RQ2 is frozen.
    rq1_introduced_ready = groups_terminal["ai"] and groups_enhanced["ai"]
    rq1_ready = rq1_introduced_ready and groups_size_complete["ai"]
    rq2_ready = (
        all(groups_terminal.values())
        and all(groups_enhanced.values())
        and all(groups_size_complete.values())
    )
    rq3_frame_ready = rq2_ready

    selection_eligible = [
        row
        for row in analysis_rows
        if not (
            set(row["exclusion_reason"].split(";"))
            & SELECTION_EXCLUSION_REASONS
        )
    ]
    shared_repositories = {
        row["repo_name"].casefold()
        for row in selection_eligible
        if row["group"] == "ai"
    } & {
        row["repo_name"].casefold()
        for row in selection_eligible
        if row["group"] == "human"
    }
    common_support: list[dict[str, Any]] = []
    strata = sorted(
        {
            (row["repo_language"], row["task_type"])
            for row in selection_eligible
        }
    )
    for language, task_type in strata:
        counts: dict[str, int] = {}
        shared_counts: dict[str, int] = {}
        for group in GROUPS:
            selected = [
                row
                for row in selection_eligible
                if row["group"] == group
                and row["repo_language"] == language
                and row["task_type"] == task_type
            ]
            counts[group] = len(selected)
            shared_counts[group] = sum(
                row["repo_name"].casefold() in shared_repositories
                for row in selected
            )
        common_support.append(
            {
                "language": language,
                "task_type": task_type,
                "ai_pr_n": counts["ai"],
                "human_pr_n": counts["human"],
                "both_groups_present": str(
                    counts["ai"] > 0 and counts["human"] > 0
                ).lower(),
                "ai_shared_repo_pr_n": shared_counts["ai"],
                "human_shared_repo_pr_n": shared_counts["human"],
            }
        )

    descriptive_fields = list(
        descriptive_record([], "ai", "security").keys()
    )
    descriptive_rows: list[dict[str, Any]] = []
    for group in GROUPS:
        if not groups_enhanced[group]:
            continue
        for family in ("quality", "security"):
            descriptive_rows.append(descriptive_record(analysis_rows, group, family))
            for task_type in ("fix", "feat", "refactor"):
                descriptive_rows.append(
                    descriptive_record(analysis_rows, group, family, task_type)
                )

    rq1_quality_rows = [
        row
        for row in descriptive_rows
        if row["group"] == "ai" and row["family"] == "quality"
    ]
    rq2_quality_rows = [
        row for row in descriptive_rows if row["family"] == "quality"
    ]
    secondary_security_rows = [
        row for row in descriptive_rows if row["family"] == "security"
    ]

    write_csv(output_dir / "analysis_pr_level.csv", ANALYSIS_FIELDS, analysis_rows)
    write_csv(
        output_dir / "attrition_funnel.csv",
        ("group", "stage", "pr_n", "note"),
        attrition,
    )
    write_csv(
        output_dir / "data_quality_checks.csv",
        ("check_id", "group", "passed", "severity", "count", "denominator", "detail"),
        checks,
    )
    write_csv(
        output_dir / "group_overlap_audit.csv",
        ("repo_name", "pr_number", "ai_pr_id", "human_pr_id", "decision", "reason"),
        overlap_rows,
    )
    write_csv(
        output_dir / "configuration_compatibility.csv",
        ("group", "codeql_version", "query_suite", "language", "build_mode", "pr_n"),
        configuration,
    )
    write_csv(
        output_dir / "eligibility_audit.csv",
        ("group", "decision", "reason", "pr_n"),
        eligibility,
    )
    write_csv(
        output_dir / "common_support_audit.csv",
        (
            "language",
            "task_type",
            "ai_pr_n",
            "human_pr_n",
            "both_groups_present",
            "ai_shared_repo_pr_n",
            "human_shared_repo_pr_n",
        ),
        common_support,
    )
    write_csv(
        output_dir / "rq1_rq2_descriptive.csv",
        descriptive_fields,
        descriptive_rows,
    )
    write_csv(
        output_dir / "rq1_quality_descriptive.csv",
        descriptive_fields,
        rq1_quality_rows,
    )
    write_csv(
        output_dir / "rq2_quality_descriptive.csv",
        descriptive_fields,
        rq2_quality_rows,
    )
    write_csv(
        output_dir / "secondary_security_descriptive.csv",
        descriptive_fields,
        secondary_security_rows,
    )

    readiness_path = output_dir / "analysis_readiness.md"
    write_text(
        readiness_path,
        markdown_report(
            snapshot_id,
            args.mode,
            analysis_rows,
            checks,
            rq1_introduced_ready,
            rq1_ready,
            rq2_ready,
            rq3_frame_ready,
        ),
    )
    output_names = [
        "analysis_pr_level.csv",
        "attrition_funnel.csv",
        "data_quality_checks.csv",
        "group_overlap_audit.csv",
        "configuration_compatibility.csv",
        "eligibility_audit.csv",
        "common_support_audit.csv",
        "rq1_rq2_descriptive.csv",
        "rq1_quality_descriptive.csv",
        "rq2_quality_descriptive.csv",
        "secondary_security_descriptive.csv",
        "analysis_readiness.md",
    ]
    manifest = {
        "snapshot_id": snapshot_id,
        "generated_at_utc": generated_at.isoformat(),
        "mode": args.mode,
        "status": "final_ready" if rq2_ready else "provisional",
        "rq1_introduced_ready": rq1_introduced_ready,
        "rq1_ready": rq1_ready,
        "rq2_ready": rq2_ready,
        "rq3_frame_ready": rq3_frame_ready,
        "git_commit": git_revision(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "analysis_population": {
            group: {
                "manifest_pr_n": sum(
                    row["group"] == group for row in analysis_rows
                ),
                "quality_gated_pr_n": sum(
                    row["group"] == group
                    and truthy(row["quality_gate_pass"])
                    for row in analysis_rows
                ),
                "enriched_quality_gated_pr_n": sum(
                    row["group"] == group
                    and truthy(row["quality_gate_pass"])
                    and truthy(row["enrichment_available"])
                    for row in analysis_rows
                ),
            }
            for group in GROUPS
        },
        "changed_kloc_definition": (
            "(GitHub REST PR additions + deletions) / 1000"
        ),
        "inputs": [
            {
                "path": str(path),
                "size": path.stat().st_size,
                "mtime_ns": path.stat().st_mtime_ns,
                "sha256": sha256(path),
            }
            for path in input_paths
        ],
        "outputs": [
            {
                "path": name,
                "size": (output_dir / name).stat().st_size,
                "sha256": sha256(output_dir / name),
            }
            for name in output_names
        ],
    }
    write_text(
        output_dir / "snapshot_manifest.json",
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
    )
    print(
        f"已生成 {'最终' if rq2_ready else '临时'} "
        f"Introduced-Quality-first RQ1–RQ3 分析快照: {output_dir}"
    )
    print(
        f"RQ1 introduced-alert data ready={rq1_introduced_ready}; "
        f"RQ1 full ready={rq1_ready}; RQ2 ready={rq2_ready}; "
        f"RQ3 review frame ready={rq3_frame_ready}"
    )
    if args.mode == "final" and not rq2_ready:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
