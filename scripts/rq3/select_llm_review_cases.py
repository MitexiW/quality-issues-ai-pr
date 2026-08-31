#!/usr/bin/env python3
# RQ3 review experiment entry point.
"""Select reproducible RQ3 reference-positive PRs and CodeQL-negative controls."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FIELDS = [
    "case_id",
    "case_control",
    "target_family",
    "group",
    "repo_name",
    "pr_number",
    "pr_id",
    "language",
    "task_type",
    "changed_kloc",
    "merge_calendar_quarter",
    "silver_finding_n",
    "matched_positive_case_id",
    "same_repository_match",
    "control_match_score",
    "selection_probability",
    "sampling_weight",
    "split",
    "random_seed",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="构造 RQ3 positive/control PR 样本")
    parser.add_argument("--pr-pool", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--silver-findings")
    source.add_argument(
        "--confirmed-findings",
        help="已弃用的兼容别名；输入仍按 CodeQL silver findings 处理",
    )
    parser.add_argument(
        "--alert-family",
        choices=["quality", "security", "both"],
        default="quality",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--positive-target", type=int, default=20)
    parser.add_argument(
        "--all-positives",
        action="store_true",
        help="选择目标 reference 文件中的全部 positive PR",
    )
    parser.add_argument("--controls-per-positive", type=int, default=1)
    parser.add_argument(
        "--control-target-per-group",
        type=int,
        help=(
            "每个 AI/Human group 独立选择的 control 数；指定后不再为每个"
            " positive 配一个 control，而是从 positive 的 task/language 分布"
            "中分层选择 matching anchors"
        ),
    )
    parser.add_argument("--split", choices=["pilot", "formal"], default="pilot")
    parser.add_argument("--seed", type=int, default=20260623)
    parser.add_argument("--exclude-cases")
    parser.add_argument(
        "--selected-reference-alerts-output",
        help="默认写入 cases CSV 同目录的 selected_reference_alerts.csv",
    )
    parser.add_argument(
        "--all-case-reference-alerts-output",
        help=(
            "默认写入 cases CSV 同目录的 all_case_reference_alerts.csv；"
            "该隔离文件保存所选 PR 的两类 actionable references，防止把"
            "模型正确报告的非目标 family 告警误算为 unmatched"
        ),
    )
    parser.add_argument(
        "--all-family-findings",
        help=(
            "用于 all-case reference 表的 broad Quality + Security reference "
            "文件；未指定时复用 --silver-findings"
        ),
    )
    parser.add_argument(
        "--manifest-output",
        help="默认写入 cases CSV 同目录的 selection_manifest.json",
    )
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            break
        except OverflowError:
            limit //= 10
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    fieldnames: list[str],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def analysis_eligible(row: dict[str, Any]) -> bool:
    if "analysis_eligible" in row:
        return truthy(row.get("analysis_eligible"))
    if "quality_gate_pass" in row:
        return truthy(row.get("quality_gate_pass"))
    return True


def language(row: dict[str, Any]) -> str:
    return str(row.get("language") or row.get("repo_language") or "").strip()


def key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("group", "")).lower(),
        str(row.get("repo_name", "")).lower(),
        str(row.get("pr_number", "")),
    )


def float_value(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return math.nan


def quarter(value: str) -> str:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return ""
    return f"{timestamp.year}-Q{(timestamp.month - 1) // 3 + 1}"


def quarter_distance(first: str, second: str) -> int:
    def number(value: str) -> int | None:
        if "-Q" not in value:
            return None
        year, raw_quarter = value.split("-Q", 1)
        try:
            return int(year) * 4 + int(raw_quarter)
        except ValueError:
            return None

    a, b = number(first), number(second)
    return abs(a - b) if a is not None and b is not None else 20


def finding_family(row: dict[str, str]) -> str:
    family = row.get("alert_category", "").strip().lower()
    if family in {"quality", "security"}:
        return family
    if truthy(row.get("is_quality_alert", "")):
        return "quality"
    if truthy(row.get("is_security_alert", "")):
        return "security"
    return ""


def is_silver_finding(row: dict[str, str], family: str) -> bool:
    lifecycle = row.get("lifecycle", "").strip().lower()
    if lifecycle and lifecycle != "introduced":
        return False
    detected_family = finding_family(row)
    return not detected_family or detected_family == family


def select_positive_keys(
    silver: list[dict[str, str]],
    target: int | None,
    seed: int,
    excluded: set[tuple[str, str, str]],
) -> tuple[list[tuple[str, str, str]], dict[str, float], Counter]:
    counts = Counter(key(row) for row in silver)
    by_group: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for identifier in sorted(counts):
        if identifier not in excluded:
            by_group[identifier[0]].append(identifier)
    available = sum(len(rows) for rows in by_group.values())
    if target is None:
        selected = [
            identifier
            for group in sorted(by_group)
            for identifier in by_group[group]
        ]
        return (
            sorted(selected),
            {group: 1.0 for group in by_group},
            counts,
        )
    target = min(target, available)
    groups = sorted(by_group)
    allocation = {group: 0 for group in groups}
    if target >= len(groups):
        for group in groups:
            allocation[group] = 1
    remaining = target - sum(allocation.values())
    while remaining:
        candidates = [
            group for group in groups if allocation[group] < len(by_group[group])
        ]
        if not candidates:
            break
        group = min(candidates, key=lambda item: (allocation[item], item))
        allocation[group] += 1
        remaining -= 1
    selected = []
    probabilities = {}
    for group in groups:
        population = by_group[group]
        sample_n = allocation[group]
        chosen = random.Random(seed + sum(map(ord, group))).sample(population, sample_n)
        selected.extend(chosen)
        probability = sample_n / len(population) if population else 0
        probabilities[group] = probability
    return sorted(selected), probabilities, counts


def control_score(positive: dict[str, Any], control: dict[str, Any]) -> tuple[Any, ...]:
    same_repo = positive["repo_name"].lower() == control["repo_name"].lower()
    same_language = positive.get("language", "") == control.get("language", "")
    a = float_value(positive.get("changed_kloc"))
    b = float_value(control.get("changed_kloc"))
    size_distance = abs(math.log1p(a) - math.log1p(b)) if not math.isnan(a + b) else 100
    time_distance = quarter_distance(
        positive.get("merge_calendar_quarter", ""),
        control.get("merge_calendar_quarter", ""),
    )
    return (
        0 if same_repo else 1,
        0 if same_language else 1,
        size_distance,
        time_distance,
        control["repo_name"].lower(),
        int(control["pr_number"]),
    )


def stratified_control_anchors(
    positives: list[dict[str, Any]],
    target_per_group: int,
    seed: int,
) -> list[dict[str, Any]]:
    """Select deterministic anchors preserving each group's task/language mix."""

    if target_per_group < 1:
        raise ValueError("control-target-per-group 必须大于 0")
    selected: list[dict[str, Any]] = []
    for group in sorted({str(row.get("group", "")).lower() for row in positives}):
        population = [
            row
            for row in positives
            if str(row.get("group", "")).lower() == group
        ]
        if len(population) < target_per_group:
            raise ValueError(
                f"{group} positive 不足以构造 {target_per_group} 个 control anchors"
            )
        strata: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in population:
            strata[
                (
                    str(row.get("task_type", "")),
                    str(row.get("language", "")),
                )
            ].append(row)
        allocation: dict[tuple[str, str], int] = {}
        remainders: list[tuple[float, tuple[str, str]]] = []
        assigned = 0
        for stratum, rows in sorted(strata.items()):
            exact = target_per_group * len(rows) / len(population)
            base = min(len(rows), math.floor(exact))
            allocation[stratum] = base
            assigned += base
            remainders.append((exact - base, stratum))
        while assigned < target_per_group:
            candidates = [
                (remainder, stratum)
                for remainder, stratum in remainders
                if allocation[stratum] < len(strata[stratum])
            ]
            if not candidates:
                raise ValueError(f"{group} control anchor allocation failed")
            _remainder, chosen_stratum = max(
                candidates,
                key=lambda item: (item[0], item[1]),
            )
            allocation[chosen_stratum] += 1
            assigned += 1
            remainders = [
                (
                    remainder - 1 if stratum == chosen_stratum else remainder,
                    stratum,
                )
                for remainder, stratum in remainders
            ]
        for offset, (stratum, rows) in enumerate(sorted(strata.items())):
            sample_n = allocation[stratum]
            if not sample_n:
                continue
            ordered = sorted(rows, key=lambda row: row["case_id"])
            selected.extend(
                random.Random(
                    seed
                    + sum(map(ord, group))
                    + sum(map(ord, "|".join(stratum)))
                    + offset
                ).sample(ordered, sample_n)
            )
    return sorted(selected, key=lambda row: (row["group"], row["case_id"]))


def build_cases(
    pr_pool: list[dict[str, str]],
    silver: list[dict[str, str]],
    positive_target: int | None,
    controls_per_positive: int,
    split: str,
    seed: int,
    excluded: set[tuple[str, str, str]],
    alert_family: str = "quality",
    control_target_per_group: int | None = None,
) -> list[dict[str, Any]]:
    if controls_per_positive < 1:
        raise ValueError("controls_per_positive 必须大于 0")
    by_key = {key(row): row for row in pr_pool}
    if len(by_key) != len(pr_pool):
        raise ValueError("PR pool 包含重复 group/repo/pr")
    family_silver = [
        row for row in silver if is_silver_finding(row, alert_family)
    ]
    positive_keys, probabilities, counts = select_positive_keys(
        family_silver, positive_target, seed, excluded
    )
    missing = [identifier for identifier in positive_keys if identifier not in by_key]
    if missing:
        raise ValueError(f"silver finding 对应 PR 不在 pool: {missing[:3]}")
    positives = []
    for identifier in positive_keys:
        row = {**by_key[identifier]}
        row["language"] = language(row)
        case_id = "case-" + hashlib.sha256(
            "|".join((*identifier, alert_family)).encode()
        ).hexdigest()[:20]
        probability = probabilities[identifier[0]]
        positives.append(
            {
                **row,
                "case_id": case_id,
                "case_control": "positive",
                "target_family": alert_family,
                "merge_calendar_quarter": row.get("merge_calendar_quarter")
                or quarter(row.get("merged_at", "")),
                "silver_finding_n": counts[identifier],
                "matched_positive_case_id": "",
                "same_repository_match": "",
                "control_match_score": "",
                "selection_probability": probability,
                "sampling_weight": 1 / probability,
                "split": split,
                "random_seed": seed,
            }
        )
    positive_set = set(positive_keys)
    available_controls = [
        {
            **row,
            "language": language(row),
            "merge_calendar_quarter": row.get("merge_calendar_quarter")
            or quarter(row.get("merged_at", "")),
        }
        for row in pr_pool
        if key(row) not in positive_set
        and key(row) not in excluded
        and introduced_family_count(row, alert_family) == 0
        and analysis_eligible(row)
    ]
    used: set[tuple[str, str, str]] = set()
    controls = []
    if control_target_per_group is None:
        anchor_sequence = [
            positive
            for positive in positives
            for _ in range(controls_per_positive)
        ]
    else:
        anchor_sequence = stratified_control_anchors(
            positives,
            control_target_per_group,
            seed,
        )
    for positive in anchor_sequence:
        match_count = (
            1 if control_target_per_group is not None else controls_per_positive
        )
        # The old per-positive path expands anchors above; one match is made for
        # each sequence element.  ``match_count`` is retained only as a guard
        # against accidental zero-control configurations.
        if match_count < 1:
            raise ValueError("control match count must be positive")
        for _match_index in range(1):
            candidates = [
                row
                for row in available_controls
                if key(row) not in used
                and row.get("group", "").lower() == positive.get("group", "").lower()
                and row.get("task_type", "") == positive.get("task_type", "")
            ]
            if not candidates:
                raise ValueError(
                    f"没有匹配 control: {positive['repo_name']}#{positive['pr_number']}"
                )
            chosen = min(candidates, key=lambda row: control_score(positive, row))
            used.add(key(chosen))
            score = control_score(positive, chosen)
            case_id = "case-" + hashlib.sha256(
                "|".join((*key(chosen), alert_family)).encode()
            ).hexdigest()[:20]
            controls.append(
                {
                    **chosen,
                    "case_id": case_id,
                    "case_control": "control",
                    "target_family": alert_family,
                    "silver_finding_n": 0,
                    "matched_positive_case_id": positive["case_id"],
                    "same_repository_match": int(score[0] == 0),
                    "control_match_score": f"{score[0]}|{score[1]}|{score[2]:.8f}|{score[3]}",
                    "selection_probability": "",
                    "sampling_weight": "",
                    "split": split,
                    "random_seed": seed,
                }
            )
    rows = positives + controls
    rows.sort(key=lambda row: (row["case_control"], row["group"], row["case_id"]))
    return rows


def introduced_family_count(row: dict[str, str], family: str) -> int:
    candidates = [
        row.get(f"introduced_{family}_count", ""),
        row.get(f"introduced_{family}_alerts", ""),
    ]
    for value in candidates:
        try:
            return int(float(str(value).strip()))
        except ValueError:
            continue
    raise ValueError(
        f"PR pool 缺少 introduced_{family}_count/alerts: "
        f"{row.get('repo_name')}#{row.get('pr_number')}"
    )


def selected_reference_alerts(
    cases: list[dict[str, Any]],
    silver: list[dict[str, str]],
) -> list[dict[str, Any]]:
    positive_by_key_family = {
        (key(row), str(row.get("target_family", "")).lower()): row
        for row in cases
        if row.get("case_control") == "positive"
    }
    selected: list[dict[str, Any]] = []
    for finding in silver:
        family = finding_family(finding)
        case = positive_by_key_family.get((key(finding), family))
        if case is None or not is_silver_finding(finding, family):
            continue
        selected.append(
            {
                **finding,
                "case_id": case["case_id"],
                "target_family": family,
            }
        )
    selected.sort(
        key=lambda row: (
            row.get("target_family", ""),
            row.get("group", ""),
            row.get("case_id", ""),
            row.get("rule_id", ""),
            row.get("file_path", ""),
            row.get("start_line", ""),
            row.get("fingerprint", ""),
        )
    )
    actual = Counter(row["case_id"] for row in selected)
    for case in positive_by_key_family.values():
        expected = int(float(str(case.get("silver_finding_n", 0))))
        if actual[case["case_id"]] != expected:
            raise ValueError(
                "selected reference alert 数量不守恒: "
                f"{case['case_id']} expected={expected} "
                f"actual={actual[case['case_id']]}"
            )
    return selected


def selected_reference_fields(
    silver: list[dict[str, str]],
) -> list[str]:
    fields = ["case_id", "target_family"]
    for row in silver:
        for field in row:
            if field not in fields:
                fields.append(field)
    return fields


def all_case_reference_alerts(
    cases: list[dict[str, Any]],
    silver: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Attach every actionable family reference for each selected PR.

    A case remains positive/control with respect to ``target_family`` only.
    The hidden all-family reference set is used solely to distinguish a true
    off-target-family recovery from an unmatched model report.
    """

    case_by_key = {key(row): row for row in cases}
    if len(case_by_key) != len(cases):
        raise ValueError("所选 cases 包含重复 PR，无法关联 all-family references")
    attached: list[dict[str, Any]] = []
    for finding in silver:
        case = case_by_key.get(key(finding))
        family = finding_family(finding)
        if case is None or family not in {"quality", "security"}:
            continue
        if not is_silver_finding(finding, family):
            continue
        target_family = str(case.get("target_family", "")).lower()
        if family == target_family:
            if family == "quality" and "quality_primary_reference" in finding:
                role = (
                    "target_reference"
                    if truthy(finding.get("quality_primary_reference"))
                    else "target_sensitivity_reference"
                )
            else:
                role = "target_reference"
        else:
            role = "off_target_reference"
        attached.append(
            {
                **finding,
                "case_id": case["case_id"],
                "case_target_family": target_family,
                "reference_family": family,
                "reference_role": role,
            }
        )
    attached.sort(
        key=lambda row: (
            row.get("case_target_family", ""),
            row.get("group", ""),
            row.get("case_id", ""),
            row.get("reference_role", ""),
            row.get("reference_family", ""),
            row.get("rule_id", ""),
            row.get("file_path", ""),
            row.get("start_line", ""),
            row.get("fingerprint", ""),
        )
    )
    target_counts = Counter(
        row["case_id"]
        for row in attached
        if row["reference_role"] == "target_reference"
    )
    for case in cases:
        expected = (
            int(float(str(case.get("silver_finding_n", 0))))
            if case.get("case_control") == "positive"
            else 0
        )
        actual = target_counts[case["case_id"]]
        if actual != expected:
            raise ValueError(
                "all-family reference target 数量不守恒: "
                f"{case['case_id']} expected={expected} actual={actual}"
            )
    return attached


def all_case_reference_fields(
    silver: list[dict[str, str]],
) -> list[str]:
    fields = [
        "case_id",
        "case_target_family",
        "reference_family",
        "reference_role",
    ]
    for row in silver:
        for field in row:
            if field not in fields:
                fields.append(field)
    return fields


def main() -> None:
    args = parse_args()
    excluded: set[tuple[str, str, str]] = set()
    if args.exclude_cases:
        excluded = {key(row) for row in read_csv(Path(args.exclude_cases))}
    pr_pool = read_csv(Path(args.pr_pool))
    silver_path = args.silver_findings or args.confirmed_findings
    silver = read_csv(Path(silver_path))
    all_silver_path = args.all_family_findings or silver_path
    all_silver = read_csv(Path(all_silver_path))
    families = (
        ["quality", "security"]
        if args.alert_family == "both"
        else [args.alert_family]
    )
    targets = (
        {
            "quality": (args.positive_target + 1) // 2,
            "security": args.positive_target // 2,
        }
        if args.alert_family == "both"
        else {
            args.alert_family: (
                None if args.all_positives else args.positive_target
            )
        }
    )
    rows = []
    used_prs = set(excluded)
    for offset, family in enumerate(families):
        family_rows = build_cases(
            pr_pool,
            silver,
            targets[family],
            args.controls_per_positive,
            args.split,
            args.seed + offset,
            used_prs,
            family,
            args.control_target_per_group,
        )
        rows.extend(family_rows)
        used_prs.update(key(row) for row in family_rows)
    if len({row["case_id"] for row in rows}) != len(rows):
        raise ValueError("Quality/Security case_id 冲突")
    output = Path(args.output)
    selected_output = (
        Path(args.selected_reference_alerts_output)
        if args.selected_reference_alerts_output
        else output.parent / "selected_reference_alerts.csv"
    )
    all_references_output = (
        Path(args.all_case_reference_alerts_output)
        if args.all_case_reference_alerts_output
        else output.parent / "all_case_reference_alerts.csv"
    )
    manifest_output = (
        Path(args.manifest_output)
        if args.manifest_output
        else output.parent / "selection_manifest.json"
    )
    selected = selected_reference_alerts(rows, silver)
    all_references = all_case_reference_alerts(rows, all_silver)
    write_csv(output, rows, FIELDS)
    write_csv(
        selected_output,
        selected,
        selected_reference_fields(silver),
    )
    write_csv(
        all_references_output,
        all_references,
        all_case_reference_fields(all_silver),
    )
    inputs = {
        "pr_pool": {
            "path": str(Path(args.pr_pool)),
            "sha256": sha256_file(Path(args.pr_pool)),
        },
        "silver_findings": {
            "path": str(Path(silver_path)),
            "sha256": sha256_file(Path(silver_path)),
        },
        "all_family_findings": {
            "path": str(Path(all_silver_path)),
            "sha256": sha256_file(Path(all_silver_path)),
        },
    }
    if args.exclude_cases:
        inputs["exclude_cases"] = {
            "path": str(Path(args.exclude_cases)),
            "sha256": sha256_file(Path(args.exclude_cases)),
        }
    manifest = {
        "schema_version": "1.0.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "split": args.split,
        "alert_family": args.alert_family,
        "positive_target": (
            "all" if args.all_positives else args.positive_target
        ),
        "controls_per_positive": args.controls_per_positive,
        "control_target_per_group": args.control_target_per_group,
        "seed": args.seed,
        "selector_sha256": sha256_file(Path(__file__)),
        "case_n": len(rows),
        "positive_case_n": sum(
            row["case_control"] == "positive" for row in rows
        ),
        "control_case_n": sum(
            row["case_control"] == "control" for row in rows
        ),
        "selected_reference_alert_n": len(selected),
        "all_case_reference_alert_n": len(all_references),
        "off_target_reference_alert_n": sum(
            row["reference_role"] == "off_target_reference"
            for row in all_references
        ),
        "inputs": inputs,
        "outputs": {
            "cases": {
                "path": str(output),
                "sha256": sha256_file(output),
            },
            "selected_reference_alerts": {
                "path": str(selected_output),
                "sha256": sha256_file(selected_output),
            },
            "all_case_reference_alerts": {
                "path": str(all_references_output),
                "sha256": sha256_file(all_references_output),
            },
        },
    }
    manifest_output.parent.mkdir(parents=True, exist_ok=True)
    manifest_output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"已生成 RQ3 {args.split} cases {len(rows)} 个："
        f"positive={sum(row['case_control'] == 'positive' for row in rows)}, "
        f"control={sum(row['case_control'] == 'control' for row in rows)}, "
        f"reference_alerts={len(selected)}"
    )


if __name__ == "__main__":
    main()
