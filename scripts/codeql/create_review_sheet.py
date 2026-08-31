#!/usr/bin/env python3
# CodeQL pipeline entry point.
"""Create a manual review sheet for introduced CodeQL alerts."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Any, Iterable

REVIEW_FIELDS = [
    "review_status",
    "reviewer",
    "reviewed_at",
    "is_true_introduced",
    "is_pr_related",
    "is_file_move_or_rename",
    "is_false_positive",
    "manual_severity",
    "notes",
]


def raise_csv_field_size_limit() -> None:
    """Allow SARIF messages larger than csv's platform default field limit."""
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


raise_csv_field_size_limit()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="为 introduced 告警生成逐条人工复核表")
    parser.add_argument(
        "--introduced",
        default="data/results/introduced_alerts.csv",
        help="compare_sarif.py 生成的 introduced_alerts.csv",
    )
    parser.add_argument(
        "--output",
        default="data/results/introduced_alert_review.csv",
        help="人工复核表输出路径",
    )
    parser.add_argument(
        "--preserve-existing",
        action="store_true",
        help="已有复核表存在时，按告警 identity 保留人工填写列",
    )
    return parser.parse_args()


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.exists():
        raise SystemExit(f"输入文件不存在: {path}")
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temp.replace(path)


def alert_identity(row: dict[str, str]) -> tuple[str, ...]:
    return (
        row.get("repo_name", ""),
        row.get("pr_number", ""),
        row.get("base_sha", ""),
        row.get("head_sha", ""),
        row.get("rule_id", ""),
        row.get("file_path", ""),
        row.get("start_line", ""),
        row.get("message", ""),
        row.get("fingerprint", ""),
    )


def existing_reviews(path: Path) -> dict[tuple[str, ...], dict[str, str]]:
    if not path.exists():
        return {}
    _, rows = read_csv(path)
    return {alert_identity(row): row for row in rows}


def main() -> None:
    args = parse_args()
    introduced_path = Path(args.introduced)
    output_path = Path(args.output)
    alert_fields, alerts = read_csv(introduced_path)
    output_fields = list(alert_fields)
    for field in REVIEW_FIELDS:
        if field not in output_fields:
            output_fields.append(field)

    preserved = (
        existing_reviews(output_path)
        if args.preserve_existing
        else {}
    )
    rows: list[dict[str, str]] = []
    for alert in alerts:
        row = dict(alert)
        previous = preserved.get(alert_identity(alert), {})
        for field in REVIEW_FIELDS:
            if field == "review_status":
                row[field] = previous.get(field, "pending")
            else:
                row[field] = previous.get(field, "")
        rows.append(row)

    write_csv(output_path, output_fields, rows)
    print(f"已生成人工复核表: {output_path}，introduced 告警 {len(rows)} 条")


if __name__ == "__main__":
    main()
