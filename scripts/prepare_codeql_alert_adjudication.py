#!/usr/bin/env python3
"""Freeze the full introduced CodeQL alert frame for model adjudication.

The frame is restricted to PRs in the frozen RQ1/RQ2 analysis roster.  It
assigns content-derived case, alert, and batch identifiers without changing
the source result files.  Model execution is intentionally handled by a
separate command so that frame construction remains offline and reproducible.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "1.0.0"
EXPECTED_ROSTER_N = 5_404
EXPECTED_ALERT_N = 7_124
EXPECTED_GROUP_ROSTER_N = {"ai": 3_087, "human": 2_317}
EXPECTED_GROUP_ALERT_N = {"ai": 2_751, "human": 4_373}
EXPECTED_GROUP_POSITIVE_PR_N = {"ai": 476, "human": 481}

PR_FIELDS = (
    "case_id",
    "group",
    "repo_name",
    "pr_number",
    "pr_id",
    "language",
    "task_type",
    "base_sha",
    "head_sha",
    "introduced_alert_n",
    "batch_n",
)
ALERT_FIELDS = (
    "alert_id",
    "duplicate_ordinal",
    "case_id",
    "group",
    "repo_name",
    "pr_number",
    "pr_id",
    "language",
    "task_type",
    "base_sha",
    "head_sha",
    "issue_domain",
    "is_quality_alert",
    "rule_id",
    "rule_name",
    "problem_severity",
    "precision",
    "quality_category",
    "rule_tags",
    "file_path",
    "start_line",
    "message",
    "fingerprint",
    "fingerprint_method",
    "fingerprint_ambiguity_n",
    "source_group",
    "source_row_number",
)
BATCH_FIELDS = (
    "batch_id",
    "case_id",
    "batch_index",
    "batch_alert_n",
    "alert_ids_json",
)


def maximize_csv_field_limit() -> None:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


maximize_csv_field_limit()


def parse_args() -> argparse.Namespace:
    base = "data/experiments/security-and-quality/study_stars500"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--analysis-pr-level",
        type=Path,
        default=f"{base}/reports/rq_analysis_final_20260727_v3/analysis_pr_level.csv",
    )
    parser.add_argument(
        "--ai-alerts",
        type=Path,
        default=(
            f"{base}/reports/ai_quality_taxonomy_drill/results/"
            "introduced_alerts.csv"
        ),
    )
    parser.add_argument(
        "--human-alerts",
        type=Path,
        default=f"{base}/human/results/introduced_alerts.csv",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--alerts-per-batch", type=int, default=5)
    parser.add_argument(
        "--allow-unexpected-counts",
        action="store_true",
        help="Allow exploratory frames that differ from the frozen paper counts.",
    )
    return parser.parse_args()


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.casefold() in {"nan", "none", "null", "<na>"} else text


def truthy(value: Any) -> bool:
    return clean(value).casefold() in {"1", "true", "yes", "y"}


def normalize_pr_number(value: Any) -> str:
    text = clean(value)
    try:
        return str(int(float(text)))
    except (TypeError, ValueError):
        return text


def pr_key(group: Any, repo_name: Any, pr_number: Any) -> tuple[str, str, str]:
    return (
        clean(group).casefold(),
        clean(repo_name).casefold(),
        normalize_pr_number(pr_number),
    )


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
        rows = [
            {field: clean(value) for field, value in row.items()}
            for row in reader
        ]
    if not fields:
        raise ValueError(f"CSV has no header: {path}")
    return fields, rows


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_id(prefix: str, parts: Iterable[Any], length: int = 24) -> str:
    payload = "\x1f".join(clean(part) for part in parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(payload).hexdigest()[:length]}"


def alert_identity(group: str, row: dict[str, str]) -> tuple[str, ...]:
    return (
        group,
        clean(row.get("repo_name")).casefold(),
        normalize_pr_number(row.get("pr_number")),
        clean(row.get("rule_id")),
        clean(row.get("file_path")),
        clean(row.get("start_line")),
        clean(row.get("fingerprint")),
        clean(row.get("message")),
    )


def sort_alert_key(row: dict[str, str]) -> tuple[Any, ...]:
    raw_line = clean(row.get("start_line"))
    try:
        line: int | str = int(float(raw_line))
    except (TypeError, ValueError):
        line = raw_line
    return (
        clean(row.get("file_path")).casefold(),
        str(line).zfill(12),
        clean(row.get("rule_id")),
        clean(row.get("message")),
        clean(row.get("alert_id")),
    )


def write_csv(
    path: Path,
    fields: Sequence[str],
    rows: Iterable[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        newline="",
        dir=path.parent,
        delete=False,
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        temporary = Path(handle.name)
    temporary.replace(path)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
    ) as handle:
        json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def require_expected_counts(
    *,
    roster_rows: list[dict[str, str]],
    alerts: list[dict[str, str]],
    allow_unexpected: bool,
) -> None:
    if allow_unexpected:
        return
    roster_by_group = Counter(row["group"] for row in roster_rows)
    alerts_by_group = Counter(row["group"] for row in alerts)
    positive_pr_by_group = Counter(
        group
        for group, _, _ in {
            pr_key(row["group"], row["repo_name"], row["pr_number"])
            for row in alerts
        }
    )
    observed = {
        "roster_n": len(roster_rows),
        "alert_n": len(alerts),
        "roster_by_group": dict(roster_by_group),
        "alerts_by_group": dict(alerts_by_group),
        "positive_pr_by_group": dict(positive_pr_by_group),
    }
    expected = {
        "roster_n": EXPECTED_ROSTER_N,
        "alert_n": EXPECTED_ALERT_N,
        "roster_by_group": EXPECTED_GROUP_ROSTER_N,
        "alerts_by_group": EXPECTED_GROUP_ALERT_N,
        "positive_pr_by_group": EXPECTED_GROUP_POSITIVE_PR_N,
    }
    if observed != expected:
        raise ValueError(
            "frozen adjudication counts changed; refuse to create a new formal "
            f"frame\nexpected={expected}\nobserved={observed}"
        )


def prepare_frame(
    analysis_path: Path,
    alert_paths: dict[str, Path],
    output_dir: Path,
    alerts_per_batch: int,
    *,
    allow_unexpected_counts: bool = False,
) -> dict[str, Any]:
    if output_dir.exists():
        raise ValueError(f"output directory already exists: {output_dir}")
    if alerts_per_batch < 1 or alerts_per_batch > 100:
        raise ValueError("alerts-per-batch must be between 1 and 100")

    _, analysis_rows = read_csv(analysis_path)
    roster_rows: list[dict[str, str]] = []
    roster: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in analysis_rows:
        if not truthy(row.get("quality_gate_pass")):
            continue
        group = clean(row.get("group")).casefold()
        if group not in {"ai", "human"}:
            raise ValueError(f"unexpected roster group: {group}")
        normalized = dict(row)
        normalized["group"] = group
        key = pr_key(group, row.get("repo_name"), row.get("pr_number"))
        if key in roster:
            raise ValueError(f"duplicate eligible PR in analysis roster: {key}")
        roster[key] = normalized
        roster_rows.append(normalized)

    raw_alerts: list[dict[str, str]] = []
    identity_counts: Counter[tuple[str, ...]] = Counter()
    for group in ("ai", "human"):
        _, rows = read_csv(alert_paths[group])
        for source_row_number, row in enumerate(rows, start=2):
            key = pr_key(group, row.get("repo_name"), row.get("pr_number"))
            if key not in roster:
                continue
            lifecycle = clean(row.get("lifecycle")).casefold()
            if lifecycle and lifecycle != "introduced":
                raise ValueError(
                    f"non-introduced alert in introduced input: {key}"
                )
            identity = alert_identity(group, row)
            identity_counts[identity] += 1
            ordinal = identity_counts[identity]
            metadata = roster[key]
            case_id = stable_id("adjcase", key)
            alert_id = stable_id("qalert", (*identity, ordinal))
            raw_alerts.append(
                {
                    "alert_id": alert_id,
                    "duplicate_ordinal": str(ordinal),
                    "case_id": case_id,
                    "group": group,
                    "repo_name": clean(row.get("repo_name")),
                    "pr_number": normalize_pr_number(row.get("pr_number")),
                    "pr_id": clean(row.get("pr_id")) or clean(metadata.get("pr_id")),
                    "language": clean(row.get("language"))
                    or clean(metadata.get("repo_language")),
                    "task_type": clean(metadata.get("task_type")),
                    "base_sha": clean(row.get("base_sha"))
                    or clean(metadata.get("base_sha")),
                    "head_sha": clean(row.get("head_sha"))
                    or clean(metadata.get("head_sha")),
                    "issue_domain": (
                        "quality" if truthy(row.get("is_quality_alert")) else "security"
                    ),
                    "is_quality_alert": (
                        "true" if truthy(row.get("is_quality_alert")) else "false"
                    ),
                    "rule_id": clean(row.get("rule_id")),
                    "rule_name": clean(row.get("rule_name")),
                    "problem_severity": clean(row.get("problem_severity")),
                    "precision": clean(row.get("precision")),
                    "quality_category": clean(row.get("quality_category")),
                    "rule_tags": clean(row.get("rule_tags")),
                    "file_path": clean(row.get("file_path")),
                    "start_line": clean(row.get("start_line")),
                    "message": clean(row.get("message")),
                    "fingerprint": clean(row.get("fingerprint")),
                    "fingerprint_method": clean(row.get("fingerprint_method")),
                    "fingerprint_ambiguity_n": clean(
                        row.get("fingerprint_ambiguity_n")
                    ),
                    "source_group": group,
                    "source_row_number": str(source_row_number),
                }
            )

    require_expected_counts(
        roster_rows=roster_rows,
        alerts=raw_alerts,
        allow_unexpected=allow_unexpected_counts,
    )

    by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in raw_alerts:
        by_case[row["case_id"]].append(row)
    for rows in by_case.values():
        rows.sort(key=sort_alert_key)

    pr_rows: list[dict[str, Any]] = []
    batch_rows: list[dict[str, Any]] = []
    for case_id, rows in sorted(by_case.items()):
        first = rows[0]
        chunks = [
            rows[index : index + alerts_per_batch]
            for index in range(0, len(rows), alerts_per_batch)
        ]
        pr_rows.append(
            {
                "case_id": case_id,
                "group": first["group"],
                "repo_name": first["repo_name"],
                "pr_number": first["pr_number"],
                "pr_id": first["pr_id"],
                "language": first["language"],
                "task_type": first["task_type"],
                "base_sha": first["base_sha"],
                "head_sha": first["head_sha"],
                "introduced_alert_n": str(len(rows)),
                "batch_n": str(len(chunks)),
            }
        )
        for batch_index, chunk in enumerate(chunks, start=1):
            batch_id = stable_id("adjbatch", (case_id, batch_index))
            batch_rows.append(
                {
                    "batch_id": batch_id,
                    "case_id": case_id,
                    "batch_index": str(batch_index),
                    "batch_alert_n": str(len(chunk)),
                    "alert_ids_json": json.dumps(
                        [row["alert_id"] for row in chunk],
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                }
            )

    output_dir.mkdir(parents=True)
    alerts_path = output_dir / "adjudication_alerts.csv"
    prs_path = output_dir / "adjudication_prs.csv"
    batches_path = output_dir / "adjudication_batches.csv"
    write_csv(alerts_path, ALERT_FIELDS, sorted(raw_alerts, key=lambda row: row["alert_id"]))
    write_csv(prs_path, PR_FIELDS, pr_rows)
    write_csv(batches_path, BATCH_FIELDS, batch_rows)

    group_alert_counts = Counter(row["group"] for row in raw_alerts)
    group_pr_counts = Counter(row["group"] for row in pr_rows)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "analysis_roster_n": len(roster_rows),
            "introduced_alert_n": len(raw_alerts),
            "alert_positive_pr_n": len(pr_rows),
            "batch_n": len(batch_rows),
            "alerts_per_batch": alerts_per_batch,
            "alerts_by_group": dict(sorted(group_alert_counts.items())),
            "positive_prs_by_group": dict(sorted(group_pr_counts.items())),
            "exact_duplicate_alert_row_n": sum(
                count - 1 for count in identity_counts.values() if count > 1
            ),
        },
        "protocol": {
            "issue_domains": ["quality", "security"],
            "lifecycle": "introduced",
            "roster_filter": "quality_gate_pass=true",
            "authorship_blinding": (
                "group/repository metadata stay in the private frame and are not "
                "included in model prompt projections"
            ),
            "model_execution": "not_performed_by_this_command",
        },
        "inputs": {
            "analysis_pr_level": {
                "path": str(analysis_path),
                "sha256": sha256_file(analysis_path),
            },
            **{
                f"{group}_alerts": {
                    "path": str(path),
                    "sha256": sha256_file(path),
                }
                for group, path in alert_paths.items()
            },
        },
        "outputs": {
            path.name: {"sha256": sha256_file(path), "size": path.stat().st_size}
            for path in (alerts_path, prs_path, batches_path)
        },
    }
    write_json(output_dir / "manifest.json", manifest)
    return manifest


def main() -> None:
    args = parse_args()
    manifest = prepare_frame(
        resolve(args.analysis_pr_level),
        {"ai": resolve(args.ai_alerts), "human": resolve(args.human_alerts)},
        resolve(args.output_dir),
        args.alerts_per_batch,
        allow_unexpected_counts=args.allow_unexpected_counts,
    )
    scope = manifest["scope"]
    print(
        "已冻结 introduced CodeQL alert adjudication frame: "
        f"alerts={scope['introduced_alert_n']} "
        f"prs={scope['alert_positive_pr_n']} batches={scope['batch_n']}"
    )


if __name__ == "__main__":
    main()
