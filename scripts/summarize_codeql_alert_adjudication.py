#!/usr/bin/env python3
"""Export auditable model adjudications and aggregate summaries.

By default this command refuses to produce a formal export until every frozen
batch is completed.  ``--allow-incomplete`` is intended only for progress
inspection and marks every output as preliminary.
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
DECISION_FIELDS = (
    "condition_present",
    "valid_issue",
    "introduced_by_pr",
    "actionability",
    "confidence",
    "evidence_json",
    "rationale",
    "model_supported_introduced_issue",
    "model_supported_actionable_issue",
)
PR_SUMMARY_FIELDS = (
    "case_id",
    "group",
    "repo_name",
    "pr_number",
    "language",
    "task_type",
    "frozen_alert_n",
    "frozen_quality_alert_n",
    "frozen_security_alert_n",
    "adjudicated_alert_n",
    "adjudicated_quality_alert_n",
    "adjudicated_security_alert_n",
    "model_valid_issue_n",
    "model_supported_introduced_issue_n",
    "model_supported_introduced_quality_issue_n",
    "model_supported_introduced_security_issue_n",
    "model_supported_actionable_issue_n",
    "uncertain_alert_n",
)


class SummaryError(ValueError):
    """Raised when a run cannot support an auditable summary."""


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
    base = "data/experiments/security-and-quality/study_stars500/reports"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--frame-dir",
        type=Path,
        default=f"{base}/codeql_alert_adjudication_20260804_v5/frame",
    )
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="Write a clearly preliminary progress export before all batches finish.",
    )
    return parser.parse_args()


def resolve(path: Path) -> Path:
    return path.expanduser().resolve() if path.is_absolute() else (ROOT / path).resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise SummaryError(f"invalid JSON file {path}: {exc}") from None
    if not isinstance(value, dict):
        raise SummaryError(f"JSON file must contain an object: {path}")
    return value


def write_csv(
    path: Path, fields: Sequence[str], rows: Iterable[dict[str, Any]]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        temporary = Path(handle.name)
    temporary.replace(path)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def percent(numerator: int, denominator: int) -> str:
    return "NA" if not denominator else f"{100 * numerator / denominator:.2f}%"


def latest_completed_response(
    run_dir: Path, status: dict[str, str]
) -> tuple[dict[str, Any], dict[str, Any], int]:
    try:
        attempt = int(status.get("attempts") or 0)
    except ValueError:
        raise SummaryError(f"invalid attempt count for {status.get('batch_id')}") from None
    attempt_dir = run_dir / "invocations" / status["batch_id"] / f"attempt-{attempt:03d}"
    execution_path = attempt_dir / "execution.json"
    response_path = attempt_dir / "adjudication_response.json"
    execution = read_json(execution_path)
    response = read_json(response_path)
    if execution.get("status") != "completed":
        raise SummaryError(f"completed status lacks completed execution: {status['batch_id']}")
    if execution.get("response_sha256") != sha256_file(response_path):
        raise SummaryError(f"response hash mismatch: {status['batch_id']}")
    return execution, response, attempt


def summarize(
    frame_dir: Path,
    run_dir: Path,
    output_dir: Path,
    *,
    allow_incomplete: bool,
) -> dict[str, Any]:
    if output_dir.exists():
        raise SummaryError(f"output directory already exists: {output_dir}")
    frame_manifest = read_json(frame_dir / "manifest.json")
    for filename, record in frame_manifest.get("outputs", {}).items():
        if sha256_file(frame_dir / filename) != record.get("sha256"):
            raise SummaryError(f"frame hash mismatch: {filename}")

    alert_fields, alerts = read_csv(frame_dir / "adjudication_alerts.csv")
    _, cases = read_csv(frame_dir / "adjudication_prs.csv")
    _, batches = read_csv(frame_dir / "adjudication_batches.csv")
    _, status_rows = read_csv(run_dir / "batch_status.csv")
    run_config = read_json(run_dir / "run_config.json")
    status_by_batch = {row["batch_id"]: row for row in status_rows}
    if len(status_by_batch) != len(status_rows) or set(status_by_batch) != {
        row["batch_id"] for row in batches
    }:
        raise SummaryError("run status does not match the frozen batch inventory")
    counts = Counter(row["status"] for row in status_rows)
    complete = counts.get("completed", 0) == len(batches)
    if not complete and not allow_incomplete:
        raise SummaryError(
            "formal export requires every frozen batch to be completed; "
            "use --allow-incomplete only for a preliminary progress summary"
        )

    alert_by_id = {row["alert_id"]: row for row in alerts}
    if len(alert_by_id) != len(alerts):
        raise SummaryError("duplicate alert IDs in frozen frame")
    decisions: dict[str, dict[str, Any]] = {}
    decision_audit: dict[str, dict[str, Any]] = {}
    for batch in batches:
        status = status_by_batch[batch["batch_id"]]
        if status["status"] != "completed":
            continue
        execution, response, attempt = latest_completed_response(run_dir, status)
        expected_ids = json.loads(batch["alert_ids_json"])
        rows = response.get("adjudications")
        if not isinstance(rows, list):
            raise SummaryError(f"invalid adjudication response: {batch['batch_id']}")
        observed_ids = [str(row.get("alert_id") or "") for row in rows]
        if len(observed_ids) != len(set(observed_ids)) or set(observed_ids) != set(expected_ids):
            raise SummaryError(f"response IDs do not match batch: {batch['batch_id']}")
        for row in rows:
            alert_id = row["alert_id"]
            if alert_id in decisions or alert_id not in alert_by_id:
                raise SummaryError(f"duplicate or unknown adjudicated alert: {alert_id}")
            decisions[alert_id] = row
            decision_audit[alert_id] = {
                "batch_id": batch["batch_id"],
                "attempt": str(attempt),
                "execution_sha256": execution.get("execution_sha256", ""),
            }

    flat_rows: list[dict[str, Any]] = []
    for alert in alerts:
        alert_id = alert["alert_id"]
        if alert_id not in decisions:
            continue
        decision = decisions[alert_id]
        model_supported = (
            decision["condition_present"] == "yes"
            and decision["valid_issue"] == "yes"
            and decision["introduced_by_pr"] == "yes"
        )
        actionable = model_supported and decision["actionability"] in {
            "must_fix",
            "should_fix",
        }
        flat_rows.append(
            {
                **alert,
                **decision_audit[alert_id],
                "condition_present": decision["condition_present"],
                "valid_issue": decision["valid_issue"],
                "introduced_by_pr": decision["introduced_by_pr"],
                "actionability": decision["actionability"],
                "confidence": decision["confidence"],
                "evidence_json": json.dumps(
                    decision["evidence"], ensure_ascii=False, separators=(",", ":")
                ),
                "rationale": decision["rationale"],
                "model_supported_introduced_issue": "1" if model_supported else "0",
                "model_supported_actionable_issue": "1" if actionable else "0",
            }
        )

    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in flat_rows:
        by_case[row["case_id"]].append(row)
    frozen_by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in alerts:
        frozen_by_case[row["case_id"]].append(row)
    pr_rows: list[dict[str, Any]] = []
    for case in cases:
        rows = by_case.get(case["case_id"], [])
        frozen_rows = frozen_by_case.get(case["case_id"], [])
        pr_rows.append(
            {
                "case_id": case["case_id"],
                "group": case["group"],
                "repo_name": case["repo_name"],
                "pr_number": case["pr_number"],
                "language": case["language"],
                "task_type": case["task_type"],
                "frozen_alert_n": case["introduced_alert_n"],
                "frozen_quality_alert_n": str(
                    sum(row["issue_domain"] == "quality" for row in frozen_rows)
                ),
                "frozen_security_alert_n": str(
                    sum(row["issue_domain"] == "security" for row in frozen_rows)
                ),
                "adjudicated_alert_n": str(len(rows)),
                "adjudicated_quality_alert_n": str(
                    sum(row["issue_domain"] == "quality" for row in rows)
                ),
                "adjudicated_security_alert_n": str(
                    sum(row["issue_domain"] == "security" for row in rows)
                ),
                "model_valid_issue_n": str(
                    sum(row["valid_issue"] == "yes" for row in rows)
                ),
                "model_supported_introduced_issue_n": str(
                    sum(row["model_supported_introduced_issue"] == "1" for row in rows)
                ),
                "model_supported_introduced_quality_issue_n": str(
                    sum(
                        row["model_supported_introduced_issue"] == "1"
                        and row["issue_domain"] == "quality"
                        for row in rows
                    )
                ),
                "model_supported_introduced_security_issue_n": str(
                    sum(
                        row["model_supported_introduced_issue"] == "1"
                        and row["issue_domain"] == "security"
                        for row in rows
                    )
                ),
                "model_supported_actionable_issue_n": str(
                    sum(row["model_supported_actionable_issue"] == "1" for row in rows)
                ),
                "uncertain_alert_n": str(
                    sum(
                        row["condition_present"] == "uncertain"
                        or row["valid_issue"] == "uncertain"
                        or row["introduced_by_pr"] == "uncertain"
                        or row["actionability"] == "uncertain"
                        for row in rows
                    )
                ),
            }
        )

    output_dir.mkdir(parents=True)
    decision_path = output_dir / "model_adjudications.csv"
    pr_path = output_dir / "pr_model_adjudication_summary.csv"
    batch_path = output_dir / "batch_audit.csv"
    write_csv(
        decision_path,
        (*alert_fields, "batch_id", "attempt", "execution_sha256", *DECISION_FIELDS),
        flat_rows,
    )
    write_csv(pr_path, PR_SUMMARY_FIELDS, pr_rows)
    write_csv(batch_path, list(status_rows[0]) if status_rows else [], status_rows)

    group_rows: list[dict[str, Any]] = []
    for group in ("ai", "human"):
        rows = [row for row in flat_rows if row["group"] == group]
        supported = sum(row["model_supported_introduced_issue"] == "1" for row in rows)
        actionable = sum(row["model_supported_actionable_issue"] == "1" for row in rows)
        group_rows.append(
            {
                "group": group,
                "adjudicated": len(rows),
                "supported": supported,
                "actionable": actionable,
            }
        )
    state = "FORMAL COMPLETE" if complete else "PRELIMINARY INCOMPLETE"
    lines = [
        "# CodeQL alert model-adjudication summary",
        "",
        f"Status: **{state}**",
        "",
        "These are model adjudications, not human-validated ground truth.",
        "",
        f"- Frozen alerts: {len(alerts):,}",
        f"- Adjudicated alerts: {len(flat_rows):,}",
        f"- Frozen batches: {len(batches):,}",
        f"- Completed batches: {counts.get('completed', 0):,}",
        f"- SDK-reported cost: ${sum(float(row.get('total_cost_usd') or 0) for row in status_rows):,.4f}",
        "",
        "| Group | Adjudicated | Model-adjudicated CodeQL issues | Rate | Actionable adjudicated issues | Rate |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in group_rows:
        lines.append(
            f"| {row['group']} | {row['adjudicated']:,} | {row['supported']:,} | "
            f"{percent(row['supported'], row['adjudicated'])} | {row['actionable']:,} | "
            f"{percent(row['actionable'], row['adjudicated'])} |"
        )
    lines.extend(
        [
            "",
            "| Domain | Adjudicated | Model-adjudicated CodeQL issues | Rate |",
            "|---|---:|---:|---:|",
        ]
    )
    for domain in ("quality", "security"):
        rows = [row for row in flat_rows if row["issue_domain"] == domain]
        supported = sum(row["model_supported_introduced_issue"] == "1" for row in rows)
        lines.append(
            f"| {domain} | {len(rows):,} | {supported:,} | "
            f"{percent(supported, len(rows))} |"
        )
    summary_path = output_dir / "summary.md"
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "formal_complete" if complete else "preliminary_incomplete",
        "formal_downstream_analysis_allowed": complete,
        "frozen_alert_n": len(alerts),
        "adjudicated_alert_n": len(flat_rows),
        "frozen_alerts_by_domain": dict(
            sorted(Counter(row["issue_domain"] for row in alerts).items())
        ),
        "adjudicated_alerts_by_domain": dict(
            sorted(Counter(row["issue_domain"] for row in flat_rows).items())
        ),
        "batch_status_counts": dict(sorted(counts.items())),
        "run_config_sha256": run_config.get("config_sha256"),
        "inputs": {
            "frame_manifest_sha256": sha256_file(frame_dir / "manifest.json"),
            "batch_status_sha256": sha256_file(run_dir / "batch_status.csv"),
        },
        "outputs": {
            path.name: {"sha256": sha256_file(path), "size": path.stat().st_size}
            for path in (decision_path, pr_path, batch_path, summary_path)
        },
    }
    write_json(output_dir / "manifest.json", manifest)
    return manifest


def main() -> None:
    args = parse_args()
    run_dir = resolve(args.run_dir)
    output_dir = resolve(args.output_dir) if args.output_dir else run_dir / "results"
    manifest = summarize(
        resolve(args.frame_dir),
        run_dir,
        output_dir,
        allow_incomplete=args.allow_incomplete,
    )
    print(
        "CodeQL alert adjudication summary generated: "
        f"status={manifest['status']} alerts={manifest['adjudicated_alert_n']}/"
        f"{manifest['frozen_alert_n']} output={output_dir}"
    )


if __name__ == "__main__":
    main()
