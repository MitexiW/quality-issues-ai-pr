#!/usr/bin/env python3
"""Prepare auditable review packets for AI Quality root-cause coding.

The script deliberately stops at evidence preparation.  A PR--rule group is
an initial review unit, not an assumed root-cause cluster: reviewers may split
one unit or assign units from different rules in the same PR to one cluster.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "data/experiments/security-and-quality/study_stars500/reports"
DEFAULT_ALERTS = REPORTS / "final_human_confirmed_issue_analysis_20260817_v1/validated_alerts.csv"
DEFAULT_REPOS = ROOT / "data/experiments/security-and-quality/study_stars500/ai/repos"
DEFAULT_OUTPUT = REPORTS / "ai_quality_root_cause_review_20260831_v1"
EXPECTED = {"alerts": 775, "prs": 251, "pr_rules": 316}
CONTEXT_LINES = 30
MAX_PATCH_CHARS = 120_000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts", type=Path, default=DEFAULT_ALERTS)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPOS)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--skip-count-contract", action="store_true")
    return parser.parse_args()


def clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.casefold() in {"nan", "none", "null", "<na>"} else text


def truthy(value: Any) -> bool:
    return clean(value).casefold() in {"1", "true", "yes", "y"}


def maximize_csv_field_limit() -> None:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


def read_csv(path: Path) -> list[dict[str, str]]:
    maximize_csv_field_limit()
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return [{k: clean(v) for k, v in row.items()} for row in csv.DictReader(handle)]


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def digest_id(prefix: str, *parts: str) -> str:
    payload = "\0".join(parts).encode()
    return f"{prefix}-{hashlib.sha256(payload).hexdigest()[:20]}"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def repo_slug(repo: str) -> str:
    return repo.replace("/", "_")


def source_dirs(repo_root: Path, repo: str, pr: str) -> tuple[Path, Path]:
    slug = repo_slug(repo)
    parent = repo_root / slug
    return parent / f"{slug}__pr-{pr}__before", parent / f"{slug}__pr-{pr}__after"


def validate_and_select(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    required = {
        "alert_id", "group", "repo_name", "pr_number", "base_sha", "head_sha",
        "issue_domain", "is_quality_alert", "rule_id", "rule_name", "file_path",
        "start_line", "message", "human_disposition", "human_notes",
    }
    missing = sorted(required - set(rows[0])) if rows else sorted(required)
    if missing:
        raise ValueError(f"validated alert table missing fields: {missing}")
    selected = [
        row for row in rows
        if row["group"].casefold() == "ai"
        and row["issue_domain"].casefold() == "quality"
        and truthy(row["is_quality_alert"])
        and row["human_disposition"] == "confirmed_valid"
    ]
    identifiers = [row["alert_id"] for row in selected]
    if not identifiers or any(not value for value in identifiers) or len(set(identifiers)) != len(identifiers):
        raise ValueError("selected alert_id values must be non-empty and unique")
    return selected


def line_number(value: str) -> int:
    try:
        return max(1, int(float(value)))
    except ValueError:
        return 1


def excerpt(path: Path, lines: list[int], fallback_text: str | None = None) -> dict[str, Any]:
    if not path.is_file() and fallback_text is None:
        return {"available": False, "path": str(path), "ranges": []}
    content = (
        path.read_text(encoding="utf-8", errors="replace")
        if path.is_file() else fallback_text or ""
    ).splitlines()
    intervals: list[tuple[int, int]] = []
    for line in sorted(set(lines)):
        start, end = max(1, line - CONTEXT_LINES), min(len(content), line + CONTEXT_LINES)
        if intervals and start <= intervals[-1][1] + 1:
            intervals[-1] = intervals[-1][0], max(intervals[-1][1], end)
        else:
            intervals.append((start, end))
    return {
        "available": True,
        "path": str(path),
        "line_count": len(content),
        "ranges": [
            {"start_line": start, "end_line": end,
             "text": "\n".join(f"{number:6}: {content[number - 1]}" for number in range(start, end + 1))}
            for start, end in intervals
        ],
    }


def file_patch(
    before: Path, after: Path, relative: str,
    before_fallback: str | None = None, after_fallback: str | None = None,
) -> tuple[str, str]:
    before_text = (before.read_text(encoding="utf-8", errors="replace") if before.is_file()
                   else before_fallback or "").splitlines()
    after_text = (after.read_text(encoding="utf-8", errors="replace") if after.is_file()
                  else after_fallback or "").splitlines()
    patch = "\n".join(difflib.unified_diff(
        before_text, after_text, fromfile=f"a/{relative}", tofile=f"b/{relative}", n=12, lineterm=""
    ))
    if len(patch) > MAX_PATCH_CHARS:
        return patch[:MAX_PATCH_CHARS] + "\n[PATCH TRUNCATED]\n", "truncated"
    return patch, "complete"


def git_commands(after_dir: Path, repo: str) -> list[list[str]]:
    commands = []
    if (after_dir / ".git").exists():
        commands.append(["git", "-C", str(after_dir)])
    cache = ROOT / "data/repos/.cache" / f"{repo_slug(repo)}.git"
    if cache.is_dir():
        commands.append(["git", f"--git-dir={cache}"])
    return commands


def git_file(commands: list[list[str]], revision: str, relative: str) -> str | None:
    for command in commands:
        result = subprocess.run(
            [*command, "show", f"{revision}:{relative}"], capture_output=True, check=False
        )
        if result.returncode == 0:
            return result.stdout.decode("utf-8", errors="replace")
    return None


def changed_files(
    commands: list[list[str]], base_sha: str, head_sha: str
) -> tuple[list[dict[str, str]], str]:
    result = None
    for command in commands:
        candidate = subprocess.run(
            [*command, "diff", "--name-status", base_sha, head_sha],
            text=True, capture_output=True, check=False,
        )
        if candidate.returncode == 0:
            result = candidate
            break
    if result is None:
        return [], "git_diff_failed" if commands else "git_metadata_unavailable"
    output = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            output.append({"status": parts[0], "path": parts[-1]})
    return output, "available"


def make_packet(
    repo_root: Path, repo: str, pr: str, rows: list[dict[str, str]]
) -> tuple[dict[str, Any], str]:
    before_dir, after_dir = source_dirs(repo_root, repo, pr)
    commands = git_commands(after_dir, repo)
    worktrees_available = before_dir.is_dir() and after_dir.is_dir()
    source_status = "available" if worktrees_available else "git_object_fallback"
    by_file: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_rule: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_file[row["file_path"]].append(row)
        by_rule[row["rule_id"]].append(row)
    evidence_files = []
    for relative, alerts in sorted(by_file.items()):
        lines = [line_number(row["start_line"]) for row in alerts]
        before_file, after_file = before_dir / relative, after_dir / relative
        before_fallback = None if before_file.is_file() else git_file(commands, rows[0]["base_sha"], relative)
        after_fallback = None if after_file.is_file() else git_file(commands, rows[0]["head_sha"], relative)
        patch, patch_status = file_patch(before_file, after_file, relative, before_fallback, after_fallback)
        evidence_files.append({
            "file_path": relative,
            "alert_ids": [row["alert_id"] for row in alerts],
            "patch_status": patch_status,
            "patch": patch,
            "before_context": excerpt(before_file, lines, before_fallback),
            "head_context": excerpt(after_file, lines, after_fallback),
        })
    if any(not evidence["head_context"]["available"] for evidence in evidence_files):
        source_status = "partial_context_only"
    changes, change_status = changed_files(commands, rows[0]["base_sha"], rows[0]["head_sha"])
    packet = {
        "packet_schema_version": "1.0.0",
        "review_scope": "proximate_code_change_cause",
        "repo_name": repo,
        "pr_number": pr,
        "base_sha": rows[0]["base_sha"],
        "head_sha": rows[0]["head_sha"],
        "source_status": source_status,
        "changed_files_status": change_status,
        "changed_files": changes,
        "initial_pr_rule_units": [
            {
                "review_unit_id": digest_id("rcunit", repo, pr, rule),
                "rule_id": rule,
                "rule_name": alerts[0]["rule_name"],
                "alerts": [{k: row.get(k, "") for k in (
                    "alert_id", "file_path", "start_line", "message", "human_notes",
                    "rationale", "evidence_json", "quality_category", "problem_severity", "precision"
                )} for row in alerts],
            }
            for rule, alerts in sorted(by_rule.items())
        ],
        "relevant_file_evidence": evidence_files,
    }
    return packet, source_status


def run(args: argparse.Namespace) -> None:
    alerts_path = args.alerts if args.alerts.is_absolute() else ROOT / args.alerts
    repo_root = args.repo_root if args.repo_root.is_absolute() else ROOT / args.repo_root
    output = args.output_dir if args.output_dir.is_absolute() else ROOT / args.output_dir
    selected = validate_and_select(read_csv(alerts_path))
    prs: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    units: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in selected:
        prs[(row["repo_name"], row["pr_number"])].append(row)
        units[(row["repo_name"], row["pr_number"], row["rule_id"])].append(row)
    counts = {"alerts": len(selected), "prs": len(prs), "pr_rules": len(units)}
    if not args.skip_count_contract and counts != EXPECTED:
        raise ValueError(f"frozen count contract changed: expected {EXPECTED}, found {counts}")

    packet_paths: dict[tuple[str, str], Path] = {}
    source_statuses: dict[tuple[str, str], str] = {}
    for (repo, pr), rows in sorted(prs.items()):
        filename = f"{repo_slug(repo)}__pr-{pr}.json"
        path = output / "review_packets" / filename
        packet, status = make_packet(repo_root, repo, pr, rows)
        write_json(path, packet)
        packet_paths[(repo, pr)] = path
        source_statuses[(repo, pr)] = status

    pr_rows = []
    for (repo, pr), rows in sorted(prs.items()):
        pr_rows.append({
            "repo_name": repo, "pr_number": pr, "language": rows[0].get("language", ""),
            "task_type": rows[0].get("task_type", ""), "alert_n": len(rows),
            "rule_n": len({row["rule_id"] for row in rows}),
            "rules_json": json.dumps(sorted({row["rule_id"] for row in rows})),
            "source_status": source_statuses[(repo, pr)],
            "packet_path": str(packet_paths[(repo, pr)].relative_to(output)),
        })
    pr_fields = ["repo_name", "pr_number", "language", "task_type", "alert_n", "rule_n",
                 "rules_json", "source_status", "packet_path"]
    write_csv(output / "positive_prs.csv", pr_rows, pr_fields)

    unit_rows = []
    template_rows = []
    for (repo, pr, rule), rows in sorted(units.items()):
        unit_id = digest_id("rcunit", repo, pr, rule)
        common = {
            "review_unit_id": unit_id, "repo_name": repo, "pr_number": pr,
            "language": rows[0].get("language", ""), "task_type": rows[0].get("task_type", ""),
            "quality_category": rows[0].get("quality_category", ""),
            "rule_id": rule, "rule_name": rows[0]["rule_name"], "alert_n": len(rows),
            "alert_ids_json": json.dumps([row["alert_id"] for row in rows]),
            "files_json": json.dumps(sorted({row["file_path"] for row in rows})),
            "source_status": source_statuses[(repo, pr)],
            "packet_path": str(packet_paths[(repo, pr)].relative_to(output)),
        }
        unit_rows.append(common)
        template_rows.append({**common, "cluster_key_within_pr": "", "included_alert_ids_json": "",
            "root_cause_category": "", "mechanism_subcategory": "", "change_operation": "",
            "violated_relation": "", "cause_statement": "", "evidence_summary": "",
            "evidence_locations_json": "", "confidence": "", "reviewer": "", "review_notes": ""})
    unit_fields = ["review_unit_id", "repo_name", "pr_number", "language", "task_type",
                   "quality_category", "rule_id", "rule_name", "alert_n", "alert_ids_json",
                   "files_json", "source_status", "packet_path"]
    annotation_fields = unit_fields + ["cluster_key_within_pr", "included_alert_ids_json", "root_cause_category",
        "mechanism_subcategory", "change_operation", "violated_relation", "cause_statement",
        "evidence_summary", "evidence_locations_json", "confidence", "reviewer", "review_notes"]
    write_csv(output / "pr_rule_review_units.csv", unit_rows, unit_fields)
    write_csv(output / "cluster_annotation_template.csv", template_rows, annotation_fields)
    manifest = {
        "schema_version": "1.0.0", "status": "prepared_not_annotated",
        "generated_at": datetime.now(timezone.utc).isoformat(), "counts": counts,
        "source_complete_pr_n": sum(value in {"available", "git_object_fallback"} for value in source_statuses.values()),
        "source_worktree_pr_n": sum(value == "available" for value in source_statuses.values()),
        "source_git_fallback_pr_n": sum(value == "git_object_fallback" for value in source_statuses.values()),
        "source_partial_pr_n": sum(value == "partial_context_only" for value in source_statuses.values()),
        "source_missing_pr_n": sum(value not in {"available", "git_object_fallback", "partial_context_only"} for value in source_statuses.values()),
        "inputs": {"alerts": str(alerts_path), "alerts_sha256": sha256(alerts_path), "repo_root": str(repo_root)},
        "outputs": {"positive_prs": "positive_prs.csv", "review_units": "pr_rule_review_units.csv", "annotation_template": "cluster_annotation_template.csv",
                    "packet_directory": "review_packets"},
        "unit_semantics": "PR-rule rows are initial review units only; split or merge them when evidence supports distinct or shared causes.",
    }
    write_json(output / "manifest.json", manifest)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    run(parse_args())
