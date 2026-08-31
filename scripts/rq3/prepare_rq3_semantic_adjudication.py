#!/usr/bin/env python3
# RQ3 review experiment entry point.
"""Build complete, auditable RQ3 semantic-adjudication packets.

The generated workspace preserves the frozen automatic matcher output and adds
source/diff evidence for every formal case, every reviewer finding, and every
CodeQL reference.  It does not assign semantic labels.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .summarize_claude_review_example import reference_id
except ImportError:  # Direct CLI execution loads sibling modules by name.
    from summarize_claude_review_example import reference_id


ROOT = Path(__file__).resolve().parents[2]
REPORTS = (
    ROOT
    / "data/experiments/security-and-quality/study_stars500/reports"
)
DEFAULT_PLAN = REPORTS / "rq3_formal_plan_20260727_v1"
DEFAULT_RESULTS = REPORTS / "rq3_formal_results_20260729_v1"
DEFAULT_WORKTREES = REPORTS / "rq3_formal_worktrees_20260727_v1"
SCHEMA_VERSION = "1.0.0"
TOKEN_RE = re.compile(r"[a-z0-9_]{3,}")
HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)
STOPWORDS = {
    "about",
    "after",
    "before",
    "because",
    "could",
    "does",
    "from",
    "have",
    "into",
    "line",
    "only",
    "should",
    "that",
    "their",
    "there",
    "this",
    "when",
    "where",
    "which",
    "with",
    "without",
}
FINDING_LABEL_FIELDS = [
    "case_id",
    "model_finding_id",
    "adjudicator",
    "adjudicator_type",
    "finding_validity",
    "codeql_relation",
    "matched_reference_ids",
    "confidence",
    "rationale",
    "evidence_paths",
    "adjudicated_at_utc",
]
CASE_LABEL_FIELDS = [
    "case_id",
    "adjudicator",
    "adjudicator_type",
    "case_review_status",
    "any_semantic_codeql_match",
    "valid_introduced_finding_n",
    "pre_existing_or_out_of_scope_n",
    "invalid_finding_n",
    "uncertain_finding_n",
    "notes",
    "adjudicated_at_utc",
]


class PreparationError(RuntimeError):
    """Raised when the frozen adjudication inputs are inconsistent."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="生成覆盖全部正式 RQ3 PR 的语义核对工作台"
    )
    parser.add_argument("--cases", default=str(DEFAULT_PLAN / "formal_cases.csv"))
    parser.add_argument(
        "--references",
        default=str(DEFAULT_PLAN / "all_case_reference_alerts.csv"),
    )
    parser.add_argument(
        "--case-metrics",
        default=str(DEFAULT_RESULTS / "case_metrics.csv"),
    )
    parser.add_argument(
        "--finding-matches",
        default=str(DEFAULT_RESULTS / "finding_matches.csv"),
    )
    parser.add_argument(
        "--automatic-reference-recovery",
        default=str(DEFAULT_RESULTS / "reference_recovery.csv"),
    )
    parser.add_argument(
        "--worktree-key",
        default=str(DEFAULT_WORKTREES / "worktree_key.csv"),
    )
    parser.add_argument("--worktree-root", default=str(DEFAULT_WORKTREES))
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--context-radius", type=int, default=8)
    parser.add_argument("--candidate-limit", type=int, default=5)
    return parser.parse_args()


def read_csv(path: Path, label: str) -> list[dict[str, str]]:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            break
        except OverflowError:
            limit //= 10
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            return list(csv.DictReader(stream))
    except FileNotFoundError:
        raise PreparationError(f"{label} does not exist: {path}") from None


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_path(value: str) -> str:
    return value.replace("\\", "/").removeprefix("./")


def integer(value: Any) -> int | None:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def source_context(
    repo: Path,
    relative_path: str,
    line: int | None,
    radius: int,
) -> str:
    path = Path(normalize_path(relative_path))
    if path.is_absolute() or ".." in path.parts:
        return "[unsafe path omitted]"
    target = repo / path
    if not target.is_file():
        return "[file absent from reviewed head worktree]"
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"[unable to read source: {exc}]"
    if not lines:
        return "[empty file]"
    focus = min(max(line or 1, 1), len(lines))
    start = max(1, focus - radius)
    end = min(len(lines), focus + radius)
    width = len(str(end))
    return "\n".join(
        f"{'>' if number == focus else ' '} {number:>{width}} | {lines[number - 1]}"
        for number in range(start, end + 1)
    )


def git_diff(repo: Path, relative_path: str) -> str:
    result = subprocess.run(
        [
            "git",
            "diff",
            "--cached",
            "HEAD",
            "--no-ext-diff",
            "--no-color",
            "--unified=8",
            "--",
            normalize_path(relative_path),
        ],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        check=False,
        env={
            **__import__("os").environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
        },
    )
    if result.returncode:
        return f"[git diff failed: {result.stderr.strip()}]"
    return result.stdout


def relevant_diff_hunk(diff: str, line: int | None) -> str:
    if not diff:
        return "[path is outside the pending diff]"
    lines = diff.splitlines()
    starts = [index for index, value in enumerate(lines) if HUNK_RE.match(value)]
    if not starts:
        return diff[:12000]
    hunks = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        match = HUNK_RE.match(lines[start])
        assert match is not None
        new_start = int(match.group("new_start"))
        new_count = int(match.group("new_count") or "1")
        hunks.append((new_start, max(new_count, 1), "\n".join(lines[start:end])))
    selected = None
    if line is not None:
        selected = next(
            (
                body
                for new_start, new_count, body in hunks
                if new_start <= line < new_start + new_count
            ),
            None,
        )
    if selected is None:
        selected = min(
            hunks,
            key=lambda row: abs((line or row[0]) - row[0]),
        )[2]
    return selected[:12000]


def tokens(value: str) -> set[str]:
    return {
        token
        for token in TOKEN_RE.findall(value.casefold())
        if token not in STOPWORDS
    }


def candidate_score(
    finding: dict[str, str],
    reference: dict[str, str],
) -> tuple[float, dict[str, Any]]:
    same_file = normalize_path(finding["file"]).casefold() == normalize_path(
        reference["file_path"]
    ).casefold()
    finding_line = integer(finding.get("line"))
    reference_line = integer(reference.get("start_line"))
    distance = (
        abs(finding_line - reference_line)
        if finding_line is not None and reference_line is not None and same_file
        else None
    )
    finding_terms = tokens(
        f"{finding.get('summary', '')} {finding.get('failure_scenario', '')}"
    )
    reference_terms = tokens(
        " ".join(
            [
                reference.get("rule_id", ""),
                reference.get("rule_name", ""),
                reference.get("message", ""),
                reference.get("quality_category", ""),
                reference.get("cwe", ""),
            ]
        )
    )
    overlap = (
        len(finding_terms & reference_terms)
        / max(1, len(finding_terms | reference_terms))
    )
    automatic = finding.get("silver_finding_id") == reference_id(reference)
    score = (
        (1000.0 if automatic else 0.0)
        + (100.0 if same_file else 0.0)
        + (max(0.0, 60.0 - min(float(distance), 60.0)) if distance is not None else 0.0)
        + overlap * 50.0
    )
    return score, {
        "same_file": int(same_file),
        "line_distance": "" if distance is None else distance,
        "lexical_jaccard": round(overlap, 6),
        "automatic_match": int(automatic),
    }


def markdown_code(value: str, language: str = "") -> str:
    fence = "```"
    return f"{fence}{language}\n{value}\n{fence}"


def build_codebook() -> str:
    return """# RQ3 Semantic Adjudication Codebook

This workspace covers all 267 frozen formal cases. The automatic location
matcher is immutable. Semantic adjudication is an additional analysis layer.

## Finding validity

- `valid_introduced`: concrete issue caused by the pending PR.
- `valid_pre_existing`: real issue, but already present or only exposed by the PR.
- `plausible_uncertain`: technically plausible, but local evidence is insufficient.
- `invalid`: contradicted by the diff/source or only generic advice.
- `unassessable`: cannot be judged from the preserved local evidence.

## CodeQL relation

- `same_issue`: the finding and one or more CodeQL references describe the same
  underlying defect, even if they identify different cause/sink/result lines.
- `related_distinct`: same code area or causal chain, but materially different
  failure condition.
- `no_match`: no CodeQL reference in this PR describes the same defect.
- `no_reference`: the case has no preserved CodeQL reference to compare.
- `uncertain`: equivalence cannot be decided confidently.

`matched_reference_ids` contains pipe-separated reference IDs only for
`same_issue`. Do not rewrite the frozen automatic matcher fields.

## Confidence

Use `high`, `medium`, or `low`. Every label requires a concise rationale and
evidence path/line. The adjudicator must be disclosed accurately; Codex labels
must use `adjudicator_type=LLM_assistant`, not `human`.
"""


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    output_dir = Path(args.output_dir).expanduser().resolve()
    if output_dir.exists():
        raise PreparationError(f"output directory already exists: {output_dir}")
    if args.context_radius < 1:
        raise PreparationError("context-radius must be >= 1")
    if args.candidate_limit < 1:
        raise PreparationError("candidate-limit must be >= 1")

    paths = {
        "cases": Path(args.cases).expanduser().resolve(),
        "references": Path(args.references).expanduser().resolve(),
        "case_metrics": Path(args.case_metrics).expanduser().resolve(),
        "finding_matches": Path(args.finding_matches).expanduser().resolve(),
        "automatic_reference_recovery": Path(
            args.automatic_reference_recovery
        ).expanduser().resolve(),
        "worktree_key": Path(args.worktree_key).expanduser().resolve(),
    }
    worktree_root = Path(args.worktree_root).expanduser().resolve()
    cases = read_csv(paths["cases"], "formal cases")
    references = read_csv(paths["references"], "CodeQL references")
    metrics = read_csv(paths["case_metrics"], "case metrics")
    findings = read_csv(paths["finding_matches"], "finding matches")
    automatic_references = read_csv(
        paths["automatic_reference_recovery"],
        "automatic reference recovery",
    )
    worktree_rows = read_csv(paths["worktree_key"], "worktree key")
    if len(cases) != 267 or len(metrics) != 267 or len(worktree_rows) != 267:
        raise PreparationError("cases, metrics, and worktree key must each cover 267 PRs")
    case_ids = {row["case_id"] for row in cases}
    for label, rows in (
        ("metrics", metrics),
        ("worktrees", worktree_rows),
        ("findings", findings),
        ("references", references),
    ):
        if not {row["case_id"] for row in rows}.issubset(case_ids):
            raise PreparationError(f"{label} contains a case outside the formal set")

    case_by_id = {row["case_id"]: row for row in cases}
    metric_by_id = {row["case_id"]: row for row in metrics}
    worktree_by_id = {row["case_id"]: row for row in worktree_rows}
    refs_by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    findings_by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in references:
        enriched = dict(row)
        enriched["reference_id"] = reference_id(row)
        refs_by_case[row["case_id"]].append(enriched)
    for row in findings:
        findings_by_case[row["case_id"]].append(row)

    automatic_by_id = {row["reference_id"]: row for row in automatic_references}
    if set(automatic_by_id) != {
        row["reference_id"] for values in refs_by_case.values() for row in values
    }:
        raise PreparationError("detailed and automatic reference inventories differ")

    output_dir.mkdir(parents=True)
    packet_dir = output_dir / "case_packets"
    packet_dir.mkdir()
    context_cache: dict[tuple[str, str, int | None], str] = {}
    diff_cache: dict[tuple[str, str], str] = {}
    pair_rows: list[dict[str, Any]] = []
    finding_rows: list[dict[str, Any]] = []
    reference_rows: list[dict[str, Any]] = []
    case_rows: list[dict[str, Any]] = []

    def context(case_id: str, path: str, line: int | None) -> str:
        key = (case_id, normalize_path(path), line)
        if key not in context_cache:
            repo = worktree_root / worktree_by_id[case_id]["worktree_relpath"]
            context_cache[key] = source_context(
                repo,
                path,
                line,
                args.context_radius,
            )
        return context_cache[key]

    def hunk(case_id: str, path: str, line: int | None) -> str:
        path_key = (case_id, normalize_path(path))
        repo = worktree_root / worktree_by_id[case_id]["worktree_relpath"]
        if path_key not in diff_cache:
            diff_cache[path_key] = git_diff(repo, path)
        return relevant_diff_hunk(diff_cache[path_key], line)

    ordered_cases = sorted(
        cases,
        key=lambda row: (row["group"], row["case_control"], row["case_id"]),
    )
    for order, case in enumerate(ordered_cases, start=1):
        case_id = case["case_id"]
        metric = metric_by_id[case_id]
        case_findings = findings_by_case.get(case_id, [])
        case_refs = refs_by_case.get(case_id, [])
        case_rows.append(
            {
                **case,
                **{
                    key: metric.get(key, "")
                    for key in (
                        "model_output_valid",
                        "invalid_model_output_reason",
                        "review_finding_n",
                        "matched_finding_n",
                        "unmatched_report_n",
                        "quality_primary_reference_n",
                        "quality_primary_recovered_n",
                        "quality_strict_reference_n",
                        "quality_strict_recovered_n",
                        "quality_broad_reference_n",
                        "quality_broad_recovered_n",
                        "security_reference_n",
                        "security_recovered_n",
                        "latency_ms",
                        "total_cost_usd",
                    )
                },
                "all_reference_n": len(case_refs),
                "packet_path": f"case_packets/{order:03d}_{case_id}.md",
            }
        )

        ranked_by_finding: dict[str, list[tuple[float, dict[str, Any], dict[str, str]]]] = {}
        for finding in case_findings:
            ranked = []
            for reference in case_refs:
                score, evidence = candidate_score(finding, reference)
                pair = {
                    "case_id": case_id,
                    "group": case["group"],
                    "case_control": case["case_control"],
                    "repo_name": case["repo_name"],
                    "pr_number": case["pr_number"],
                    "model_finding_id": finding["model_finding_id"],
                    "reference_id": reference["reference_id"],
                    "candidate_score": round(score, 6),
                    **evidence,
                    "finding_file": finding["file"],
                    "finding_line": finding["line"],
                    "finding_summary": finding["summary"],
                    "finding_failure_scenario": finding["failure_scenario"],
                    "reference_family": reference["reference_family"],
                    "reference_role": reference["reference_role"],
                    "quality_primary_reference": reference[
                        "quality_primary_reference"
                    ],
                    "rule_id": reference["rule_id"],
                    "rule_name": reference.get("rule_name", ""),
                    "reference_message": reference.get("message", ""),
                    "reference_file": reference["file_path"],
                    "reference_line": reference["start_line"],
                    "manual_relation": "",
                    "manual_confidence": "",
                    "manual_rationale": "",
                }
                pair_rows.append(pair)
                ranked.append((score, evidence, reference))
            ranked.sort(
                key=lambda value: (
                    -value[0],
                    value[2]["reference_id"],
                )
            )
            ranked_by_finding[finding["model_finding_id"]] = ranked
            top = ranked[: args.candidate_limit]
            finding_line = integer(finding.get("line"))
            finding_rows.append(
                {
                    **case,
                    **finding,
                    "same_case_reference_n": len(case_refs),
                    "same_file_reference_n": sum(
                        value[1]["same_file"] for value in ranked
                    ),
                    "top_candidate_reference_ids": "|".join(
                        value[2]["reference_id"] for value in top
                    ),
                    "top_candidate_scores": "|".join(
                        f"{value[0]:.6f}" for value in top
                    ),
                    "source_context": context(
                        case_id,
                        finding["file"],
                        finding_line,
                    ),
                    "diff_hunk": hunk(
                        case_id,
                        finding["file"],
                        finding_line,
                    ),
                    "packet_path": f"case_packets/{order:03d}_{case_id}.md",
                }
            )

        for reference in case_refs:
            reference_line = integer(reference.get("start_line"))
            automatic = automatic_by_id[reference["reference_id"]]
            reference_rows.append(
                {
                    **case,
                    **reference,
                    "automatic_recovered": automatic["recovered"],
                    "source_context": context(
                        case_id,
                        reference["file_path"],
                        reference_line,
                    ),
                    "diff_hunk": hunk(
                        case_id,
                        reference["file_path"],
                        reference_line,
                    ),
                    "packet_path": f"case_packets/{order:03d}_{case_id}.md",
                }
            )

        markdown = [
            f"# {order:03d} · {case_id}",
            "",
            f"- Group: `{case['group']}`",
            f"- Case/control: `{case['case_control']}`",
            f"- Repository/PR: `{case['repo_name']}#{case['pr_number']}`",
            f"- Language/task: `{case['language']}` / `{case['task_type']}`",
            f"- Findings/references: {len(case_findings)} / {len(case_refs)}",
            f"- Automatic matched findings: {metric['matched_finding_n']}",
            f"- Model output valid: `{metric['model_output_valid']}`",
            "",
            "## Reviewer findings",
            "",
        ]
        if not case_findings:
            markdown.append("_No valid structured reviewer findings._")
        for index, finding in enumerate(case_findings, start=1):
            line = integer(finding.get("line"))
            markdown.extend(
                [
                    f"### F{index}: `{finding['model_finding_id']}`",
                    "",
                    f"- Location: `{finding['file']}:{finding['line']}`",
                    f"- Automatic status: `{finding['match_status']}`",
                    f"- Summary: {finding['summary']}",
                    f"- Failure scenario: {finding['failure_scenario']}",
                    "",
                    "Source context:",
                    "",
                    markdown_code(context(case_id, finding["file"], line)),
                    "",
                    "Relevant pending-diff hunk:",
                    "",
                    markdown_code(hunk(case_id, finding["file"], line), "diff"),
                    "",
                    "Top CodeQL candidates:",
                    "",
                ]
            )
            ranked = ranked_by_finding[finding["model_finding_id"]][
                : args.candidate_limit
            ]
            if not ranked:
                markdown.append("_No CodeQL reference exists for this case._")
            for rank, (score, evidence, reference) in enumerate(ranked, start=1):
                markdown.append(
                    f"{rank}. `{reference['reference_id']}` score={score:.2f}; "
                    f"`{reference['rule_id']}` at "
                    f"`{reference['file_path']}:{reference['start_line']}`; "
                    f"same_file={evidence['same_file']}; "
                    f"distance={evidence['line_distance']}; "
                    f"message={reference.get('message', '')}"
                )
            markdown.append("")

        markdown.extend(["## CodeQL references", ""])
        if not case_refs:
            markdown.append("_No preserved CodeQL reference for this case._")
        for index, reference in enumerate(case_refs, start=1):
            line = integer(reference.get("start_line"))
            markdown.extend(
                [
                    f"### R{index}: `{reference['reference_id']}`",
                    "",
                    f"- Family/role: `{reference['reference_family']}` / "
                    f"`{reference['reference_role']}`",
                    f"- Rule: `{reference['rule_id']}` — "
                    f"{reference.get('rule_name', '')}",
                    f"- Location: `{reference['file_path']}:{reference['start_line']}`",
                    f"- Message: {reference.get('message', '')}",
                    f"- Primary/strict/broad: "
                    f"`{reference['quality_primary_reference']}` / "
                    f"`{reference['quality_strict_reference']}` / "
                    f"`{reference['quality_broad_reference']}`",
                    "",
                    "Source context:",
                    "",
                    markdown_code(
                        context(case_id, reference["file_path"], line)
                    ),
                    "",
                    "Relevant pending-diff hunk:",
                    "",
                    markdown_code(
                        hunk(case_id, reference["file_path"], line),
                        "diff",
                    ),
                    "",
                ]
            )
        packet_path = packet_dir / f"{order:03d}_{case_id}.md"
        packet_path.write_text("\n".join(markdown) + "\n", encoding="utf-8")

    case_fields = list(case_rows[0])
    finding_fields = list(finding_rows[0]) if finding_rows else []
    reference_fields = list(reference_rows[0]) if reference_rows else []
    pair_fields = list(pair_rows[0]) if pair_rows else []
    write_csv(output_dir / "cases.csv", case_rows, case_fields)
    write_csv(
        output_dir / "findings_for_adjudication.csv",
        finding_rows,
        finding_fields,
    )
    write_csv(
        output_dir / "references_for_adjudication.csv",
        reference_rows,
        reference_fields,
    )
    write_csv(
        output_dir / "candidate_pairs.csv",
        pair_rows,
        pair_fields,
    )
    write_csv(
        output_dir / "finding_labels.csv",
        [
            {
                "case_id": row["case_id"],
                "model_finding_id": row["model_finding_id"],
            }
            for row in finding_rows
        ],
        FINDING_LABEL_FIELDS,
    )
    write_csv(
        output_dir / "case_labels.csv",
        [{"case_id": row["case_id"]} for row in case_rows],
        CASE_LABEL_FIELDS,
    )
    (output_dir / "ADJUDICATION_CODEBOOK.md").write_text(
        build_codebook(),
        encoding="utf-8",
    )

    output_files = sorted(
        path
        for path in output_dir.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "prepared_unlabeled",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "case_n": len(case_rows),
        "finding_n": len(finding_rows),
        "reference_n": len(reference_rows),
        "candidate_pair_n": len(pair_rows),
        "packet_n": len(list(packet_dir.glob("*.md"))),
        "context_radius": args.context_radius,
        "candidate_limit": args.candidate_limit,
        "inputs": {
            name: {"path": str(path), "sha256": sha256_file(path)}
            for name, path in paths.items()
        },
        "worktree_root": str(worktree_root),
        "outputs": {
            str(path.relative_to(output_dir)): {
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
            for path in output_files
        },
        "adjudicator_disclosure": (
            "Labels added by Codex must be identified as LLM_assistant and "
            "must not be represented as independent human annotation."
        ),
    }
    write_json(output_dir / "manifest.json", manifest)
    return manifest


def main() -> None:
    args = parse_args()
    try:
        manifest = prepare(args)
    except (PreparationError, OSError) as exc:
        raise SystemExit(f"RQ3 adjudication preparation failed: {exc}") from None
    print(
        "RQ3 semantic adjudication workspace prepared: "
        f"cases={manifest['case_n']}, findings={manifest['finding_n']}, "
        f"references={manifest['reference_n']}, pairs={manifest['candidate_pair_n']}"
    )


if __name__ == "__main__":
    main()
