#!/usr/bin/env python3
# CodeQL pipeline entry point.
"""Create before/after CodeQL job manifests."""

from __future__ import annotations

import argparse
import csv
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

from experiment import (
    DEFAULT_QUERY_SUITE,
    EXPECTED_CODEQL_VERSION,
    default_build_command,
    default_build_mode,
    query_spec,
)
from load_dataset import iter_local_batches
from utils import clean_text, setup_logging

JOB_FIELDS = [
    "job_id",
    "repo_id",
    "repo_name",
    "repo_url",
    "pr_id",
    "pr_number",
    "agent",
    "revision",
    "checkout_ref",
    "base_sha",
    "head_sha",
    "language",
    "codeql_language",
    "codeql_version",
    "query_suite",
    "build_mode",
    "build_command",
    "source_dir",
    "database_dir",
    "sarif_path",
    "before_sarif",
    "after_sarif",
    "comparison_status",
    "status",
    "create_command",
    "analyze_command",
]

CODEQL_LANGUAGE_MAP = {
    "C": "cpp",
    "C++": "cpp",
    "C#": "csharp",
    "Go": "go",
    "Java": "java-kotlin",
    "Kotlin": "java-kotlin",
    "JavaScript": "javascript-typescript",
    "TypeScript": "javascript-typescript",
    "Python": "python",
    "Ruby": "ruby",
    "Swift": "swift",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="生成 before/after CodeQL 作业清单")
    parser.add_argument("--prs", default="data/candidates/candidate_prs.csv")
    parser.add_argument("--output", default="data/metadata/codeql_jobs.csv")
    parser.add_argument("--repos-dir", default="data/repos")
    parser.add_argument("--databases-dir", default="data/codeql-db")
    parser.add_argument("--sarif-dir", default="data/sarif")
    parser.add_argument("--batch-size", type=int, default=10_000)
    parser.add_argument("--codeql", default="codeql")
    parser.add_argument("--codeql-version", default=EXPECTED_CODEQL_VERSION)
    parser.add_argument("--query-suite", default=DEFAULT_QUERY_SUITE)
    parser.add_argument(
        "--before-ref-template",
        default="",
        help="例如 refs/pull/{pr_number}/base；为空时标记为 needs_ref",
    )
    parser.add_argument(
        "--after-ref-template",
        default="refs/pull/{pr_number}/head",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def safe_slug(value: str) -> str:
    return "".join(char if char.isalnum() or char in "-_." else "_" for char in value)


def command_for_job(job: dict[str, Any]) -> tuple[str, str]:
    create_parts = [
        "codeql database create",
        shlex.quote(job["database_dir"]),
        f"--language={shlex.quote(job['codeql_language'])}",
        f"--source-root={shlex.quote(job['source_dir'])}",
    ]
    if job["build_command"]:
        create_parts.append(f"--command={shlex.quote(job['build_command'])}")
    else:
        create_parts.append(f"--build-mode={shlex.quote(job['build_mode'])}")
    create = " ".join(create_parts)
    suite = query_spec(job["codeql_language"], job["query_suite"])
    analyze = " ".join(
        [
            "codeql database analyze",
            shlex.quote(job["database_dir"]),
            shlex.quote(suite),
            "--format=sarif-latest",
            f"--output={shlex.quote(job['sarif_path'])}",
        ]
    )
    return create, analyze


def installed_codeql_version(executable: str) -> str:
    result = subprocess.run(
        [executable, "version", "--format=terse"],
        check=True,
        text=True,
        capture_output=True,
    )
    output = result.stdout + result.stderr
    for line in output.splitlines():
        line = line.strip()
        if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+].*)?", line):
            return line
    raise RuntimeError(f"无法解析 CodeQL 版本输出: {output[-1000:]}")


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)
    actual_version = installed_codeql_version(args.codeql)
    if actual_version != args.codeql_version:
        raise SystemExit(
            f"CodeQL 版本不匹配: 期望 {args.codeql_version}，实际 {actual_version}"
        )
    output = Path(args.output)
    roots = [
        Path(args.repos_dir),
        Path(args.databases_dir),
        Path(args.sarif_dir),
        output.parent,
        Path("data/candidates"),
    ]
    for root in roots:
        root.mkdir(parents=True, exist_ok=True)

    count = 0
    missing_refs = 0
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=JOB_FIELDS)
        writer.writeheader()
        for batch in iter_local_batches(args.prs, batch_size=args.batch_size):
            for row in batch.to_dict(orient="records"):
                repo_name = clean_text(row.get("repo_name"))
                pr_number = clean_text(row.get("pr_number"))
                pr_id = clean_text(row.get("pr_id"))
                agent = clean_text(row.get("agent"))
                language = clean_text(row.get("language"))
                codeql_language = CODEQL_LANGUAGE_MAP.get(language)
                if not codeql_language:
                    continue
                repo_slug = safe_slug(repo_name)
                format_values = {
                    "repo_id": clean_text(row.get("repo_id")),
                    "repo_name": repo_name,
                    "pr_id": pr_id,
                    "pr_number": pr_number,
                }
                refs = {
                    "before": args.before_ref_template.format(**format_values)
                    if args.before_ref_template
                    else "",
                    "after": args.after_ref_template.format(**format_values)
                    if args.after_ref_template
                    else "",
                }
                for revision in ("before", "after"):
                    job_id = f"{repo_slug}__pr-{safe_slug(pr_number or pr_id)}__{revision}"
                    source_dir = str(Path(args.repos_dir) / repo_slug / job_id)
                    database_dir = str(Path(args.databases_dir) / job_id)
                    sarif_path = str(Path(args.sarif_dir) / f"{job_id}.sarif")
                    before_sarif = str(
                        Path(args.sarif_dir)
                        / f"{repo_slug}__pr-{safe_slug(pr_number or pr_id)}__before.sarif"
                    )
                    after_sarif = str(
                        Path(args.sarif_dir)
                        / f"{repo_slug}__pr-{safe_slug(pr_number or pr_id)}__after.sarif"
                    )
                    checkout_ref = refs[revision]
                    status = "ready" if checkout_ref else "needs_ref"
                    missing_refs += int(not checkout_ref)
                    build_mode = default_build_mode(language, codeql_language)
                    build_command = default_build_command(language, codeql_language)
                    job = {
                        "job_id": job_id,
                        "repo_id": clean_text(row.get("repo_id")),
                        "repo_name": repo_name,
                        "repo_url": clean_text(row.get("repo_url")),
                        "pr_id": pr_id,
                        "pr_number": pr_number,
                        "agent": agent,
                        "revision": revision,
                        "checkout_ref": checkout_ref,
                        "base_sha": "",
                        "head_sha": "",
                        "language": language,
                        "codeql_language": codeql_language,
                        "codeql_version": args.codeql_version,
                        "query_suite": args.query_suite,
                        "build_mode": build_mode,
                        "build_command": build_command,
                        "source_dir": source_dir,
                        "database_dir": database_dir,
                        "sarif_path": sarif_path,
                        "before_sarif": before_sarif,
                        "after_sarif": after_sarif,
                        "comparison_status": "pending",
                        "status": status,
                    }
                    create, analyze = command_for_job(job)
                    job["create_command"] = create
                    job["analyze_command"] = analyze
                    writer.writerow(job)
                    count += 1

    print(
        f"已生成 {count} 个 CodeQL 作业 -> {output}；"
        f"{missing_refs} 个作业需补充 checkout_ref"
    )


if __name__ == "__main__":
    main()
