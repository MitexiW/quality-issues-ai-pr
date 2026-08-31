#!/usr/bin/env python3
# RQ3 review experiment entry point.
"""Materialize only Git objects required by failed RQ3 worktree cases.

The worktree builder intentionally disables partial-clone lazy fetching.  This
separate preparation command groups failed cases by repository, fetches their
exact before/head commits, and asks Git's promisor remote to materialize the
tracked blobs for those revisions.  It never invokes an LLM and defaults to a
read-only inventory audit unless ``--execute`` is provided.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
STUDY_ROOT = ROOT / "data/experiments/security-and-quality/study_stars500"
PLAN_ROOT = STUDY_ROOT / "reports/rq3_formal_plan_20260727_v1"
WORKTREE_ROOT = STUDY_ROOT / "reports/rq3_formal_worktrees_20260727_v1"
SCHEMA_VERSION = "1.0.0"
REPORT_FIELDS = [
    "group",
    "repo_name",
    "case_n",
    "revision_n",
    "tracked_blob_n",
    "missing_blob_before_n",
    "missing_blob_after_n",
    "cache_created",
    "status",
    "reason",
    "duration_seconds",
]


class HydrationError(ValueError):
    """Raised when exact Git object hydration cannot be completed."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="精确补齐 RQ3 worktree 失败 case 所需的 partial-clone Git 对象"
    )
    parser.add_argument("--cases", default=str(PLAN_ROOT / "formal_cases.csv"))
    parser.add_argument(
        "--failures", default=str(WORKTREE_ROOT / "worktree_failures.csv")
    )
    parser.add_argument("--ai-jobs", default=str(STUDY_ROOT / "ai/codeql_jobs.csv"))
    parser.add_argument(
        "--human-jobs", default=str(STUDY_ROOT / "human/codeql_jobs.csv")
    )
    parser.add_argument(
        "--ai-cache-dir", default=str(STUDY_ROOT / "ai/repos/.cache")
    )
    parser.add_argument(
        "--human-cache-dir", default=str(STUDY_ROOT / "human/repos/.cache")
    )
    parser.add_argument(
        "--output-dir",
        default=str(STUDY_ROOT / "reports/rq3_git_hydration_20260727_v1"),
    )
    parser.add_argument(
        "--case-kind",
        choices=("positive", "control", "all"),
        default="positive",
    )
    parser.add_argument("--repo", action="append", dest="repos")
    parser.add_argument(
        "--failure-status",
        action="append",
        dest="failure_statuses",
        help=(
            "When the failure inventory has a status column, select only these "
            "statuses. Repeat as needed; omitted preserves the original behavior."
        ),
    )
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=7200)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="允许 GitHub fetch/lazy fetch；省略时只生成待补齐清单",
    )
    return parser.parse_args(argv)


def read_csv(path: Path, label: str) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            return list(csv.DictReader(stream))
    except FileNotFoundError:
        raise HydrationError(f"{label} does not exist: {path}") from None


def revision_from_job(row: dict[str, str]) -> str:
    revision = row.get("revision", "").strip().lower()
    if revision == "before":
        return (
            row.get("checkout_ref", "").strip()
            or row.get("base_sha", "").strip()
        )
    if revision == "after":
        return (
            row.get("checkout_ref", "").strip()
            or row.get("head_sha", "").strip()
        )
    return ""


def build_targets(
    *,
    cases: list[dict[str, str]],
    failures: list[dict[str, str]],
    ai_jobs: list[dict[str, str]],
    human_jobs: list[dict[str, str]],
    ai_cache_dir: Path,
    human_cache_dir: Path,
    case_kind: str = "positive",
    repos: set[str] | None = None,
    failure_statuses: set[str] | None = None,
) -> list[dict[str, Any]]:
    case_index = {row.get("case_id", "").strip(): row for row in cases}
    jobs: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for group, rows in (("ai", ai_jobs), ("human", human_jobs)):
        for row in rows:
            key = (
                group,
                row.get("repo_name", "").strip().casefold(),
                row.get("pr_number", "").strip(),
                row.get("revision", "").strip().lower(),
            )
            jobs[key] = row
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for failure in failures:
        if (
            failure_statuses is not None
            and str(failure.get("status", "")).strip() not in failure_statuses
        ):
            continue
        case_id = failure.get("case_id", "").strip()
        case = case_index.get(case_id)
        if case is None:
            raise HydrationError(f"failure references unknown case: {case_id}")
        kind = case.get("case_control", "").strip().lower()
        if case_kind != "all" and kind != case_kind:
            continue
        repo_name = case.get("repo_name", "").strip()
        if repos and repo_name.casefold() not in repos:
            continue
        group = case.get("group", "").strip().lower()
        pr_number = case.get("pr_number", "").strip()
        key = (group, repo_name)
        target = grouped.setdefault(
            key,
            {
                "group": group,
                "repo_name": repo_name,
                "case_ids": [],
                "revisions": set(),
                "cache": (
                    ai_cache_dir if group == "ai" else human_cache_dir
                )
                / f"{repo_name.replace('/', '_')}.git",
                "remote_url": f"https://github.com/{repo_name}.git",
            },
        )
        target["case_ids"].append(case_id)
        for revision in ("before", "after"):
            job = jobs.get((group, repo_name.casefold(), pr_number, revision))
            if job is None:
                raise HydrationError(
                    f"missing {group} {revision} job for {repo_name}#{pr_number}"
                )
            sha = revision_from_job(job)
            if not sha:
                raise HydrationError(
                    f"missing revision SHA for {repo_name}#{pr_number} {revision}"
                )
            target["revisions"].add(sha)
    result = []
    for target in grouped.values():
        target["case_ids"] = sorted(set(target["case_ids"]))
        target["revisions"] = sorted(target["revisions"])
        result.append(target)
    return sorted(result, key=lambda row: (row["group"], row["repo_name"].casefold()))


def git_env(*, no_lazy_fetch: bool) -> dict[str, str]:
    env = dict(os.environ)
    for name in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        env.pop(name, None)
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    if no_lazy_fetch:
        env["GIT_NO_LAZY_FETCH"] = "1"
    else:
        env.pop("GIT_NO_LAZY_FETCH", None)
    return env


def run(
    command: list[str],
    *,
    timeout: float,
    input_bytes: bytes | None = None,
    no_lazy_fetch: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env=git_env(no_lazy_fetch=no_lazy_fetch),
        )
    except subprocess.TimeoutExpired:
        raise HydrationError(f"command timed out: {' '.join(command)}") from None
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise HydrationError(
            f"command failed ({result.returncode}): {' '.join(command)}: {detail}"
        )
    return result


def ensure_cache(target: dict[str, Any], timeout: float) -> bool:
    cache = Path(target["cache"])
    if cache.is_dir():
        return False
    cache.parent.mkdir(parents=True, exist_ok=True)
    # A worktree builder may be reading sibling caches while hydration runs.
    # Do not expose a half-cloned bare repository at the canonical path: clone
    # beside it and publish the completed cache with one same-filesystem rename.
    with tempfile.TemporaryDirectory(
        prefix=f".{cache.name}.hydrate-", dir=cache.parent
    ) as temporary:
        staged_cache = Path(temporary) / cache.name
        run(
            [
                "git",
                "clone",
                "--bare",
                "--filter=blob:none",
                "--no-tags",
                "--quiet",
                target["remote_url"],
                str(staged_cache),
            ],
            timeout=timeout,
        )
        if cache.is_dir():
            # Another repair worker completed the same cache while this clone
            # was in flight.  Its complete cache wins; the temporary clone is
            # removed by TemporaryDirectory.
            return False
        staged_cache.replace(cache)
    return True


def ensure_revision(cache: Path, sha: str, timeout: float) -> None:
    probe = subprocess.run(
        ["git", f"--git-dir={cache}", "cat-file", "-e", f"{sha}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env=git_env(no_lazy_fetch=True),
    )
    if probe.returncode == 0:
        return
    run(
        [
            "git",
            "-c",
            "fetch.negotiationAlgorithm=noop",
            f"--git-dir={cache}",
            "fetch",
            "--no-tags",
            "--filter=blob:none",
            "origin",
            sha,
        ],
        timeout=timeout,
    )
    verify = subprocess.run(
        ["git", f"--git-dir={cache}", "cat-file", "-e", f"{sha}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env=git_env(no_lazy_fetch=True),
    )
    if verify.returncode != 0:
        raise HydrationError(f"fetched revision is still unavailable: {sha}")


def tracked_blob_ids(cache: Path, revisions: list[str], timeout: float) -> list[str]:
    blobs: set[str] = set()
    for revision in revisions:
        result = run(
            ["git", f"--git-dir={cache}", "ls-tree", "-r", "-z", revision],
            timeout=timeout,
            no_lazy_fetch=False,
        )
        for raw in result.stdout.split(b"\0"):
            if not raw:
                continue
            try:
                metadata, _path = raw.split(b"\t", 1)
                _mode, kind, oid = metadata.split(b" ", 2)
            except ValueError as exc:
                raise HydrationError("git ls-tree returned an invalid entry") from exc
            if kind == b"blob":
                blobs.add(oid.decode("ascii"))
    return sorted(blobs)


def missing_objects(
    cache: Path,
    object_ids: list[str],
    timeout: float,
) -> list[str]:
    if not object_ids:
        return []
    payload = ("\n".join(object_ids) + "\n").encode("ascii")
    result = run(
        [
            "git",
            f"--git-dir={cache}",
            "cat-file",
            "--batch-check=%(objectname) %(objecttype)",
        ],
        timeout=timeout,
        input_bytes=payload,
        no_lazy_fetch=True,
    )
    missing: list[str] = []
    for line in result.stdout.decode("ascii", errors="replace").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-1] == "missing":
            missing.append(fields[0])
    return missing


def materialize_objects(
    cache: Path,
    object_ids: list[str],
    timeout: float,
) -> None:
    if not object_ids:
        return
    payload = ("\n".join(object_ids) + "\n").encode("ascii")
    # This is the same batching shape used by Git's partial-clone fetch-object
    # helper.  Sending every missing OID through one ``fetch --stdin`` avoids
    # ``cat-file`` launching one network request and one tiny pack per blob.
    run(
        [
            "git",
            "-c",
            "fetch.negotiationAlgorithm=noop",
            f"--git-dir={cache}",
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            "--recurse-submodules=no",
            "--filter=blob:none",
            "origin",
            "--stdin",
        ],
        timeout=timeout,
        input_bytes=payload,
        no_lazy_fetch=False,
    )


def hydrate_target(
    target: dict[str, Any],
    *,
    execute: bool,
    timeout: float,
) -> dict[str, Any]:
    started = time.monotonic()
    base = {
        "group": target["group"],
        "repo_name": target["repo_name"],
        "case_n": len(target["case_ids"]),
        "revision_n": len(target["revisions"]),
        "tracked_blob_n": "",
        "missing_blob_before_n": "",
        "missing_blob_after_n": "",
        "cache_created": False,
        "status": "planned" if not execute else "failed",
        "reason": "",
        "duration_seconds": "",
    }
    if not execute:
        base["reason"] = (
            "network fetch not attempted; rerun with --execute after reviewing inventory"
        )
        base["duration_seconds"] = f"{time.monotonic() - started:.3f}"
        return base
    try:
        cache_created = ensure_cache(target, timeout)
        cache = Path(target["cache"])
        for revision in target["revisions"]:
            ensure_revision(cache, revision, timeout)
        object_ids = tracked_blob_ids(cache, target["revisions"], timeout)
        missing_before = missing_objects(cache, object_ids, timeout)
        materialize_objects(cache, missing_before, timeout)
        missing_after = missing_objects(cache, object_ids, timeout)
        if missing_after:
            raise HydrationError(
                f"{len(missing_after)} tracked blobs remain unavailable"
            )
        base.update(
            {
                "tracked_blob_n": len(object_ids),
                "missing_blob_before_n": len(missing_before),
                "missing_blob_after_n": 0,
                "cache_created": cache_created,
                "status": "hydrated" if missing_before or cache_created else "already_complete",
            }
        )
    except (HydrationError, OSError) as exc:
        base["reason"] = str(exc)
    base["duration_seconds"] = f"{time.monotonic() - started:.3f}"
    return base


def write_report(path: Path, rows: list[dict[str, Any]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def orchestrate(args: argparse.Namespace) -> dict[str, Any]:
    if args.workers < 1:
        raise HydrationError("workers must be >= 1")
    if args.timeout <= 0:
        raise HydrationError("timeout must be > 0")
    cases_path = Path(args.cases).expanduser().resolve()
    failures_path = Path(args.failures).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    if output_dir.exists():
        raise HydrationError(f"output directory already exists: {output_dir}")
    output_dir.mkdir(parents=True)
    selected_repos = (
        {repo.strip().casefold() for repo in args.repos if repo.strip()}
        if args.repos
        else None
    )
    targets = build_targets(
        cases=read_csv(cases_path, "cases"),
        failures=read_csv(failures_path, "failures"),
        ai_jobs=read_csv(Path(args.ai_jobs).expanduser().resolve(), "AI jobs"),
        human_jobs=read_csv(
            Path(args.human_jobs).expanduser().resolve(), "Human jobs"
        ),
        ai_cache_dir=Path(args.ai_cache_dir).expanduser().resolve(),
        human_cache_dir=Path(args.human_cache_dir).expanduser().resolve(),
        case_kind=args.case_kind,
        repos=selected_repos,
        failure_statuses=(
            {status.strip() for status in args.failure_statuses if status.strip()}
            if args.failure_statuses
            else None
        ),
    )
    rows: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                hydrate_target,
                target,
                execute=args.execute,
                timeout=args.timeout,
            ): target
            for target in targets
        }
        for index, future in enumerate(as_completed(futures), start=1):
            row = future.result()
            rows.append(row)
            write_report(
                output_dir / "hydration_report.csv",
                sorted(rows, key=lambda value: (value["group"], value["repo_name"].casefold())),
            )
            print(
                f"[{index}/{len(targets)}] {row['repo_name']}: {row['status']}",
                flush=True,
            )
    rows.sort(key=lambda value: (value["group"], value["repo_name"].casefold()))
    write_report(output_dir / "hydration_report.csv", rows)
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        counts[str(row["status"])] += 1
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": (
            "audit_complete"
            if not args.execute
            else ("passed" if not counts.get("failed") else "incomplete")
        ),
        "network_authorized": bool(args.execute),
        "case_kind": args.case_kind,
        "failure_statuses": sorted(args.failure_statuses or []),
        "repository_n": len(targets),
        "case_n": sum(len(target["case_ids"]) for target in targets),
        "status_counts": dict(sorted(counts.items())),
        "inputs": {
            "cases": str(cases_path),
            "failures": str(failures_path),
        },
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> None:
    args = parse_args()
    try:
        manifest = orchestrate(args)
    except (HydrationError, OSError) as exc:
        raise SystemExit(f"RQ3 Git hydration error: {exc}") from None
    print(
        "RQ3 Git object hydration finished: "
        f"status={manifest['status']}, repos={manifest['repository_n']}, "
        f"cases={manifest['case_n']}"
    )


if __name__ == "__main__":
    main()
