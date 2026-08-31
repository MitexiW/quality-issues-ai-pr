#!/usr/bin/env python3
"""Build one provenance-blinded worktree for CodeQL alert adjudication.

This module reuses the audited snapshot reconstruction used by the RQ3
review experiment, but derives the pending change directly from the frozen
before/after jobs.  It therefore also supports PRs whose GitHub REST patch was
truncated or omitted.
"""

from __future__ import annotations

import csv
import hashlib
import os
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import prepare_claude_review_worktrees as worktrees


ROOT = Path(__file__).resolve().parents[1]


def maximize_csv_field_limit() -> None:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


maximize_csv_field_limit()


class AdjudicationWorktreeError(ValueError):
    """Raised when an adjudication worktree cannot be reconstructed."""


def clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def normalized_pr_key(
    group: Any, repo_name: Any, pr_number: Any
) -> tuple[str, str, str]:
    return (
        clean(group).casefold(),
        clean(repo_name).casefold(),
        clean(pr_number),
    )


def read_jobs(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def absolute_source_job(job: dict[str, str]) -> dict[str, str]:
    normalized = dict(job)
    source = clean(normalized.get("source_dir"))
    if source and not Path(source).is_absolute():
        normalized["source_dir"] = str((ROOT / source).resolve())
    return normalized


def build_job_index(
    ai_jobs: list[dict[str, str]],
    human_jobs: list[dict[str, str]],
) -> dict[tuple[str, str, str, str], dict[str, str]]:
    index: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for group, rows in (("ai", ai_jobs), ("human", human_jobs)):
        for row in rows:
            revision = clean(row.get("revision")).casefold()
            if revision not in {"before", "after"}:
                continue
            key = (*normalized_pr_key(group, row.get("repo_name"), row.get("pr_number")), revision)
            if key in index:
                raise AdjudicationWorktreeError(f"duplicate job revision: {key}")
            index[key] = row
    return index


def full_revision(job: dict[str, str], fallback_field: str) -> str:
    revision = clean(job.get("checkout_ref")) or clean(job.get(fallback_field))
    if not worktrees.is_full_object_id(revision):
        recovered = worktrees.source_head_revision(job)
        if recovered:
            revision = recovered
    if not worktrees.is_full_object_id(revision):
        raise AdjudicationWorktreeError(
            f"job lacks a full {fallback_field}/checkout_ref revision"
        )
    return revision


def export_verified_plain_snapshot(
    job: dict[str, str],
    cache: Path,
    revision_sha: str,
    destination: Path,
) -> tuple[str, str, dict[str, str]]:
    """Recover an exact tree from a pruned source directory.

    Some completed scale jobs retain source files after their ``.git``
    metadata was pruned, while the partial bare cache lacks one or more blobs.
    The cache still contains the commit/tree/index metadata.  This fallback
    enumerates that exact tree and accepts each retained file only when its
    recomputed Git object ID matches the tree entry.
    """

    source_raw = clean(job.get("source_dir"))
    source = Path(source_raw).expanduser() if source_raw else None
    if source is None or not source.is_dir() or not cache.is_dir():
        raise AdjudicationWorktreeError(
            "verified snapshot fallback requires source and bare cache directories"
        )
    git_prefix = ["git", f"--git-dir={cache}"]
    object_format = (
        worktrees.run([*git_prefix, "rev-parse", "--show-object-format"])
        .stdout.decode()
        .strip()
    )
    with tempfile.TemporaryDirectory(prefix="adjudication-index-") as temporary:
        index_path = Path(temporary) / "index"
        env = {"GIT_INDEX_FILE": str(index_path)}
        worktrees.run([*git_prefix, "read-tree", revision_sha], extra_env=env)
        expected_tree = (
            worktrees.run([*git_prefix, "write-tree"], extra_env=env)
            .stdout.decode()
            .strip()
        )
        listing = worktrees.run(
            [*git_prefix, "ls-files", "--stage", "-z"], extra_env=env
        ).stdout

    destination.mkdir(parents=True, exist_ok=True)
    gitlinks: dict[str, str] = {}
    for raw_entry in listing.split(b"\0"):
        worktrees.remaining_case_timeout()
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            raw_mode, raw_oid, raw_stage = metadata.split(b" ", 2)
            mode = raw_mode.decode("ascii")
            expected_oid = raw_oid.decode("ascii")
            stage = raw_stage.decode("ascii")
            relative = raw_path.decode("utf-8", errors="surrogateescape")
        except (ValueError, UnicodeDecodeError) as exc:
            raise AdjudicationWorktreeError(
                "bare-cache tree contains an invalid index entry"
            ) from exc
        relative_path = Path(relative)
        if stage != "0" or relative_path.is_absolute() or ".." in relative_path.parts:
            raise AdjudicationWorktreeError(
                f"unsafe or unmerged tree entry in snapshot fallback: {relative}"
            )
        if mode == "160000":
            gitlinks[relative] = expected_oid
            continue
        source_path = source / relative_path
        target_path = destination / relative_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        if mode == "120000":
            if not source_path.is_symlink():
                raise AdjudicationWorktreeError(
                    f"retained source lacks tracked symlink: {relative}"
                )
            link_target = os.readlink(source_path)
            payload = os.fsencode(link_target)
            if worktrees.git_object_digest(payload, object_format) != expected_oid:
                raise AdjudicationWorktreeError(
                    f"retained symlink differs from frozen Git tree: {relative}"
                )
            os.symlink(link_target, target_path)
        elif mode in {"100644", "100755"}:
            if source_path.is_symlink() or not source_path.is_file():
                raise AdjudicationWorktreeError(
                    f"retained source lacks tracked file: {relative}"
                )
            payload = source_path.read_bytes()
            if worktrees.git_object_digest(payload, object_format) != expected_oid:
                raise AdjudicationWorktreeError(
                    f"retained file differs from frozen Git tree: {relative}"
                )
            target_path.write_bytes(payload)
            permissions = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
            if mode == "100755":
                permissions |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            target_path.chmod(permissions)
        else:
            raise AdjudicationWorktreeError(
                f"unsupported tracked-file mode {mode}: {relative}"
            )
    return expected_tree, "verified_pruned_experiment_source", gitlinks


def export_revision_with_verified_fallback(
    job: dict[str, str],
    cache: Path,
    revision_sha: str,
    destination: Path,
) -> tuple[str, str, dict[str, str]]:
    try:
        return worktrees.export_revision(job, cache, revision_sha, destination)
    except worktrees.WorktreeBuildError as primary:
        worktrees.clear_snapshot_directory(destination)
        try:
            return export_verified_plain_snapshot(job, cache, revision_sha, destination)
        except AdjudicationWorktreeError as fallback:
            worktrees.clear_snapshot_directory(destination)
            raise AdjudicationWorktreeError(
                f"{primary}; verified retained-source fallback failed: {fallback}"
            ) from fallback


def build_case_worktree(
    case: dict[str, str],
    *,
    job_index: dict[tuple[str, str, str, str], dict[str, str]],
    cache_dirs: dict[str, Path],
    scratch_root: Path,
    timeout_seconds: float = 900,
) -> tuple[dict[str, str], Path]:
    """Reconstruct one neutral before commit with the full head tree staged."""

    case_id = clean(case.get("case_id"))
    group = clean(case.get("group")).casefold()
    repo_name = clean(case.get("repo_name"))
    pr_number = clean(case.get("pr_number"))
    if not case_id or group not in {"ai", "human"} or not repo_name or not pr_number:
        raise AdjudicationWorktreeError("case lacks a valid id/group/repository/PR")
    if timeout_seconds <= 0:
        raise AdjudicationWorktreeError("timeout_seconds must be positive")
    before = job_index.get((*normalized_pr_key(group, repo_name, pr_number), "before"))
    after = job_index.get((*normalized_pr_key(group, repo_name, pr_number), "after"))
    if before is None or after is None:
        raise AdjudicationWorktreeError(
            f"missing before/after jobs for {group}:{repo_name}#{pr_number}"
        )
    before = absolute_source_job(before)
    after = absolute_source_job(after)
    base_sha = full_revision(before, "base_sha")
    head_sha = full_revision(after, "head_sha")
    cache_dir = cache_dirs[group] / f"{repo_name.replace('/', '_')}.git"
    case_root = scratch_root / case_id
    repo = case_root / "repo"
    shutil.rmtree(case_root, ignore_errors=True)
    case_root.mkdir(parents=True)
    deadline_token = worktrees.CASE_DEADLINE.set(
        time.monotonic() + timeout_seconds
    )
    try:
        original_base_tree, before_source, base_gitlinks = export_revision_with_verified_fallback(
            before, cache_dir, base_sha, repo
        )
        absolute_symlinks = worktrees.sanitize_snapshot_symlinks(repo)
        neutral_tree = worktrees.initialize_neutral_repo(repo, base_gitlinks)
        if not absolute_symlinks and neutral_tree != original_base_tree:
            raise AdjudicationWorktreeError(
                "reconstructed before snapshot does not match its Git tree"
            )
        worktrees.clear_working_tree(repo)
        original_head_tree, after_source, head_gitlinks = export_revision_with_verified_fallback(
            after, cache_dir, head_sha, repo
        )
        worktrees.sanitize_snapshot_symlinks(
            repo,
            expected_absolute=absolute_symlinks,
        )
        pending_hash, changed_file_n, sanitized_head_tree = (
            worktrees.stage_after_and_audit(
                repo,
                None if absolute_symlinks else original_head_tree,
                head_gitlinks,
            )
        )
        row = {
            "case_id": case_id,
            "group": group,
            "repo_name": repo_name,
            "pr_number": pr_number,
            "base_sha": base_sha,
            "head_sha": head_sha,
            "patch_sha256": pending_hash,
            "base_tree_sha": neutral_tree,
            "head_tree_sha": sanitized_head_tree,
            "pending_diff_sha256": pending_hash,
            "changed_file_n": str(changed_file_n),
            "enrichment_changed_file_n": "",
            "reconstruction_source": (
                f"before={before_source};after={after_source};"
                "diff_source=exact_reconstructed_trees"
                + (
                    ";invariant_absolute_symlinks_neutralized="
                    + hashlib.sha256(
                        repr(sorted(absolute_symlinks.items())).encode("utf-8")
                    ).hexdigest()
                    if absolute_symlinks
                    else ""
                )
            ),
            "worktree_relpath": str(repo.relative_to(scratch_root)),
        }
        return row, repo
    except (AdjudicationWorktreeError, worktrees.WorktreeBuildError, OSError) as exc:
        shutil.rmtree(case_root, ignore_errors=True)
        if isinstance(exc, AdjudicationWorktreeError):
            raise
        raise AdjudicationWorktreeError(str(exc)) from exc
    finally:
        worktrees.CASE_DEADLINE.reset(deadline_token)


def remove_case_worktree(scratch_root: Path, case_id: str) -> None:
    shutil.rmtree(scratch_root / case_id, ignore_errors=True)
