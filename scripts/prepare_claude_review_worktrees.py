#!/usr/bin/env python3
"""Build blinded local Git worktrees for the RQ3 Claude Code reviewer.

The builder is intentionally offline. For every selected case it exports the
tracked before and after Git snapshots from the experiment worktrees (falling
back to the bare cache), creates a fresh repository with one neutral baseline
commit, and stages the exact after snapshot as the complete pending change.
Original remotes, commit authorship, PR metadata, CodeQL outputs, and hidden
reference alerts are not copied into the reviewer cwd.
"""

from __future__ import annotations

import argparse
import contextvars
import csv
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.1.0"
CASE_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "rq3_case_deadline",
    default=None,
)
NEUTRAL_NAME = "RQ3 Benchmark"
NEUTRAL_EMAIL = "rq3-benchmark@invalid"
NEUTRAL_DATE = "2000-01-01T00:00:00+00:00"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
KEY_FIELDS = (
    "case_id",
    "group",
    "repo_name",
    "pr_number",
    "base_sha",
    "head_sha",
    "patch_sha256",
    "base_tree_sha",
    "head_tree_sha",
    "pending_diff_sha256",
    "changed_file_n",
    "enrichment_changed_file_n",
    "reconstruction_source",
    "worktree_relpath",
)


class WorktreeBuildError(ValueError):
    """Raised when a blinded reviewer worktree cannot be built safely."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="为 RQ3 Claude Code /code-review 构建离线盲化 Git worktree"
    )
    parser.add_argument("--cases", required=True)
    parser.add_argument("--diffs", required=True)
    parser.add_argument("--ai-jobs", required=True)
    parser.add_argument("--human-jobs", required=True)
    parser.add_argument("--ai-cache-dir", required=True)
    parser.add_argument("--human-cache-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--case-id",
        action="append",
        dest="case_ids",
        help=(
            "首次构建时只构建指定 case；与 --resume-failures 合用时，"
            "精确重建已通过或失败的指定 case；可重复提供"
        ),
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--case-timeout",
        type=float,
        default=900,
        help="每个 case 的累计构建超时秒数，默认 900",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="并行构建 case 数，默认 1",
    )
    parser.add_argument(
        "--resume-failures",
        action="store_true",
        help="复用同一输出目录中已通过的 case，只重试 worktree_failures.csv",
    )
    parser.add_argument(
        "--resume-failure-kind",
        choices=("all", "positive", "control"),
        default="all",
        help="续跑时只处理全部、positive 或 control 失败项，默认 all",
    )
    return parser.parse_args()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def read_csv(
    path: Path,
    label: str,
    *,
    allow_header_only: bool = False,
) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
    except FileNotFoundError:
        raise WorktreeBuildError(f"{label} does not exist: {path}") from None
    except csv.Error as exc:
        raise WorktreeBuildError(f"{label} is invalid CSV: {exc}") from None
    if not rows and not allow_header_only:
        raise WorktreeBuildError(f"{label} must not be empty")
    return rows


def read_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        stream = path.open(encoding="utf-8")
    except FileNotFoundError:
        raise WorktreeBuildError(f"{label} does not exist: {path}") from None
    with stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                raise WorktreeBuildError(
                    f"{label} contains invalid JSON at line {line_number}"
                ) from None
            if not isinstance(row, dict):
                raise WorktreeBuildError(
                    f"{label} line {line_number} must be an object"
                )
            rows.append(row)
    if not rows:
        raise WorktreeBuildError(f"{label} must not be empty")
    return rows


def read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise WorktreeBuildError(f"{label} does not exist: {path}") from None
    except json.JSONDecodeError as exc:
        raise WorktreeBuildError(
            f"{label} is invalid JSON: {path}:{exc.lineno}"
        ) from None
    if not isinstance(value, dict):
        raise WorktreeBuildError(f"{label} must be an object")
    return value


def require_field(row: dict[str, Any], field: str, label: str) -> str:
    value = str(row.get(field, "")).strip()
    if not value:
        raise WorktreeBuildError(f"{label} missing {field}")
    return value


def normalized_pr_key(repo_name: str, pr_number: str) -> tuple[str, str]:
    return repo_name.strip().lower(), pr_number.strip()


def repo_slug(repo_name: str) -> str:
    return repo_name.replace("/", "_")


def offline_git_env() -> dict[str, str]:
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
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            # Experiment source/worktree directories live below the project
            # checkout.  If one was cleaned and no longer contains its own
            # .git metadata, never let Git discover the parent project repo.
            "GIT_CEILING_DIRECTORIES": str(PROJECT_ROOT),
            "GIT_AUTHOR_NAME": NEUTRAL_NAME,
            "GIT_AUTHOR_EMAIL": NEUTRAL_EMAIL,
            "GIT_AUTHOR_DATE": NEUTRAL_DATE,
            "GIT_COMMITTER_NAME": NEUTRAL_NAME,
            "GIT_COMMITTER_EMAIL": NEUTRAL_EMAIL,
            "GIT_COMMITTER_DATE": NEUTRAL_DATE,
        }
    )
    return env


def remaining_case_timeout() -> float | None:
    deadline = CASE_DEADLINE.get()
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise WorktreeBuildError("case build timed out")
    return remaining


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
    check: bool = True,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    env = offline_git_env()
    if extra_env:
        env.update(extra_env)
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
            timeout=remaining_case_timeout(),
        )
    except subprocess.TimeoutExpired:
        raise WorktreeBuildError(
            f"case build timed out while running: {' '.join(command)}"
        ) from None
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise WorktreeBuildError(
            f"command failed ({result.returncode}): {' '.join(command)}: {detail}"
        )
    return result


def build_job_index(
    ai_jobs: list[dict[str, str]],
    human_jobs: list[dict[str, str]],
) -> dict[tuple[str, str, str], dict[str, str]]:
    index: dict[tuple[str, str, str], dict[str, str]] = {}
    for group, rows in (("ai", ai_jobs), ("human", human_jobs)):
        for row in rows:
            revision = str(row.get("revision", "")).strip().lower()
            if revision not in {"before", "after"}:
                continue
            repo_name = require_field(row, "repo_name", f"{group} job")
            pr_number = require_field(row, "pr_number", f"{group} job")
            key = (group, *normalized_pr_key(repo_name, pr_number), revision)
            if key in index:
                raise WorktreeBuildError(f"duplicate revision job: {key}")
            index[key] = row
    return index


def build_diff_index(
    rows: list[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        repo_name = require_field(row, "repo_name", "diff row")
        pr_number = require_field(row, "pr_number", "diff row")
        key = normalized_pr_key(repo_name, pr_number)
        if key in index:
            raise WorktreeBuildError(f"duplicate diff row: {key}")
        patch = str(row.get("diff", ""))
        if not patch.strip() or "diff --git " not in patch:
            raise WorktreeBuildError(f"empty or invalid diff: {key}")
        index[key] = row
    return index


def validate_cases(rows: list[dict[str, str]]) -> None:
    ids = [require_field(row, "case_id", "case") for row in rows]
    duplicate_ids = sorted(key for key, count in Counter(ids).items() if count > 1)
    if duplicate_ids:
        raise WorktreeBuildError(f"duplicate case_id values: {duplicate_ids}")
    for row in rows:
        group = require_field(row, "group", f"case {row.get('case_id', '')}").lower()
        if group not in {"ai", "human"}:
            raise WorktreeBuildError(f"invalid group for {row['case_id']}: {group}")
        require_field(row, "repo_name", f"case {row['case_id']}")
        require_field(row, "pr_number", f"case {row['case_id']}")


def ensure_new_output(path: Path) -> None:
    if path.exists():
        raise WorktreeBuildError(f"output directory already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)


def sanitize_snapshot_symlinks(
    root: Path,
    *,
    expected_absolute: dict[str, str] | None = None,
) -> dict[str, str]:
    """Reject escaping links and neutralize invariant absolute symlinks."""

    resolved_root = root.resolve()
    absolute: dict[str, str] = {}
    for path in root.rglob("*"):
        remaining_case_timeout()
        if not path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        target = os.readlink(path)
        if os.path.isabs(target):
            absolute[relative] = target
            if (
                expected_absolute is not None
                and expected_absolute.get(relative) != target
            ):
                raise WorktreeBuildError(
                    f"absolute symlink differs between revisions: {relative}"
                )
            replacement = (
                ".rq3-blocked-absolute-symlink-"
                + hashlib.sha256(target.encode("utf-8")).hexdigest()[:20]
            )
            path.unlink()
            os.symlink(replacement, path)
            continue
        resolved = (path.parent / target).resolve()
        try:
            resolved.relative_to(resolved_root)
        except ValueError:
            raise WorktreeBuildError(
                f"snapshot contains escaping symlink: {path.relative_to(root)}"
            ) from None
    if expected_absolute is not None and absolute != expected_absolute:
        missing = sorted(set(expected_absolute) - set(absolute))
        added = sorted(set(absolute) - set(expected_absolute))
        raise WorktreeBuildError(
            "absolute symlink inventory differs between revisions: "
            f"missing={missing[:3]}, added={added[:3]}"
        )
    return absolute


def git_object_digest(payload: bytes, object_format: str) -> str:
    try:
        digest = hashlib.new(object_format)
    except ValueError as exc:
        raise WorktreeBuildError(
            f"unsupported Git object format: {object_format}"
        ) from exc
    digest.update(f"blob {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    return digest.hexdigest()


def export_checked_out_index(
    source: Path,
    revision_sha: str,
    destination: Path,
) -> str:
    """Export exact tracked files when a partial clone lacks archived blobs."""

    source_probe = run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=source,
        check=False,
    )
    source_top_level = source_probe.stdout.decode().strip()
    if (
        source_probe.returncode != 0
        or not source_top_level
        or Path(source_top_level).resolve() != source.resolve()
    ):
        raise WorktreeBuildError(
            f"source directory is not a standalone Git worktree root: {source}"
        )
    head = run(["git", "rev-parse", "HEAD"], cwd=source).stdout.decode().strip()
    if head != revision_sha:
        raise WorktreeBuildError(
            f"checked-out source HEAD {head} does not equal requested {revision_sha}"
        )
    object_format = (
        run(["git", "rev-parse", "--show-object-format"], cwd=source)
        .stdout.decode()
        .strip()
    )
    expected_tree = run(["git", "write-tree"], cwd=source).stdout.decode().strip()
    listing = run(["git", "ls-files", "--stage", "-z"], cwd=source).stdout
    destination.mkdir(parents=True, exist_ok=True)
    seen_paths: set[str] = set()
    for raw_entry in listing.split(b"\0"):
        remaining_case_timeout()
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
            raise WorktreeBuildError(
                "checked-out source contains an invalid index entry"
            ) from exc
        if stage != "0":
            raise WorktreeBuildError(
                f"checked-out source contains an unmerged index entry: {relative}"
            )
        if relative in seen_paths:
            raise WorktreeBuildError(
                f"checked-out source contains duplicate index path: {relative}"
            )
        seen_paths.add(relative)
        source_path = source / relative
        target_path = destination / relative
        target_path.parent.mkdir(parents=True, exist_ok=True)
        if mode == "120000":
            if not source_path.is_symlink():
                raise WorktreeBuildError(
                    f"tracked symlink is unavailable in checked-out source: {relative}"
                )
            link_target = os.readlink(source_path)
            payload = os.fsencode(link_target)
            if git_object_digest(payload, object_format) != expected_oid:
                raise WorktreeBuildError(
                    f"tracked symlink differs from Git index: {relative}"
                )
            os.symlink(link_target, target_path)
        elif mode in {"100644", "100755"}:
            if source_path.is_symlink() or not source_path.is_file():
                raise WorktreeBuildError(
                    f"tracked file is unavailable in checked-out source: {relative}"
                )
            payload = source_path.read_bytes()
            if git_object_digest(payload, object_format) != expected_oid:
                raise WorktreeBuildError(
                    f"tracked file differs from Git index: {relative}"
                )
            target_path.write_bytes(payload)
            permissions = (
                stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
            )
            if mode == "100755":
                permissions |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            target_path.chmod(permissions)
        elif mode == "160000":
            raise WorktreeBuildError(
                f"checked-out index fallback does not support gitlink: {relative}"
            )
        else:
            raise WorktreeBuildError(
                f"unsupported tracked-file mode {mode}: {relative}"
            )
    return expected_tree


def export_object_database_index(
    *,
    git_prefix: list[str],
    cwd: Path | None,
    revision_sha: str,
    destination: Path,
) -> tuple[str, dict[str, str]]:
    """Export raw blobs through a temporary index without filters/export-ignore."""

    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rq3-index-") as tmp:
        index_path = Path(tmp) / "index"
        env = {"GIT_INDEX_FILE": str(index_path)}
        run([*git_prefix, "read-tree", revision_sha], cwd=cwd, extra_env=env)
        expected_tree = (
            run([*git_prefix, "write-tree"], cwd=cwd, extra_env=env)
            .stdout.decode()
            .strip()
        )
        listing = run(
            [*git_prefix, "ls-files", "--stage", "-z"],
            cwd=cwd,
            extra_env=env,
        ).stdout
        entries: list[tuple[str, str, str]] = []
        gitlinks: dict[str, str] = {}
        for raw_entry in listing.split(b"\0"):
            if not raw_entry:
                continue
            try:
                metadata, raw_path = raw_entry.split(b"\t", 1)
                raw_mode, raw_oid, raw_stage = metadata.split(b" ", 2)
                mode = raw_mode.decode("ascii")
                oid = raw_oid.decode("ascii")
                stage = raw_stage.decode("ascii")
                relative = raw_path.decode("utf-8", errors="surrogateescape")
            except (ValueError, UnicodeDecodeError) as exc:
                raise WorktreeBuildError(
                    "temporary Git index contains an invalid entry"
                ) from exc
            if stage != "0":
                raise WorktreeBuildError(
                    f"temporary Git index contains an unmerged entry: {relative}"
                )
            if mode == "160000":
                gitlinks[relative] = oid
                continue
            if mode not in {"100644", "100755", "120000"}:
                raise WorktreeBuildError(
                    f"temporary Git index has unsupported mode {mode}: {relative}"
                )
            entries.append((mode, oid, relative))

        process = subprocess.Popen(
            [*git_prefix, "cat-file", "--batch"],
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=offline_git_env(),
        )
        assert process.stdin is not None
        assert process.stdout is not None
        try:
            for mode, expected_oid, relative in entries:
                remaining_case_timeout()
                process.stdin.write(expected_oid.encode("ascii") + b"\n")
                process.stdin.flush()
                header = process.stdout.readline().rstrip(b"\n")
                if header.endswith(b" missing"):
                    raise WorktreeBuildError(
                        f"Git object is missing for tracked path {relative}: "
                        f"{expected_oid}"
                    )
                parts = header.split(b" ")
                if len(parts) != 3:
                    raise WorktreeBuildError(
                        f"invalid git cat-file header for {relative}: "
                        f"{header.decode(errors='replace')}"
                    )
                actual_oid = parts[0].decode("ascii")
                object_type = parts[1].decode("ascii")
                try:
                    size = int(parts[2])
                except ValueError:
                    raise WorktreeBuildError(
                        f"invalid Git blob size for {relative}"
                    ) from None
                if actual_oid != expected_oid or object_type != "blob" or size < 0:
                    raise WorktreeBuildError(
                        f"unexpected Git object for tracked path {relative}"
                    )
                payload = process.stdout.read(size)
                separator = process.stdout.read(1)
                if len(payload) != size or separator != b"\n":
                    raise WorktreeBuildError(
                        f"truncated Git blob for tracked path {relative}"
                    )
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if mode == "120000":
                    os.symlink(os.fsdecode(payload), target)
                else:
                    target.write_bytes(payload)
                    permissions = (
                        stat.S_IRUSR
                        | stat.S_IWUSR
                        | stat.S_IRGRP
                        | stat.S_IROTH
                    )
                    if mode == "100755":
                        permissions |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                    target.chmod(permissions)
            process.stdin.close()
            return_code = process.wait(timeout=remaining_case_timeout())
            if return_code != 0:
                detail = process.stderr.read().decode(
                    "utf-8", errors="replace"
                ).strip()
                raise WorktreeBuildError(
                    f"git cat-file failed ({return_code}): {detail}"
                )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
    return expected_tree, gitlinks


def export_revision(
    job: dict[str, str],
    cache: Path,
    revision_sha: str,
    destination: Path,
) -> tuple[str, str, dict[str, str]]:
    source_raw = str(job.get("source_dir", "")).strip()
    source = Path(source_raw).expanduser() if source_raw else None
    if source is not None and source.is_dir():
        try:
            tree = export_checked_out_index(source, revision_sha, destination)
            return tree, "experiment_source_index", {}
        except WorktreeBuildError:
            clear_snapshot_directory(destination)
        source_root = run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=source,
            check=False,
        )
        if (
            source_root.returncode == 0
            and Path(source_root.stdout.decode().strip()).resolve()
            == source.resolve()
        ):
            try:
                tree, gitlinks = export_object_database_index(
                    git_prefix=["git"],
                    cwd=source,
                    revision_sha=revision_sha,
                    destination=destination,
                )
                return tree, "experiment_source_temporary_index", gitlinks
            except WorktreeBuildError:
                clear_snapshot_directory(destination)
    if not cache.is_dir():
        raise WorktreeBuildError(f"bare repository cache missing: {cache}")
    tree, gitlinks = export_object_database_index(
        git_prefix=["git", f"--git-dir={cache}"],
        cwd=None,
        revision_sha=revision_sha,
        destination=destination,
    )
    return tree, "bare_cache_temporary_index", gitlinks


def apply_gitlinks(repo_dir: Path, gitlinks: dict[str, str]) -> None:
    for relative, oid in sorted(gitlinks.items()):
        run(
            [
                "git",
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{oid},{relative}",
            ],
            cwd=repo_dir,
        )
        # A gitlink whose path is absent from the working tree appears as an
        # unstaged deletion even when the index tree is exact.  An empty,
        # untracked-by-Git directory is sufficient to represent the submodule
        # checkout boundary without copying nested repository contents.
        (repo_dir / relative).mkdir(parents=True, exist_ok=True)


def initialize_neutral_repo(
    repo_dir: Path,
    gitlinks: dict[str, str] | None = None,
) -> str:
    run(["git", "init", "--quiet"], cwd=repo_dir)
    local_git_dir = repo_dir / ".git"
    if not local_git_dir.is_dir():
        raise WorktreeBuildError(
            f"neutral repository initialization escaped case directory: {repo_dir}"
        )
    top_level = (
        run(["git", "rev-parse", "--show-toplevel"], cwd=repo_dir)
        .stdout.decode()
        .strip()
    )
    if Path(top_level).resolve() != repo_dir.resolve():
        raise WorktreeBuildError(
            f"neutral repository resolved outside case directory: {repo_dir}"
        )
    run(["git", "config", "user.name", NEUTRAL_NAME], cwd=repo_dir)
    run(["git", "config", "user.email", NEUTRAL_EMAIL], cwd=repo_dir)
    run(["git", "config", "core.autocrlf", "false"], cwd=repo_dir)
    run(["git", "config", "core.safecrlf", "false"], cwd=repo_dir)
    attributes = repo_dir / ".git/info/attributes"
    attributes.write_text(
        "* -text -eol -filter -ident -working-tree-encoding\n",
        encoding="utf-8",
    )
    run(["git", "add", "--force", "-A"], cwd=repo_dir)
    apply_gitlinks(repo_dir, gitlinks or {})
    run(["git", "commit", "--quiet", "-m", "neutral baseline"], cwd=repo_dir)
    tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=repo_dir)
    return tree.stdout.decode().strip()


def clear_working_tree(repo_dir: Path) -> None:
    for path in repo_dir.iterdir():
        remaining_case_timeout()
        if path.name == ".git":
            continue
        if path.is_symlink() or path.is_file():
            path.unlink()
        else:
            shutil.rmtree(path)


def clear_snapshot_directory(path: Path) -> None:
    if not path.exists():
        return
    for child in path.iterdir():
        remaining_case_timeout()
        # The same destination becomes the sanitized repository after the
        # neutral baseline is committed.  Head-side source fallbacks may need
        # to clear a failed export, but must never remove that local .git.
        if child.name == ".git":
            continue
        if child.is_symlink() or child.is_file():
            child.unlink()
        else:
            shutil.rmtree(child)


def stage_after_and_audit(
    repo_dir: Path,
    expected_head_tree: str | None,
    gitlinks: dict[str, str] | None = None,
) -> tuple[str, int, str]:
    run(["git", "add", "--force", "-A"], cwd=repo_dir)
    apply_gitlinks(repo_dir, gitlinks or {})
    staged_tree = run(["git", "write-tree"], cwd=repo_dir).stdout.decode().strip()
    if expected_head_tree is not None and staged_tree != expected_head_tree:
        raise WorktreeBuildError(
            "reconstructed after snapshot does not match the original Git tree"
        )
    remotes = run(["git", "remote"], cwd=repo_dir).stdout.decode().strip()
    if remotes:
        raise WorktreeBuildError(f"sanitized repo unexpectedly has remotes: {remotes}")
    commit_count = run(
        ["git", "rev-list", "--count", "HEAD"], cwd=repo_dir
    ).stdout.decode().strip()
    if commit_count != "1":
        raise WorktreeBuildError(
            f"sanitized repo must contain one commit, found {commit_count}"
        )
    author = run(
        ["git", "log", "-1", "--format=%an <%ae>"], cwd=repo_dir
    ).stdout.decode().strip()
    if author != f"{NEUTRAL_NAME} <{NEUTRAL_EMAIL}>":
        raise WorktreeBuildError(f"non-neutral base author: {author}")
    status = run(["git", "status", "--porcelain=v1"], cwd=repo_dir).stdout
    if not status.strip():
        raise WorktreeBuildError("PR patch produced no pending changes")
    if any(line.startswith(b"?? ") for line in status.splitlines()):
        raise WorktreeBuildError("PR patch produced unaudited untracked files")
    pending_diff = run(
        ["git", "diff", "HEAD", "--binary", "--no-ext-diff", "--no-color"],
        cwd=repo_dir,
    ).stdout
    if not pending_diff.strip():
        raise WorktreeBuildError("pending Git diff is empty after patch application")
    names = run(
        ["git", "diff", "HEAD", "--name-only", "--no-ext-diff"], cwd=repo_dir
    ).stdout.decode().splitlines()
    return (
        sha256_bytes(pending_diff),
        len([name for name in names if name.strip()]),
        staged_tree,
    )


def source_head_revision(job: dict[str, str]) -> str:
    """Recover an omitted job revision from its preserved source worktree."""
    raw_source = str(job.get("source_dir", "")).strip()
    if not raw_source:
        return ""
    source = Path(raw_source)
    if not source.is_absolute():
        source = PROJECT_ROOT / source
    source = source.resolve()
    if not source.is_dir():
        return ""
    try:
        revision = (
            run(
                ["git", "rev-parse", "--verify", "HEAD^{commit}"],
                cwd=source,
            )
            .stdout.decode("ascii")
            .strip()
        )
    except WorktreeBuildError:
        return ""
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise WorktreeBuildError(
            f"source worktree returned an invalid HEAD revision: {source}"
        )
    return revision


def is_full_object_id(value: str) -> bool:
    return len(value) == 40 and not any(
        character not in "0123456789abcdef" for character in value
    )


def build_one(
    case: dict[str, str],
    *,
    job_index: dict[tuple[str, str, str], dict[str, str]],
    diff_index: dict[tuple[str, str], dict[str, Any]],
    cache_dirs: dict[str, Path],
    worktrees_dir: Path,
) -> dict[str, str | int]:
    case_id = case["case_id"].strip()
    group = case["group"].strip().lower()
    repo_name = case["repo_name"].strip()
    pr_number = case["pr_number"].strip()
    pr_key = normalized_pr_key(repo_name, pr_number)
    before_job = job_index.get((group, *pr_key, "before"))
    after_job = job_index.get((group, *pr_key, "after"))
    if before_job is None or after_job is None:
        raise WorktreeBuildError(
            f"{case_id}: missing {group} before/after job for {repo_name}#{pr_number}"
        )
    source = diff_index.get(pr_key)
    if source is None:
        raise WorktreeBuildError(
            f"{case_id}: missing complete diff for {repo_name}#{pr_number}"
        )
    base_sha = (
        str(before_job.get("checkout_ref", "")).strip()
        or str(before_job.get("base_sha", "")).strip()
    )
    head_sha = (
        str(after_job.get("checkout_ref", "")).strip()
        or str(after_job.get("head_sha", "")).strip()
    )
    base_revision_source = "job_metadata"
    head_revision_source = "job_metadata"
    if not is_full_object_id(base_sha):
        recovered_base_sha = source_head_revision(before_job)
        if recovered_base_sha:
            base_sha = recovered_base_sha
            base_revision_source = "experiment_source_head"
    if not is_full_object_id(head_sha):
        recovered_head_sha = source_head_revision(after_job)
        if recovered_head_sha:
            head_sha = recovered_head_sha
            head_revision_source = "experiment_source_head"
    if not base_sha:
        raise WorktreeBuildError(f"before job for {case_id} missing checkout_ref/base_sha")
    if not head_sha:
        raise WorktreeBuildError(f"after job for {case_id} missing checkout_ref/head_sha")
    patch = str(source["diff"]).encode("utf-8")
    cache = cache_dirs[group] / f"{repo_slug(repo_name)}.git"
    repo_dir = worktrees_dir / case_id / "repo"
    original_base_tree, before_source, base_gitlinks = export_revision(
        before_job, cache, base_sha, repo_dir
    )
    absolute_symlinks = sanitize_snapshot_symlinks(repo_dir)
    neutral_tree = initialize_neutral_repo(repo_dir, base_gitlinks)
    if not absolute_symlinks and neutral_tree != original_base_tree:
        raise WorktreeBuildError(
            f"{case_id}: reconstructed before snapshot does not match Git tree"
        )
    clear_working_tree(repo_dir)
    original_head_tree, after_source, head_gitlinks = export_revision(
        after_job, cache, head_sha, repo_dir
    )
    sanitize_snapshot_symlinks(
        repo_dir,
        expected_absolute=absolute_symlinks,
    )
    pending_hash, changed_file_n, sanitized_head_tree = stage_after_and_audit(
        repo_dir,
        None if absolute_symlinks else original_head_tree,
        head_gitlinks,
    )
    expected_changed = int(require_field(source, "changed_file_n", f"diff for {case_id}"))
    return {
        "case_id": case_id,
        "group": group,
        "repo_name": repo_name,
        "pr_number": pr_number,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "patch_sha256": sha256_bytes(patch),
        "base_tree_sha": neutral_tree,
        "head_tree_sha": sanitized_head_tree,
        "pending_diff_sha256": pending_hash,
        "changed_file_n": changed_file_n,
        "enrichment_changed_file_n": expected_changed,
        "reconstruction_source": (
            f"before={before_source};after={after_source};"
            f"base_revision={base_revision_source};"
            f"head_revision={head_revision_source}"
            + (
                ";invariant_absolute_symlinks_neutralized="
                + json.dumps(
                    {
                        "paths": sorted(absolute_symlinks),
                        "target_hashes": {
                            path: sha256_bytes(target.encode("utf-8"))
                            for path, target in sorted(absolute_symlinks.items())
                        },
                        "original_base_tree": original_base_tree,
                        "original_head_tree": original_head_tree,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if absolute_symlinks
                else ""
            )
        ),
        "worktree_relpath": str(repo_dir.relative_to(worktrees_dir.parent)),
    }


def write_key(path: Path, rows: list[dict[str, Any]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=KEY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def write_failures(path: Path, rows: list[dict[str, str]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("case_id", "reason"))
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def prepare_worktrees(
    cases_path: Path,
    diffs_path: Path,
    ai_jobs_path: Path,
    human_jobs_path: Path,
    ai_cache_dir: Path,
    human_cache_dir: Path,
    output_dir: Path,
    limit: int | None = None,
    case_timeout_seconds: float = 900,
    case_ids: list[str] | None = None,
    workers: int = 1,
    resume_failures: bool = False,
    resume_failure_kind: str = "all",
) -> dict[str, Any]:
    if resume_failures:
        if not output_dir.is_dir():
            raise WorktreeBuildError(
                f"resume output directory does not exist: {output_dir}"
            )
        if limit is not None:
            raise WorktreeBuildError(
                "--resume-failures cannot be combined with limit"
            )
    else:
        ensure_new_output(output_dir)
    cases = read_csv(cases_path, "cases")
    validate_cases(cases)
    requested_case_ids: list[str] | None = None
    if case_ids:
        requested_ids = [value.strip() for value in case_ids if value.strip()]
        if len(requested_ids) != len(case_ids) or len(set(requested_ids)) != len(
            requested_ids
        ):
            raise WorktreeBuildError(
                "case-id values must be non-empty and unique"
            )
        available = {row["case_id"] for row in cases}
        missing = sorted(set(requested_ids) - available)
        if missing:
            raise WorktreeBuildError(f"unknown case-id values: {missing}")
        requested_case_ids = requested_ids
        if not resume_failures:
            selected = set(requested_ids)
            cases = [row for row in cases if row["case_id"] in selected]
    if limit is not None:
        if limit < 1:
            raise WorktreeBuildError("limit must be >= 1")
        cases = cases[:limit]
    if not (case_timeout_seconds > 0):
        raise WorktreeBuildError("case-timeout must be > 0")
    if workers < 1:
        raise WorktreeBuildError("workers must be >= 1")
    if resume_failure_kind not in {"all", "positive", "control"}:
        raise WorktreeBuildError("resume-failure-kind is invalid")
    if not resume_failures and resume_failure_kind != "all":
        raise WorktreeBuildError(
            "resume-failure-kind requires --resume-failures"
        )
    diffs = read_jsonl(diffs_path, "diffs")
    jobs = build_job_index(
        read_csv(ai_jobs_path, "AI jobs"),
        read_csv(human_jobs_path, "Human jobs"),
    )
    diff_index = build_diff_index(diffs)
    worktrees_dir = output_dir / "worktrees"
    worktrees_dir.mkdir(parents=True, exist_ok=resume_failures)
    key_path = output_dir / "worktree_key.csv"
    failure_path = output_dir / "worktree_failures.csv"
    previous_manifest: dict[str, Any] | None = None
    if resume_failures:
        previous_manifest = read_json_object(
            output_dir / "manifest.json",
            "existing worktree manifest",
        )
        expected_input_hashes = {
            "cases": sha256_file(cases_path),
            "diffs": sha256_file(diffs_path),
            "ai_jobs": sha256_file(ai_jobs_path),
            "human_jobs": sha256_file(human_jobs_path),
        }
        for name, expected_hash in expected_input_hashes.items():
            actual_hash = (
                previous_manifest.get("inputs", {})
                .get(name, {})
                .get("sha256")
            )
            if actual_hash != expected_hash:
                raise WorktreeBuildError(
                    f"resume input hash mismatch for {name}"
                )
        if previous_manifest.get("requested_case_n") != len(cases):
            raise WorktreeBuildError("resume requested_case_n mismatch")
        key_rows_existing = read_csv(
            key_path,
            "existing worktree key",
            allow_header_only=True,
        )
        failure_rows_existing = read_csv(
            failure_path,
            "existing worktree failures",
            allow_header_only=True,
        )
        case_ids_expected = {case["case_id"] for case in cases}
        key_ids = {row.get("case_id", "") for row in key_rows_existing}
        failure_ids = {row.get("case_id", "") for row in failure_rows_existing}
        if (
            not key_ids.isdisjoint(failure_ids)
            or key_ids | failure_ids != case_ids_expected
            or len(key_ids) != len(key_rows_existing)
            or len(failure_ids) != len(failure_rows_existing)
        ):
            raise WorktreeBuildError(
                "existing key/failure inventory does not partition requested cases"
            )
        for case_id in key_ids:
            if not (worktrees_dir / case_id / "repo").is_dir():
                raise WorktreeBuildError(
                    f"existing built worktree is missing: {case_id}"
                )
        key_by_case = {
            row["case_id"]: row for row in key_rows_existing
        }
        failure_by_case = {
            row["case_id"]: row for row in failure_rows_existing
        }
        if requested_case_ids is not None:
            selected_resume_ids = set(requested_case_ids)
            cases_to_process = [
                case for case in cases if case["case_id"] in selected_resume_ids
            ]
        else:
            cases_to_process = [
                case
                for case in cases
                if case["case_id"] in failure_ids
                and (
                    resume_failure_kind == "all"
                    or case.get("case_control", "").strip() == resume_failure_kind
                )
            ]
    else:
        key_by_case = {}
        failure_by_case = {}
        cases_to_process = cases

    def process_case(
        case: dict[str, str],
    ) -> tuple[str, dict[str, Any] | None, dict[str, str] | None]:
        case_id = case.get("case_id", "")
        # A SIGINT or machine restart can leave a half-built neutral repository
        # (including .git/index.lock).  Only failed/selected cases reach this
        # function during resume, so remove their private scratch directory
        # before rebuilding from immutable inputs.
        shutil.rmtree(worktrees_dir / case_id, ignore_errors=True)
        deadline_token = CASE_DEADLINE.set(
            time.monotonic() + case_timeout_seconds
        )
        try:
            row = build_one(
                case,
                job_index=jobs,
                diff_index=diff_index,
                cache_dirs={"ai": ai_cache_dir, "human": human_cache_dir},
                worktrees_dir=worktrees_dir,
            )
            return case_id, row, None
        except WorktreeBuildError as exc:
            shutil.rmtree(worktrees_dir / case_id, ignore_errors=True)
            return (
                case_id,
                None,
                {"case_id": case_id, "reason": str(exc)},
            )
        finally:
            CASE_DEADLINE.reset(deadline_token)

    try:
        completed = 0
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(process_case, case): case["case_id"]
                for case in cases_to_process
            }
            for future in as_completed(futures):
                case_id, key_row, failure = future.result()
                if key_row is not None:
                    key_by_case[case_id] = key_row
                    failure_by_case.pop(case_id, None)
                    status = "built"
                else:
                    if failure is None:
                        raise AssertionError("case result lacks key and failure")
                    failure_by_case[case_id] = failure
                    status = "failed"
                completed += 1
                ordered_keys = [
                    key_by_case[case["case_id"]]
                    for case in cases
                    if case["case_id"] in key_by_case
                ]
                ordered_failures = [
                    failure_by_case[case["case_id"]]
                    for case in cases
                    if case["case_id"] in failure_by_case
                ]
                write_key(key_path, ordered_keys)
                write_failures(failure_path, ordered_failures)
                print(
                    f"[{completed}/{len(cases_to_process)}] {case_id}: {status}",
                    flush=True,
                )
        key_rows = [
            key_by_case[case["case_id"]]
            for case in cases
            if case["case_id"] in key_by_case
        ]
        failures = [
            failure_by_case[case["case_id"]]
            for case in cases
            if case["case_id"] in failure_by_case
        ]
        write_key(key_path, key_rows)
        write_failures(failure_path, failures)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "status": "passed" if not failures else "incomplete",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "resumed_from_manifest_sha256": (
                previous_manifest.get("manifest_sha256")
                if previous_manifest is not None
                else None
            ),
            "resume_attempt_n": (
                int(previous_manifest.get("resume_attempt_n", 0)) + 1
                if previous_manifest is not None
                else 0
            ),
            "resume_failure_kind": (
                resume_failure_kind if previous_manifest is not None else None
            ),
            "review_surface": "Claude Agent SDK local /code-review",
            "network_used": False,
            "requested_case_n": len(cases),
            "requested_case_ids": (
                [row["case_id"] for row in cases]
                if case_ids and not resume_failures
                else (
                    previous_manifest.get("requested_case_ids")
                    if previous_manifest is not None
                    else None
                )
            ),
            "resume_case_ids": (
                requested_case_ids if previous_manifest is not None else None
            ),
            "built_case_n": len(key_rows),
            "failed_case_n": len(failures),
            "case_timeout_seconds": case_timeout_seconds,
            "workers": workers,
            "inputs": {
                "cases": {
                    "path": str(cases_path),
                    "sha256": sha256_file(cases_path),
                },
                "diffs": {
                    "path": str(diffs_path),
                    "sha256": sha256_file(diffs_path),
                },
                "ai_jobs": {
                    "path": str(ai_jobs_path),
                    "sha256": sha256_file(ai_jobs_path),
                },
                "human_jobs": {
                    "path": str(human_jobs_path),
                    "sha256": sha256_file(human_jobs_path),
                },
            },
            "outputs": {
                "worktree_key": {
                    "path": "worktree_key.csv",
                    "sha256": sha256_file(key_path),
                },
                "worktree_failures": {
                    "path": "worktree_failures.csv",
                    "sha256": sha256_file(failure_path),
                },
            },
            "blinding": {
                "remote_urls_removed": True,
                "original_git_history_removed": True,
                "neutral_single_base_commit": True,
                "codeql_references_outside_reviewer_cwd": True,
            },
            "reconstruction": {
                "method": (
                    "exact tracked before/after Git snapshots with deterministic "
                    "neutralization of invariant absolute symlinks"
                ),
                "github_patch_used_as_provenance_only": True,
                "base_and_head_tree_hashes_verified": True,
                "escaping_symlinks_rejected": True,
                "changed_absolute_symlinks_rejected": True,
                "invariant_absolute_symlink_case_n": sum(
                    "invariant_absolute_symlinks_neutralized="
                    in str(row.get("reconstruction_source", ""))
                    for row in key_rows
                ),
            },
        }
        manifest["manifest_sha256"] = sha256_bytes(canonical_bytes(manifest))
        (output_dir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        return manifest
    except Exception:
        if not resume_failures:
            shutil.rmtree(output_dir, ignore_errors=True)
        raise


def main() -> None:
    args = parse_args()
    manifest = prepare_worktrees(
        Path(args.cases),
        Path(args.diffs),
        Path(args.ai_jobs),
        Path(args.human_jobs),
        Path(args.ai_cache_dir),
        Path(args.human_cache_dir),
        Path(args.output_dir),
        args.limit,
        args.case_timeout,
        args.case_ids,
        args.workers,
        args.resume_failures,
        args.resume_failure_kind,
    )
    print(
        "Claude review worktree 构建完成："
        f"成功 {manifest['built_case_n']}，失败 {manifest['failed_case_n']}，"
        f"状态 {manifest['status']}"
    )


if __name__ == "__main__":
    main()
