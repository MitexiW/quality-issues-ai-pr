#!/usr/bin/env python3
# CodeQL pipeline entry point.
"""Resolve PR revisions and prepare authenticated Git worktrees safely."""

from __future__ import annotations

import argparse
import csv
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse, urlunparse

import requests

from utils import clean_text, setup_logging


PROXY_CREDENTIALS_RE = re.compile(
    r"([a-z][a-z0-9+.-]*://)[^/@\s]+@",
    re.IGNORECASE,
)

# Git/libcurl normally negotiates HTTP/2 with GitHub. Long pack transfers over
# SOCKS proxies can then fail with HTTP/2 stream resets. Keep these settings
# local to this script instead of changing the user's global Git configuration.
GIT_TRANSPORT_ARGS = [
    "-c",
    "http.version=HTTP/1.1",
    "-c",
    "http.maxRequests=1",
]


class GitHubBearerAuth(requests.auth.AuthBase):
    """Attach GitHub authentication without exposing the token in argv or logs."""

    def __init__(self, token: str) -> None:
        self.token = token

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if self.token:
            request.headers["Authorization"] = f"Bearer {self.token}"
        return request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="安全认证 GitHub，解析 PR SHA，并准备 before/after 源码目录"
    )
    parser.add_argument("--jobs", default="data/metadata/codeql_jobs.csv")
    parser.add_argument(
        "--token-env",
        default="GH_TOKEN",
        help="GitHub token 环境变量名；未设置时回退 GITHUB_TOKEN",
    )
    parser.add_argument(
        "--require-token",
        action="store_true",
        help="未找到 token 时直接失败，适合私有仓库",
    )
    parser.add_argument(
        "--cache-dir",
        default="data/repos/.cache",
        help="每个仓库共用的 bare clone 缓存",
    )
    parser.add_argument("--limit", type=int, default=None, help="最多处理多少个 PR")
    parser.add_argument(
        "--repo",
        action="append",
        default=[],
        help="只处理指定仓库；可重复传入，例如 --repo owner/name",
    )
    parser.add_argument(
        "--pr-number",
        action="append",
        default=[],
        help="只处理指定 PR 编号；可重复传入",
    )
    parser.add_argument(
        "--status",
        action="append",
        default=[],
        help="只处理包含指定作业状态的 PR；可重复传入，例如 --status ready --status needs_ref",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true", help="重建已存在的 worktree")
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="并行准备的仓库数;按仓库分组,不同仓库并行,同仓库内串行(共享 bare mirror)",
    )
    parser.add_argument("--retries", type=int, default=4)
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def get_token(env_name: str) -> str:
    return os.environ.get(env_name, "") or os.environ.get("GITHUB_TOKEN", "")


def safe_repo_url(value: str, repo_name: str) -> str:
    raw = value.strip() or f"https://github.com/{repo_name}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or parsed.hostname != "github.com":
        raise ValueError(f"仅支持 github.com HTTPS 仓库地址: {raw}")
    host = parsed.hostname
    if parsed.port:
        host = f"{host}:{parsed.port}"
    clean = urlunparse(("https", host, parsed.path.removesuffix(".git") + ".git", "", "", ""))
    return clean


def safe_slug(value: str) -> str:
    return "".join(char if char.isalnum() or char in "-_." else "_" for char in value)


@contextmanager
def git_auth_environment(token: str) -> Iterator[dict[str, str]]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "Never",
        }
    )
    if not token:
        yield env
        return

    with tempfile.TemporaryDirectory(prefix="aipr-git-auth-") as directory:
        askpass = Path(directory) / "askpass.sh"
        askpass.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            '  *Username*) printf "%s\\n" "x-access-token" ;;\n'
            '  *) printf "%s\\n" "$AIPR_GITHUB_TOKEN" ;;\n'
            "esac\n",
            encoding="utf-8",
        )
        askpass.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        env["GIT_ASKPASS"] = str(askpass)
        env["AIPR_GITHUB_TOKEN"] = token
        yield env


def run_git(
    args: list[str],
    env: dict[str, str],
    dry_run: bool = False,
    retries: int = 1,
) -> None:
    command = ["git", *GIT_TRANSPORT_ARGS, *args]
    logging.debug("执行: %s", " ".join(command))
    if dry_run:
        return
    for attempt in range(1, retries + 1):
        result = subprocess.run(
            command,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            return
        removed_files, removed_bytes = cleanup_incomplete_pack_files(args)
        if removed_files:
            logging.warning(
                "已清理 Git 中断下载临时 pack: files=%d size=%.2f GiB",
                removed_files,
                removed_bytes / (1024**3),
            )
        error = clean_text(result.stderr) or clean_text(result.stdout)
        if attempt == retries:
            raise RuntimeError(
                f"git {' '.join(args)} 失败（退出码 {result.returncode}）: {error}"
            )
        delay = min(2 ** (attempt - 1), 8)
        logging.warning(
            "Git 命令失败，第 %d/%d 次，%d 秒后重试: %s",
            attempt,
            retries,
            delay,
            error[-500:],
        )
        time.sleep(delay)


def cleanup_incomplete_pack_files(args: list[str]) -> tuple[int, int]:
    """Remove invalid fetch-pack temporary files left by an interrupted Git command."""
    try:
        marker = args.index("--git-dir")
        mirror = Path(args[marker + 1])
    except (ValueError, IndexError):
        return 0, 0
    pack_dir = mirror / "objects" / "pack"
    if not pack_dir.is_dir():
        return 0, 0
    removed_files = 0
    removed_bytes = 0
    for path in pack_dir.glob("tmp_pack_*"):
        if not path.is_file():
            continue
        try:
            removed_bytes += path.stat().st_size
            path.unlink()
            removed_files += 1
        except FileNotFoundError:
            continue
    return removed_files, removed_bytes


def safe_request_error(error: BaseException, token: str) -> str:
    """Return a bounded network error without credentials or GitHub tokens."""
    text = clean_text(str(error))
    if token:
        text = text.replace(token, "<redacted>")
    text = PROXY_CREDENTIALS_RE.sub(r"\1<redacted>@", text)
    return text[-500:]


def github_pr(
    repo_name: str,
    pr_number: str,
    token: str,
    retries: int,
) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "aipr-codeql",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    # A non-empty AuthBase also prevents ~/.netrc credentials from replacing
    # the explicit Bearer header. Each worker gets its own Session, while
    # trust_env remains enabled so HTTP(S), SOCKS5 and SOCKS5H proxies work.
    with requests.Session() as session:
        session.auth = GitHubBearerAuth(token)
        for attempt in range(1, retries + 1):
            try:
                response = session.get(
                    url,
                    headers=headers,
                    timeout=(30, 30),
                )
            except requests.exceptions.InvalidSchema as exc:
                message = safe_request_error(exc, token)
                if "socks" in message.lower():
                    raise RuntimeError(
                        "检测到 SOCKS 代理，但 Python 环境缺少 SOCKS 支持；"
                        "请运行 uv pip install --python .venv/bin/python "
                        "-r requirements.txt"
                    ) from None
                raise RuntimeError(f"GitHub API 代理配置无效: {message}") from None
            except requests.exceptions.RequestException as exc:
                error: BaseException = exc
            else:
                try:
                    status = response.status_code
                    if status in {401, 403}:
                        raise RuntimeError(
                            f"GitHub API 认证或限流失败（HTTP {status}）。"
                            "请检查 token 是否有效及其仓库权限。"
                        )
                    if status == 404:
                        raise RuntimeError(
                            f"找不到 {repo_name} PR #{pr_number}；"
                            "仓库或 PR 可能已不可访问。"
                        )
                    if status == 429 or status >= 500:
                        reason = clean_text(response.reason)
                        error = RuntimeError(
                            f"HTTP {status}" + (f" {reason}" if reason else "")
                        )
                    else:
                        response.raise_for_status()
                        try:
                            payload = response.json()
                        except ValueError as exc:
                            error = exc
                        else:
                            if isinstance(payload, dict):
                                return payload
                            error = ValueError("GitHub API 返回的 JSON 不是对象")
                finally:
                    response.close()

            safe_error = safe_request_error(error, token)
            if attempt == retries:
                raise RuntimeError(
                    f"GitHub API 请求失败，重试 {retries} 次: {safe_error}"
                ) from None
            delay = min(2 ** (attempt - 1), 8)
            logging.warning(
                "GitHub API 请求失败，第 %d/%d 次，%d 秒后重试: %s",
                attempt,
                retries,
                delay,
                safe_error,
            )
            time.sleep(delay)
    raise AssertionError("unreachable")


def ensure_mirror(
    mirror: Path,
    repo_url: str,
    env: dict[str, str],
    dry_run: bool,
    retries: int,
) -> None:
    if mirror.exists():
        try:
            run_git(
                ["--git-dir", str(mirror), "rev-parse", "--is-bare-repository"],
                env,
                dry_run,
            )
        except RuntimeError:
            if not dry_run:
                shutil.rmtree(mirror)
        else:
            run_git(
                ["--git-dir", str(mirror), "remote", "set-url", "origin", repo_url],
                env,
                dry_run,
            )
            return
    mirror.parent.mkdir(parents=True, exist_ok=True)
    run_git(
        ["clone", "--bare", "--filter=blob:none", repo_url, str(mirror)],
        env,
        dry_run,
        retries,
    )


def prepare_worktree(
    mirror: Path,
    source_dir: Path,
    sha: str,
    env: dict[str, str],
    *,
    force: bool,
    dry_run: bool,
    retries: int,
) -> None:
    if source_dir.exists():
        if not force:
            logging.info("源码目录已存在，跳过: %s", source_dir)
            return
        if not dry_run:
            shutil.rmtree(source_dir)
    source_dir.parent.mkdir(parents=True, exist_ok=True)
    run_git(
        ["--git-dir", str(mirror), "fetch", "--no-tags", "origin", sha],
        env,
        dry_run,
        retries,
    )
    for attempt in range(1, retries + 1):
        try:
            run_git(
                ["--git-dir", str(mirror), "worktree", "prune"],
                env,
                dry_run,
            )
            run_git(
                [
                    "--git-dir",
                    str(mirror),
                    "worktree",
                    "add",
                    "--detach",
                    str(source_dir),
                    sha,
                ],
                env,
                dry_run,
            )
            return
        except RuntimeError:
            if not dry_run and source_dir.exists():
                shutil.rmtree(source_dir)
            if attempt == retries:
                raise
            time.sleep(min(2 ** (attempt - 1), 8))


def read_jobs(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def write_jobs(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temp.replace(path)


def retry_excluded(job: dict[str, str]) -> bool:
    return clean_text(job.get("retry_excluded")).lower() in {
        "1",
        "true",
        "yes",
        "y",
    }


def prepare_pr(
    repo_name: str,
    pr_number: str,
    group: list[dict[str, str]],
    *,
    token: str,
    cache_dir: Path,
    git_env: dict[str, str],
    args: argparse.Namespace,
) -> bool:
    """Prepare a single PR (before/after worktrees). Returns True on failure."""
    try:
        metadata = github_pr(repo_name, pr_number, token, args.retries)
        refs = {
            "before": clean_text(metadata.get("base", {}).get("sha")),
            "after": clean_text(metadata.get("head", {}).get("sha")),
        }
        repo_url = safe_repo_url(group[0].get("repo_url", ""), repo_name)
        mirror = cache_dir / f"{safe_slug(repo_name)}.git"
        ensure_mirror(mirror, repo_url, git_env, args.dry_run, args.retries)
        for job in group:
            job["base_sha"] = refs["before"]
            job["head_sha"] = refs["after"]
            revision = job["revision"]
            sha = refs.get(revision, "")
            if not sha:
                job["status"] = "needs_ref"
                job["comparison_status"] = "failed"
                continue
            job["checkout_ref"] = sha
            prepare_worktree(
                mirror,
                Path(job["source_dir"]),
                sha,
                git_env,
                force=args.force,
                dry_run=args.dry_run,
                retries=args.retries,
            )
            job["status"] = "prepared" if not args.dry_run else "dry_run"
            job["comparison_status"] = "prepared" if not args.dry_run else "pending"
        logging.info("已准备 %s PR #%s", repo_name, pr_number)
        return False
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as exc:
        for job in group:
            job["status"] = "prepare_failed"
            job["comparison_status"] = "failed"
        logging.error("准备 %s PR #%s 失败: %s", repo_name, pr_number, exc)
        return True


def prepare_repo(
    repo_name: str,
    pr_groups: list[tuple[str, list[dict[str, str]]]],
    *,
    token: str,
    cache_dir: Path,
    git_env: dict[str, str],
    args: argparse.Namespace,
) -> int:
    """Prepare all selected PRs of one repo sequentially (shared bare mirror).

    Returns the number of failed PRs for this repo.
    """
    failures = 0
    for pr_number, group in pr_groups:
        failures += int(
            prepare_pr(
                repo_name,
                pr_number,
                group,
                token=token,
                cache_dir=cache_dir,
                git_env=git_env,
                args=args,
            )
        )
    return failures


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)
    if args.workers < 1:
        raise SystemExit("--workers 必须大于等于 1")
    token = get_token(args.token_env)
    if args.require_token and not token:
        raise SystemExit(
            f"未设置 {args.token_env} 或 GITHUB_TOKEN；请通过环境变量提供 token"
        )
    logging.info(
        "GitHub 认证模式: %s",
        f"环境变量 {args.token_env}/GITHUB_TOKEN" if token else "匿名公共仓库",
    )

    jobs_path = Path(args.jobs)
    fields, jobs = read_jobs(jobs_path)
    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for job in jobs:
        groups[(job["repo_name"], job["pr_number"])].append(job)

    cache_dir = Path(args.cache_dir)
    allowed_statuses = set(args.status)
    allowed_repos = set(args.repo)
    allowed_pr_numbers = set(args.pr_number)

    # Select eligible PRs (respecting --limit on total PR count), then group by
    # repository so different repos can be prepared in parallel while PRs of the
    # same repo stay serial (they share one bare mirror).
    selected_by_repo: dict[str, list[tuple[str, list[dict[str, str]]]]] = defaultdict(list)
    processed = 0
    for (repo_name, pr_number), group in groups.items():
        if any(retry_excluded(job) for job in group):
            continue
        if allowed_repos and repo_name not in allowed_repos:
            continue
        if allowed_pr_numbers and pr_number not in allowed_pr_numbers:
            continue
        if allowed_statuses and not any(
            job.get("status", "") in allowed_statuses for job in group
        ):
            continue
        if args.limit is not None and processed >= args.limit:
            break
        processed += 1
        selected_by_repo[repo_name].append((pr_number, group))

    failed = 0
    with git_auth_environment(token) as git_env:
        if args.workers == 1:
            for repo_name, pr_groups in selected_by_repo.items():
                failed += prepare_repo(
                    repo_name,
                    pr_groups,
                    token=token,
                    cache_dir=cache_dir,
                    git_env=git_env,
                    args=args,
                )
        else:
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {
                    executor.submit(
                        prepare_repo,
                        repo_name,
                        pr_groups,
                        token=token,
                        cache_dir=cache_dir,
                        git_env=git_env,
                        args=args,
                    ): repo_name
                    for repo_name, pr_groups in selected_by_repo.items()
                }
                for future in as_completed(futures):
                    failed += future.result()

    if not args.dry_run:
        write_jobs(jobs_path, fields, jobs)
    logging.info("处理 PR %d 个，失败 %d 个", processed, failed)
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
