#!/usr/bin/env python3
# CodeQL pipeline entry point.
"""Collect one reproducible GitHub PR/file metadata source for AI and Human PRs."""

from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import json
import logging
import os
import random
import re
import tempfile
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from threading import Lock
from typing import Any, Iterable

import pyarrow.parquet as pq
import requests

from utils import clean_text, setup_logging


SCHEMA_VERSION = "1.0.0"
GITHUB_API_VERSION = "2022-11-28"
USER_AGENT = "aipr-codeql-pr-enrichment"
TRANSIENT_STATUS = {429, 500, 502, 503, 504}
PR_FIELDS = [
    "group",
    "repo_name",
    "pr_number",
    "pr_id",
    "source_language",
    "task_type",
    "api_state",
    "merged",
    "merged_at",
    "created_at",
    "closed_at",
    "base_sha",
    "head_sha",
    "additions",
    "deletions",
    "changed_lines",
    "changed_kloc",
    "changed_files",
    "file_list_returned",
    "file_list_complete",
    "commit_count",
    "production_files",
    "test_files",
    "docs_files",
    "example_files",
    "generated_files",
    "vendor_files",
    "build_files",
    "binary_files",
    "no_patch_files",
    "actual_languages",
    "cache_key",
    "cache_sha256",
    "source",
    "fetched_at",
]
FILE_FIELDS = [
    "group",
    "repo_name",
    "pr_number",
    "pr_id",
    "filename",
    "previous_filename",
    "status",
    "additions",
    "deletions",
    "changes",
    "extension",
    "actual_language",
    "path_class",
    "is_binary",
    "patch_available",
    "source",
]
FAILURE_FIELDS = [
    "group",
    "repo_name",
    "pr_number",
    "pr_id",
    "category",
    "retryable",
    "attempts",
    "message",
]


class CollectionError(RuntimeError):
    def __init__(
        self,
        category: str,
        message: str,
        *,
        retryable: bool,
        attempts: int = 0,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.retryable = retryable
        self.attempts = attempts


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token: str) -> None:
        self.token = token

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if self.token:
            request.headers["Authorization"] = f"Bearer {self.token}"
        return request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="统一补齐 study_stars500 AI/Human PR 规模与文件分类"
    )
    parser.add_argument(
        "--study-root",
        default="data/experiments/security-and-quality/study_stars500",
    )
    parser.add_argument(
        "--group",
        action="append",
        choices=["ai", "human"],
        dest="groups",
        help="要处理的组；默认同时处理 ai 和 human",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="默认 <study-root>/reports/pr_enrichment",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="默认 <study-root>/metadata/pr_enrichment_cache",
    )
    parser.add_argument(
        "--rules",
        default="config/study/pr_enrichment_rules.json",
    )
    parser.add_argument(
        "--aidev-commit-details",
        default="data/aidev_parquet/pr_commit_details/train/0000.parquet",
        help="仅用于 AI 交叉验证；文件不存在时跳过",
    )
    parser.add_argument("--token-env", default="GH_TOKEN")
    parser.add_argument("--require-token", action="store_true")
    parser.add_argument(
        "--prompt-token",
        action="store_true",
        help="环境变量没有 token 时安全交互读取；不回显、不持久化",
    )
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--retries", type=int, default=8)
    parser.add_argument(
        "--max-rate-limit-wait",
        type=int,
        default=3700,
        help="遇到 GitHub 主限额时最多等待秒数；设为 0 则记录可重试失败并退出该 PR",
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument("--seed", type=int, default=20260623)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="只使用已有原始响应缓存，不访问 GitHub",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="忽略已有缓存并重新获取",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_token(
    token_env: str,
    *,
    prompt_token: bool,
    require_token: bool,
) -> str:
    token = os.environ.get(token_env, "") or os.environ.get("GITHUB_TOKEN", "")
    if not token and prompt_token:
        token = getpass.getpass("GitHub token: ").strip()
    if require_token and not token:
        raise SystemExit(
            f"未设置 {token_env} 或 GITHUB_TOKEN；"
            "请设置环境变量或同时使用 --prompt-token"
        )
    return token


def sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
        temporary = Path(stream.name)
    temporary.replace(path)


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        temporary = Path(stream.name)
    temporary.replace(path)


def cache_key(repo_name: str, pr_number: str) -> str:
    normalized = f"{repo_name.strip().lower()}#{str(pr_number).strip()}"
    readable = re.sub(r"[^A-Za-z0-9_.-]+", "_", normalized)[:120]
    return f"{readable}__{hashlib.sha256(normalized.encode()).hexdigest()[:12]}"


def safe_error(error: BaseException, token: str) -> str:
    text = clean_text(error)
    if token:
        text = text.replace(token, "<redacted>")
    text = re.sub(
        r"([a-z][a-z0-9+.-]*://)[^/@\s]+@",
        r"\1<redacted>@",
        text,
        flags=re.IGNORECASE,
    )
    return text[-500:]


def classify_http(status: int) -> tuple[str, bool]:
    if status in {401, 403}:
        return "authentication_or_rate_limit", False
    if status == 404:
        return "not_found", False
    if status in TRANSIENT_STATUS:
        return "transient_http", True
    return "http_error", False


def request_json(
    session: requests.Session,
    url: str,
    token: str,
    retries: int,
    max_rate_limit_wait: int,
) -> tuple[Any, dict[str, str], int]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    error: BaseException | None = None
    for attempt in range(1, retries + 1):
        try:
            response = session.get(url, headers=headers, timeout=(30, 90))
        except requests.exceptions.InvalidSchema as exc:
            raise CollectionError(
                "proxy_configuration",
                safe_error(exc, token),
                retryable=False,
                attempts=attempt,
            ) from None
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            error = exc
            category = "network_timeout"
        except requests.exceptions.RequestException as exc:
            error = exc
            category = "network_error"
        else:
            if response.ok:
                try:
                    return (
                        response.json(),
                        {
                            "etag": response.headers.get("ETag", ""),
                            "rate_limit_remaining": response.headers.get(
                                "X-RateLimit-Remaining", ""
                            ),
                            "rate_limit_reset": response.headers.get(
                                "X-RateLimit-Reset", ""
                            ),
                        },
                        attempt,
                    )
                except ValueError as exc:
                    error = exc
                    category = "invalid_json"
            else:
                remaining = response.headers.get("X-RateLimit-Remaining", "")
                reset = response.headers.get("X-RateLimit-Reset", "")
                retry_after = response.headers.get("Retry-After", "")
                is_rate_limit = (
                    response.status_code == 429
                    or (response.status_code == 403 and remaining == "0")
                )
                if is_rate_limit:
                    try:
                        if retry_after:
                            wait = int(float(retry_after))
                        else:
                            wait = max(1, int(float(reset) - time.time()) + 2)
                    except (TypeError, ValueError):
                        wait = max_rate_limit_wait + 1
                    if wait <= max_rate_limit_wait and attempt < retries:
                        logging.warning(
                            "GitHub API 限额耗尽，等待 %d 秒后继续（remaining=%s）",
                            wait,
                            remaining or "unknown",
                        )
                        time.sleep(wait)
                        continue
                    raise CollectionError(
                        "rate_limit",
                        f"GitHub API rate limit; remaining={remaining or 'unknown'}, "
                        f"reset={reset or 'unknown'}, retry_after={retry_after or 'unknown'}",
                        retryable=True,
                        attempts=attempt,
                    )
                category, retryable = classify_http(response.status_code)
                message = f"GitHub API HTTP {response.status_code}: {response.reason}"
                if not retryable:
                    raise CollectionError(
                        category,
                        message,
                        retryable=False,
                        attempts=attempt,
                    )
                error = RuntimeError(message)
        if attempt < retries:
            delay = min(2 ** (attempt - 1), 30) + random.random()
            logging.warning(
                "GitHub API 请求失败，第 %d/%d 次，%.1f 秒后重试: %s",
                attempt,
                retries,
                delay,
                safe_error(error or RuntimeError(category), token),
            )
            time.sleep(delay)
    raise CollectionError(
        category,
        safe_error(error or RuntimeError("unknown GitHub API error"), token),
        retryable=True,
        attempts=retries,
    )


def fetch_pr(
    repo_name: str,
    pr_number: str,
    token: str,
    retries: int,
    max_rate_limit_wait: int,
) -> dict[str, Any]:
    base = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
    with requests.Session() as session:
        session.auth = BearerAuth(token)
        metadata, metadata_headers, attempts = request_json(
            session, base, token, retries, max_rate_limit_wait
        )
        files: list[dict[str, Any]] = []
        page = 1
        total_attempts = attempts
        page_headers: list[dict[str, str]] = []
        while True:
            payload, headers, page_attempts = request_json(
                session,
                f"{base}/files?per_page=100&page={page}",
                token,
                retries,
                max_rate_limit_wait,
            )
            total_attempts += page_attempts
            if not isinstance(payload, list):
                raise CollectionError(
                    "invalid_payload",
                    "GitHub PR files response is not a list",
                    retryable=False,
                    attempts=total_attempts,
                )
            files.extend(payload)
            page_headers.append(headers)
            if len(payload) < 100:
                break
            page += 1
        return {
            "schema_version": SCHEMA_VERSION,
            "repo_name": repo_name,
            "pr_number": str(pr_number),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata,
            "files": files,
            "response_headers": {
                "metadata": metadata_headers,
                "file_pages": page_headers,
            },
            "request_attempts": total_attempts,
        }


def load_rules(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        rules = json.load(stream)
    required = {"classification_precedence", "path_rules", "language_extensions"}
    missing = required - rules.keys()
    if missing:
        raise ValueError(f"路径规则缺少字段: {sorted(missing)}")
    return rules


def file_extension(filename: str) -> str:
    lowered = filename.lower()
    for compound in (".d.ts", ".min.js", ".min.css"):
        if lowered.endswith(compound):
            return compound
    return PurePosixPath(lowered).suffix


def classify_path(filename: str, rules: dict[str, Any]) -> str:
    normalized = filename.replace("\\", "/").strip("/").lower()
    parts = [part for part in normalized.split("/") if part]
    basename = parts[-1] if parts else ""
    for category in rules["classification_precedence"]:
        if category == "production":
            return category
        definition = rules["path_rules"].get(category, {})
        if any(segment.lower() in parts for segment in definition.get("segments", [])):
            return category
        if any(normalized.startswith(prefix.lower()) for prefix in definition.get("prefixes", [])):
            return category
        if basename in {value.lower() for value in definition.get("basenames", [])}:
            return category
        if any(normalized.endswith(suffix.lower()) for suffix in definition.get("suffixes", [])):
            return category
    return "production"


def normalize_file(
    group: str,
    source: dict[str, str],
    payload: dict[str, Any],
    rules: dict[str, Any],
) -> dict[str, Any]:
    filename = clean_text(payload.get("filename"))
    extension = file_extension(filename)
    patch_available = isinstance(payload.get("patch"), str)
    binary = extension in set(rules.get("binary_extensions", []))
    return {
        "group": group,
        "repo_name": source["repo_name"],
        "pr_number": source["pr_number"],
        "pr_id": source.get("pr_id", ""),
        "filename": filename,
        "previous_filename": clean_text(payload.get("previous_filename")),
        "status": clean_text(payload.get("status")),
        "additions": int(payload.get("additions") or 0),
        "deletions": int(payload.get("deletions") or 0),
        "changes": int(payload.get("changes") or 0),
        "extension": extension,
        "actual_language": rules["language_extensions"].get(extension, "Other"),
        "path_class": classify_path(filename, rules),
        "is_binary": int(binary),
        "patch_available": int(patch_available),
        "source": "github_rest_api",
    }


def normalize_pr(
    group: str,
    source: dict[str, str],
    cached: dict[str, Any],
    normalized_files: list[dict[str, Any]],
    cache_path: Path,
) -> dict[str, Any]:
    metadata = cached["metadata"]
    additions = int(metadata.get("additions") or 0)
    deletions = int(metadata.get("deletions") or 0)
    classes = Counter(row["path_class"] for row in normalized_files)
    languages = sorted(
        {row["actual_language"] for row in normalized_files if row["actual_language"] != "Other"}
    )
    return {
        "group": group,
        "repo_name": source["repo_name"],
        "pr_number": source["pr_number"],
        "pr_id": source.get("pr_id", ""),
        "source_language": source.get("language", ""),
        "task_type": source.get("task_type", ""),
        "api_state": clean_text(metadata.get("state")),
        "merged": int(bool(metadata.get("merged"))),
        "merged_at": clean_text(metadata.get("merged_at")),
        "created_at": clean_text(metadata.get("created_at")),
        "closed_at": clean_text(metadata.get("closed_at")),
        "base_sha": clean_text((metadata.get("base") or {}).get("sha")),
        "head_sha": clean_text((metadata.get("head") or {}).get("sha")),
        "additions": additions,
        "deletions": deletions,
        "changed_lines": additions + deletions,
        "changed_kloc": f"{(additions + deletions) / 1000:.6f}",
        "changed_files": int(metadata.get("changed_files") or len(normalized_files)),
        "file_list_returned": len(normalized_files),
        "file_list_complete": int(
            int(metadata.get("changed_files") or len(normalized_files))
            == len(normalized_files)
        ),
        "commit_count": int(metadata.get("commits") or 0),
        "production_files": classes["production"],
        "test_files": classes["test"],
        "docs_files": classes["docs"],
        "example_files": classes["example"],
        "generated_files": classes["generated"],
        "vendor_files": classes["vendor"],
        "build_files": classes["build"],
        "binary_files": sum(row["is_binary"] for row in normalized_files),
        "no_patch_files": sum(not row["patch_available"] for row in normalized_files),
        "actual_languages": ";".join(languages),
        "cache_key": cache_path.stem,
        "cache_sha256": sha256_file(cache_path),
        "source": "github_rest_api",
        "fetched_at": cached.get("fetched_at", ""),
    }


def read_manifest_rows(study_root: Path, groups: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for group in groups:
        path = study_root / group / "prs.csv"
        with path.open(newline="", encoding="utf-8-sig") as stream:
            for row in csv.DictReader(stream):
                repo_name = clean_text(row.get("repo_name"))
                pr_number = clean_text(row.get("pr_number"))
                if not repo_name or not pr_number:
                    raise ValueError(f"{path} 包含缺少 repo_name/pr_number 的记录")
                key = (group, repo_name.lower(), pr_number)
                if key in seen:
                    raise ValueError(f"{path} 包含重复 PR: {repo_name}#{pr_number}")
                seen.add(key)
                rows.append({**row, "group": group})
    return rows


def interleave_sources(
    sources: list[dict[str, str]], groups: list[str]
) -> list[dict[str, str]]:
    buckets = {
        group: sorted(
            (row for row in sources if row["group"] == group),
            key=lambda row: (row["repo_name"].lower(), int(row["pr_number"])),
        )
        for group in groups
    }
    result: list[dict[str, str]] = []
    index = 0
    while True:
        added = False
        for group in groups:
            if index < len(buckets[group]):
                result.append(buckets[group][index])
                added = True
        if not added:
            return result
        index += 1


def collect_one(
    source: dict[str, str],
    cache_dir: Path,
    rules: dict[str, Any],
    token: str,
    retries: int,
    max_rate_limit_wait: int,
    offline: bool,
    refresh: bool,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], dict[str, Any] | None]:
    group = source["group"]
    key = cache_key(source["repo_name"], source["pr_number"])
    cache_path = cache_dir / f"{key}.json"
    try:
        if cache_path.exists() and not refresh:
            with cache_path.open(encoding="utf-8") as stream:
                cached = json.load(stream)
        elif offline:
            raise CollectionError(
                "cache_missing",
                "offline 模式下没有原始 GitHub 响应缓存",
                retryable=True,
            )
        else:
            cached = fetch_pr(
                source["repo_name"],
                source["pr_number"],
                token,
                retries,
                max_rate_limit_wait,
            )
            atomic_json(cache_path, cached)
        if (
            clean_text(cached.get("repo_name")).lower() != source["repo_name"].lower()
            or clean_text(cached.get("pr_number")) != source["pr_number"]
        ):
            raise CollectionError(
                "cache_identity_mismatch",
                "缓存中的 repo_name/pr_number 与输入不一致",
                retryable=False,
            )
        files = [
            normalize_file(group, source, payload, rules)
            for payload in cached.get("files", [])
        ]
        return normalize_pr(group, source, cached, files, cache_path), files, None
    except (CollectionError, OSError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, CollectionError):
            category = exc.category
            retryable = exc.retryable
            attempts = exc.attempts
        elif isinstance(exc, json.JSONDecodeError):
            category, retryable, attempts = "cache_invalid_json", False, 0
        elif isinstance(exc, OSError):
            category, retryable, attempts = "local_io", True, 0
        else:
            category, retryable, attempts = "invalid_payload", False, 0
        return None, [], {
            "group": group,
            "repo_name": source["repo_name"],
            "pr_number": source["pr_number"],
            "pr_id": source.get("pr_id", ""),
            "category": category,
            "retryable": int(retryable),
            "attempts": attempts,
            "message": safe_error(exc, token),
        }


def collect_one_locked(
    lock: Lock,
    source: dict[str, str],
    cache_dir: Path,
    rules: dict[str, Any],
    token: str,
    retries: int,
    max_rate_limit_wait: int,
    offline: bool,
    refresh: bool,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], dict[str, Any] | None]:
    with lock:
        return collect_one(
            source,
            cache_dir,
            rules,
            token,
            retries,
            max_rate_limit_wait,
            offline,
            refresh,
        )


def write_aidev_validation(
    parquet_path: Path,
    pr_rows: list[dict[str, Any]],
    output_path: Path,
) -> int:
    ai_by_id = {
        int(row["pr_id"]): row
        for row in pr_rows
        if row["group"] == "ai" and clean_text(row.get("pr_id")).isdigit()
    }
    if not parquet_path.exists() or not ai_by_id:
        return 0
    aggregates: dict[int, dict[str, Any]] = defaultdict(
        lambda: {"additions": 0.0, "deletions": 0.0, "files": set(), "commits": set()}
    )
    parquet = pq.ParquetFile(parquet_path)
    for batch in parquet.iter_batches(
        columns=["pr_id", "sha", "filename", "additions", "deletions"],
        batch_size=65536,
    ):
        values = batch.to_pydict()
        for index, pr_id in enumerate(values["pr_id"]):
            if pr_id not in ai_by_id:
                continue
            current = aggregates[pr_id]
            current["additions"] += float(values["additions"][index] or 0)
            current["deletions"] += float(values["deletions"][index] or 0)
            current["files"].add(clean_text(values["filename"][index]))
            current["commits"].add(clean_text(values["sha"][index]))
    rows: list[dict[str, Any]] = []
    for pr_id, github in sorted(ai_by_id.items()):
        aidev = aggregates.get(pr_id)
        if not aidev:
            rows.append(
                {
                    "pr_id": pr_id,
                    "repo_name": github["repo_name"],
                    "pr_number": github["pr_number"],
                    "status": "missing_in_aidev",
                }
            )
            continue
        github_additions = int(github["additions"])
        github_deletions = int(github["deletions"])
        aidev_additions = int(aidev["additions"])
        aidev_deletions = int(aidev["deletions"])
        rows.append(
            {
                "pr_id": pr_id,
                "repo_name": github["repo_name"],
                "pr_number": github["pr_number"],
                "status": "compared",
                "github_additions": github_additions,
                "aidev_commit_file_additions": aidev_additions,
                "additions_difference": github_additions - aidev_additions,
                "github_deletions": github_deletions,
                "aidev_commit_file_deletions": aidev_deletions,
                "deletions_difference": github_deletions - aidev_deletions,
                "github_changed_files": github["changed_files"],
                "aidev_unique_files": len(aidev["files"]),
                "github_commit_count": github["commit_count"],
                "aidev_unique_commits": len(aidev["commits"]),
            }
        )
    fields = sorted({key for row in rows for key in row})
    write_csv(output_path, rows, fields)
    return len(rows)


def write_coverage_reports(
    output_dir: Path,
    sources: list[dict[str, str]],
    pr_rows: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> None:
    requested = Counter(row["group"] for row in sources)
    successful = Counter(row["group"] for row in pr_rows)
    failed = Counter(row["group"] for row in failures)
    incomplete_files = Counter(
        row["group"] for row in pr_rows if not int(row["file_list_complete"])
    )
    missing_merge_time = Counter(
        row["group"] for row in pr_rows if not clean_text(row.get("merged_at"))
    )
    groups = sorted(requested)
    rows = []
    for group in groups:
        denominator = requested[group]
        rows.append(
            {
                "group": group,
                "requested_prs": denominator,
                "successful_prs": successful[group],
                "failed_prs": failed[group],
                "coverage_rate": f"{successful[group] / denominator:.8f}"
                if denominator
                else "",
                "incomplete_file_lists": incomplete_files[group],
                "missing_merge_time": missing_merge_time[group],
            }
        )
    write_csv(
        output_dir / "coverage_summary.csv",
        rows,
        [
            "group",
            "requested_prs",
            "successful_prs",
            "failed_prs",
            "coverage_rate",
            "incomplete_file_lists",
            "missing_merge_time",
        ],
    )
    failure_patterns = Counter(
        (row["group"], row["category"], row["retryable"]) for row in failures
    )
    lines = [
        "# PR Enrichment Coverage",
        "",
        "| Group | Requested | Successful | Failed | Coverage | Incomplete file lists | Missing merge time |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['group']} | {row['requested_prs']} | {row['successful_prs']} | "
            f"{row['failed_prs']} | {float(row['coverage_rate'] or 0):.2%} | "
            f"{row['incomplete_file_lists']} | {row['missing_merge_time']} |"
        )
    lines.extend(
        [
            "",
            "## Structured missingness",
            "",
            "| Group | Failure category | Retryable | PRs |",
            "| --- | --- | ---: | ---: |",
        ]
    )
    if failure_patterns:
        for (group, category, retryable), count in sorted(failure_patterns.items()):
            lines.append(f"| {group} | {category} | {retryable} | {count} |")
    else:
        lines.append("| — | none | — | 0 |")
    lines.extend(
        [
            "",
            "Coverage failures are not imputed. Retryable API/network failures may be "
            "recollected with the same command; permanent failures remain in "
            "`failure_audit.csv`.",
            "",
        ]
    )
    (output_dir / "coverage_report.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def build_manifest(
    study_root: Path,
    groups: list[str],
    rules_path: Path,
    cache_dir: Path,
    output_dir: Path,
    counts: dict[str, Any],
) -> dict[str, Any]:
    inputs = {
        str(study_root / group / "prs.csv"): sha256_file(study_root / group / "prs.csv")
        for group in groups
    }
    inputs[str(rules_path)] = sha256_file(rules_path)
    outputs = {
        str(path): sha256_file(path)
        for path in sorted(output_dir.iterdir())
        if path.is_file() and path.name != "snapshot_manifest.json"
    }
    cache_files = sorted(cache_dir.glob("*.json"))
    cache_index = [
        {"path": str(path), "sha256": sha256_file(path)} for path in cache_files
    ]
    cache_index_path = output_dir / "cache_manifest.csv"
    write_csv(cache_index_path, cache_index, ["path", "sha256"])
    outputs[str(cache_index_path)] = sha256_file(cache_index_path)
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "groups": groups,
        "source": "GitHub REST API (same definition for AI and Human)",
        "counts": counts,
        "inputs": inputs,
        "outputs": outputs,
        "cache_index": {
            "path": str(cache_index_path),
            "sha256": outputs[str(cache_index_path)],
            "entries": len(cache_index),
        },
    }


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)
    study_root = Path(args.study_root)
    groups = args.groups or ["ai", "human"]
    output_dir = (
        Path(args.output_dir)
        if args.output_dir
        else study_root / "reports" / "pr_enrichment"
    )
    cache_dir = (
        Path(args.cache_dir)
        if args.cache_dir
        else study_root / "metadata" / "pr_enrichment_cache"
    )
    rules_path = Path(args.rules)
    token = resolve_token(
        args.token_env,
        prompt_token=args.prompt_token,
        require_token=args.require_token,
    )
    if args.workers < 1 or args.retries < 1:
        raise SystemExit("--workers 和 --retries 必须大于 0")
    rules = load_rules(rules_path)
    sources = read_manifest_rows(study_root, groups)
    sources = interleave_sources(sources, groups)
    if args.limit is not None:
        sources = sources[: args.limit]
    cache_dir.mkdir(parents=True, exist_ok=True)
    pr_rows: list[dict[str, Any]] = []
    file_rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    cache_locks: dict[str, Lock] = {}
    for source in sources:
        cache_locks.setdefault(
            cache_key(source["repo_name"], source["pr_number"]), Lock()
        )
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                collect_one_locked,
                cache_locks[cache_key(source["repo_name"], source["pr_number"])],
                source,
                cache_dir,
                rules,
                token,
                args.retries,
                args.max_rate_limit_wait,
                args.offline,
                args.refresh,
            ): source
            for source in sources
        }
        for index, future in enumerate(as_completed(futures), start=1):
            pr_row, files, failure = future.result()
            if pr_row:
                pr_rows.append(pr_row)
                file_rows.extend(files)
            if failure:
                failures.append(failure)
            if index % 100 == 0 or index == len(futures):
                logging.info(
                    "enrichment %d/%d: 成功 %d，失败 %d",
                    index,
                    len(futures),
                    len(pr_rows),
                    len(failures),
                )
    pr_rows.sort(key=lambda row: (row["group"], row["repo_name"], int(row["pr_number"])))
    file_rows.sort(
        key=lambda row: (
            row["group"],
            row["repo_name"],
            int(row["pr_number"]),
            row["filename"],
        )
    )
    failures.sort(
        key=lambda row: (row["group"], row["repo_name"], int(row["pr_number"]))
    )
    write_csv(output_dir / "pr_enrichment.csv", pr_rows, PR_FIELDS)
    write_csv(output_dir / "file_enrichment.csv", file_rows, FILE_FIELDS)
    write_csv(output_dir / "failure_audit.csv", failures, FAILURE_FIELDS)
    write_coverage_reports(output_dir, sources, pr_rows, failures)
    validation_count = write_aidev_validation(
        Path(args.aidev_commit_details),
        pr_rows,
        output_dir / "ai_aidev_cross_validation.csv",
    )
    group_success = Counter(row["group"] for row in pr_rows)
    group_failures = Counter(row["group"] for row in failures)
    manifest = build_manifest(
        study_root,
        groups,
        rules_path,
        cache_dir,
        output_dir,
        {
            "requested_prs": len(sources),
            "successful_prs": len(pr_rows),
            "failed_prs": len(failures),
            "file_rows": len(file_rows),
            "aidev_validation_rows": validation_count,
            "success_by_group": dict(group_success),
            "failure_by_group": dict(group_failures),
            "failure_categories": dict(Counter(row["category"] for row in failures)),
        },
    )
    atomic_json(output_dir / "snapshot_manifest.json", manifest)
    logging.info(
        "完成：PR %d，文件 %d，失败 %d；输出 %s",
        len(pr_rows),
        len(file_rows),
        len(failures),
        output_dir,
    )


if __name__ == "__main__":
    main()
