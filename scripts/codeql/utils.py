"""Shared utilities for the CodeQL study pipeline."""

from __future__ import annotations

import csv
import logging
import math
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_LANGUAGES = ("Java", "JavaScript", "TypeScript", "Python", "Go")
CODEQL_LANGUAGES = (
    "C",
    "C++",
    "C#",
    "Go",
    "Java",
    "JavaScript",
    "Kotlin",
    "Python",
    "Ruby",
    "Swift",
    "TypeScript",
)
DEFAULT_KEYWORDS = (
    "fix",
    "bug",
    "issue",
    "error",
    "security",
    "vulnerability",
    "sanitize",
    "validation",
    "injection",
    "xss",
    "sql",
    "rce",
    "path traversal",
    "auth",
    "permission",
    "leak",
    "crash",
)
DEFAULT_REPO_EXCLUDES = (
    "awesome",
    "docs",
    "documentation",
    "examples",
    "sample",
    "samples",
    "demo",
    "tutorial",
    "template",
    "dotfiles",
    "config",
    "configuration",
    "cheatsheet",
    "roadmap",
)
DEFAULT_LOW_VALUE_TERMS = (
    "readme",
    "documentation",
    "docs only",
    "typo",
    "formatting",
    "code format",
    "prettier",
    "black formatting",
    "ci config",
    "github actions",
    "workflow",
    "lockfile",
    "dependency update",
    "dependencies update",
    "bump dependency",
    "bump version",
    "renovate",
    "dependabot",
)

REPO_ALIASES = {
    "repo_id": ("repo_id", "id", "repository_id"),
    "repo_name": ("repo_name", "full_name", "name", "repository"),
    "repo_url": ("repo_url", "html_url", "url"),
    "language": ("language", "primary_language"),
    "stars": ("stars", "stargazers_count", "star_count"),
}
PR_ALIASES = {
    "pr_id": ("pr_id", "id", "pull_request_id"),
    "pr_number": ("pr_number", "number", "pull_number"),
    "pr_title": ("pr_title", "title"),
    "pr_body": ("pr_body", "body", "description"),
    "agent": ("agent", "ai_agent", "tool"),
    "state": ("state", "status"),
    "repo_id": ("repo_id", "repository_id"),
    "repo_url": ("repo_url", "repository_url"),
    "pr_url": ("pr_url", "html_url", "url"),
    "merged_at": ("merged_at", "merge_at"),
    "closed_at": ("closed_at",),
    "base_sha": ("base_sha", "before_sha", "base_commit"),
    "head_sha": ("head_sha", "after_sha", "head_commit"),
}
FILE_ALIASES = {
    "pr_id": ("pr_id", "pull_request_id", "id"),
    "filename": ("filename", "path", "file_path"),
}

DOC_EXTENSIONS = {
    ".md",
    ".mdx",
    ".rst",
    ".adoc",
    ".txt",
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
}
LOCK_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pipfile.lock",
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
    "go.sum",
}
CONFIG_ONLY_FILES = {
    ".editorconfig",
    ".gitignore",
    ".gitattributes",
    ".prettierrc",
    ".prettierignore",
}
CI_PREFIXES = (".github/", ".circleci/", ".gitlab/", ".buildkite/")


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )


def is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    return str(value).strip().lower() in {"", "nan", "none", "null", "<na>"}


def clean_text(value: Any) -> str:
    return "" if is_missing(value) else str(value).strip()


def first_value(
    row: Mapping[str, Any],
    aliases: Mapping[str, tuple[str, ...]],
    canonical: str,
    default: Any = "",
) -> Any:
    for name in aliases[canonical]:
        if name in row and not is_missing(row[name]):
            return row[name]
    return default


def parse_int(value: Any, default: int = 0) -> int:
    if is_missing(value):
        return default
    try:
        return int(float(str(value).replace(",", "")))
    except (TypeError, ValueError):
        return default


def normalize_language(value: Any) -> str:
    raw = clean_text(value)
    aliases = {
        "js": "JavaScript",
        "javascript": "JavaScript",
        "ts": "TypeScript",
        "typescript": "TypeScript",
        "py": "Python",
        "python": "Python",
        "golang": "Go",
        "go": "Go",
        "java": "Java",
        "csharp": "C#",
        "c#": "C#",
        "cpp": "C++",
        "c++": "C++",
    }
    return aliases.get(raw.lower(), raw)


def normalize_repo_url(value: Any, repo_name: str = "") -> str:
    raw = clean_text(value)
    if raw:
        raw = raw.replace("api.github.com/repos/", "github.com/")
        return raw.removesuffix(".git")
    return f"https://github.com/{repo_name}" if repo_name else ""


def repo_name_from_url(value: Any) -> str:
    raw = clean_text(value).replace("api.github.com/repos/", "github.com/")
    if not raw:
        return ""
    path = urlparse(raw).path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.split("/")
    return "/".join(parts[:2]) if len(parts) >= 2 else path


def keyword_hits(text: str, keywords: Iterable[str]) -> list[str]:
    lowered = text.lower()
    hits = []
    for keyword in keywords:
        keyword = keyword.strip().lower()
        if not keyword:
            continue
        pattern = r"(?<!\w)" + re.escape(keyword).replace(r"\ ", r"\s+") + r"(?!\w)"
        if re.search(pattern, lowered):
            hits.append(keyword)
    return hits


def looks_like_excluded_repo(repo_name: str, terms: Iterable[str]) -> bool:
    name = repo_name.lower()
    leaf = name.rsplit("/", 1)[-1]
    tokens = set(re.split(r"[-_.\s]+", leaf))
    for term in terms:
        term = term.strip().lower()
        if term and (term in tokens or leaf == term):
            return True
    return False


def looks_low_value_text(title: str, body: str, terms: Iterable[str]) -> bool:
    text = f"{title}\n{body}".lower()
    return any(term.strip().lower() in text for term in terms if term.strip())


def is_low_value_file(filename: str) -> bool:
    path = filename.strip().lower()
    while path.startswith("./"):
        path = path[2:]
    if not path:
        return True
    name = Path(path).name
    suffix = Path(path).suffix
    if path.startswith(CI_PREFIXES):
        return True
    if name in LOCK_FILES or name in CONFIG_ONLY_FILES:
        return True
    if suffix in DOC_EXTENSIONS:
        return True
    if path.startswith(("docs/", "doc/", "documentation/")):
        return True
    return False


def warn_missing_fields(
    columns: Iterable[str],
    aliases: Mapping[str, tuple[str, ...]],
    required: Iterable[str],
    source_name: str,
) -> None:
    available = set(columns)
    for canonical in required:
        if not any(alias in available for alias in aliases[canonical]):
            logging.warning(
                "%s 缺少字段 %s（可接受别名: %s）",
                source_name,
                canonical,
                ", ".join(aliases[canonical]),
            )


def write_csv_header(path: Path, fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        csv.DictWriter(handle, fieldnames=fieldnames).writeheader()


def append_csv_rows(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> int:
    count = 0
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        for row in rows:
            writer.writerow(row)
            count += 1
    return count
