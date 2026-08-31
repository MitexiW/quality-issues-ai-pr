#!/usr/bin/env python3
"""Local, provenance-label-hidden review UI for CodeQL alert confirmation.

The application deliberately uses only the Python standard library.  It reads
the frozen alert CSV, lazily reconstructs before/head context from the existing
bare Git caches (with retained source directories as a fallback), and stores
every review action transactionally in SQLite.

The server binds to 127.0.0.1 by default.  Use SSH or VS Code port forwarding
when the experiment runs on a remote server; do not expose the annotation UI on
an unauthenticated public interface.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import errno
import hashlib
import json
import os
import random
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / (
    "data/experiments/security-and-quality/study_stars500/reports/"
    "validated_issue_analysis_20260808_v1/validated_alerts.csv"
)
DEFAULT_OUTPUT = ROOT / (
    "data/experiments/security-and-quality/study_stars500/reports/"
    "manual_validation/full_validated_2495_v1"
)
DEFAULT_AI_JOBS = ROOT / (
    "data/experiments/security-and-quality/study_stars500/ai/codeql_jobs.csv"
)
DEFAULT_HUMAN_JOBS = ROOT / (
    "data/experiments/security-and-quality/study_stars500/human/codeql_jobs.csv"
)
DEFAULT_AI_CACHE = ROOT / (
    "data/experiments/security-and-quality/study_stars500/ai/repos/.cache"
)
DEFAULT_HUMAN_CACHE = ROOT / (
    "data/experiments/security-and-quality/study_stars500/human/repos/.cache"
)
# This server only permits user services on ports above 20024.  Keep the
# review UI inside that range while avoiding the user's existing 20025 proxy.
DEFAULT_PORT = 20080

ALLOWED_DISPOSITIONS = {
    "confirmed_valid",
    "condition_absent",
    "not_pr_introduced",
    "not_valid_issue",
    "uncertain",
}
ALLOWED_ACTIONABILITY = {
    "must_fix",
    "should_fix",
    "optional",
    "no_fix",
    "uncertain",
    "not_assessed",
}
ALLOWED_CONFIDENCE = {"", "high", "medium", "low"}
ALLOWED_STATUS = {"draft", "completed", "needs_followup", "deferred"}
MAX_TEXT_BYTES = 2_000_000
MAX_DIFF_CHARS = 240_000
SNIPPET_RADIUS = 28


class ReviewConflictError(ValueError):
    """Raised when a stale browser tab attempts to overwrite a newer label."""

    def __init__(self, message: str, current_revision: int) -> None:
        super().__init__(message)
        self.current_revision = current_revision


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def maximize_csv_field_limit() -> None:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


maximize_csv_field_limit()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_relative_path(raw: str) -> str:
    value = clean(raw).replace("\\", "/")
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe repository-relative path: {raw!r}")
    return str(path)


def int_line(value: Any) -> int | None:
    raw = clean(value)
    if not raw:
        return None
    try:
        number = int(float(raw))
    except ValueError:
        return None
    return number if number > 0 else None


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def case_key(row: dict[str, str]) -> tuple[str, str, str]:
    return (
        clean(row.get("group")).casefold(),
        clean(row.get("repo_name")).casefold(),
        clean(row.get("pr_number")),
    )


def make_review_order(rows: list[dict[str, str]], seed: int) -> list[dict[str, str]]:
    """Randomize PR chunks deterministically without long same-PR runs."""

    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[clean(row.get("case_id"))].append(row)
    chunks: list[tuple[str, int, list[dict[str, str]]]] = []
    for cid, case_rows in grouped.items():
        ordered = sorted(case_rows, key=lambda item: clean(item.get("alert_id")))
        for offset in range(0, len(ordered), 10):
            chunks.append((cid, offset // 10, ordered[offset : offset + 10]))
    rng = random.Random(seed)
    rng.shuffle(chunks)
    result: list[dict[str, str]] = []
    previous_case = ""
    while chunks:
        selected = next(
            (index for index, chunk in enumerate(chunks) if chunk[0] != previous_case),
            0,
        )
        cid, _, chunk_rows = chunks.pop(selected)
        result.extend(chunk_rows)
        previous_case = cid
    return result


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS items (
    alert_id TEXT PRIMARY KEY,
    ordinal INTEGER NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS labels (
    alert_id TEXT PRIMARY KEY REFERENCES items(alert_id),
    status TEXT NOT NULL DEFAULT 'draft',
    disposition TEXT NOT NULL DEFAULT '',
    human_condition_present TEXT NOT NULL DEFAULT '',
    human_introduced_by_pr TEXT NOT NULL DEFAULT '',
    human_valid_issue TEXT NOT NULL DEFAULT '',
    human_actionability TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    flagged INTEGER NOT NULL DEFAULT 0,
    revision INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL DEFAULT '',
    submitted_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS labels_status_idx ON labels(status);
CREATE INDEX IF NOT EXISTS events_alert_idx ON events(alert_id);
"""


def connect_db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def initialize_database(
    database: Path,
    input_path: Path,
    rows: list[dict[str, str]],
    *,
    seed: int,
) -> None:
    database.parent.mkdir(parents=True, exist_ok=True)
    input_hash = sha256_file(input_path)
    ordered = make_review_order(rows, seed)
    alert_ids = [clean(row.get("alert_id")) for row in ordered]
    if any(not alert_id for alert_id in alert_ids):
        raise ValueError("every input row must have alert_id")
    if len(set(alert_ids)) != len(alert_ids):
        raise ValueError("input contains duplicate alert_id values")

    with connect_db(database) as connection:
        connection.executescript(SCHEMA)
        existing_hash = connection.execute(
            "SELECT value FROM meta WHERE key='input_sha256'"
        ).fetchone()
        if existing_hash and existing_hash[0] != input_hash:
            raise ValueError(
                "review database belongs to a different input CSV; choose a new output directory"
            )
        existing_count = connection.execute("SELECT COUNT(*) FROM items").fetchone()[0]
        if existing_count and existing_count != len(rows):
            raise ValueError(
                f"review database contains {existing_count} items, input contains {len(rows)}"
            )
        metadata = {
            "schema_version": "1",
            "input_path": str(input_path.resolve()),
            "input_sha256": input_hash,
            "input_n": str(len(rows)),
            "seed": str(seed),
            "created_at": utc_now(),
        }
        for key, value in metadata.items():
            connection.execute(
                "INSERT OR IGNORE INTO meta(key,value) VALUES (?,?)", (key, value)
            )
        if not existing_count:
            for ordinal, row in enumerate(ordered, start=1):
                connection.execute(
                    "INSERT INTO items(alert_id,ordinal,case_id,payload_json) VALUES (?,?,?,?)",
                    (
                        clean(row.get("alert_id")),
                        ordinal,
                        clean(row.get("case_id")),
                        json.dumps(row, ensure_ascii=False, separators=(",", ":")),
                    ),
                )


def backup_database(database: Path, output_dir: Path) -> Path | None:
    if not database.exists():
        return None
    with connect_db(database) as source:
        label_n = source.execute("SELECT COUNT(*) FROM labels").fetchone()[0]
        if not label_n:
            return None
        backup_dir = output_dir / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        newest = max(
            backup_dir.glob("review-*.sqlite3"),
            default=None,
            key=lambda path: path.stat().st_mtime,
        )
        if newest and time.time() - newest.stat().st_mtime < 20 * 60 * 60:
            return None
        target = backup_dir / datetime.now().strftime("review-%Y%m%d-%H%M%S.sqlite3")
        with sqlite3.connect(target) as destination:
            source.backup(destination)
        return target


def derive_human_fields(disposition: str) -> tuple[str, str, str]:
    mapping = {
        "confirmed_valid": ("yes", "yes", "yes"),
        "condition_absent": ("no", "not_assessed", "not_assessed"),
        "not_pr_introduced": ("yes", "no", "not_assessed"),
        "not_valid_issue": ("yes", "yes", "no"),
        "uncertain": ("uncertain", "uncertain", "uncertain"),
    }
    return mapping[disposition]


class SmallLRU:
    def __init__(self, maxsize: int = 32):
        self.maxsize = maxsize
        self._data: OrderedDict[str, Any] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            if key not in self._data:
                return None
            value = self._data.pop(key)
            self._data[key] = value
            return value

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            self._data.pop(key, None)
            self._data[key] = value
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)


class ContextProvider:
    def __init__(
        self,
        *,
        ai_jobs: Path,
        human_jobs: Path,
        ai_cache: Path,
        human_cache: Path,
        alert_rows: list[dict[str, str]] | None = None,
    ) -> None:
        self.jobs: dict[tuple[str, str, str, str], dict[str, str]] = {}
        for group, path in (("ai", ai_jobs), ("human", human_jobs)):
            for row in read_csv(path):
                revision = clean(row.get("revision")).casefold()
                if revision in {"before", "after"}:
                    self.jobs[(*case_key({**row, "group": group}), revision)] = row
        self.cache_dirs = {"ai": ai_cache, "human": human_cache}
        self.file_cache = SmallLRU(96)
        self.alert_rows_by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in alert_rows or []:
            self.alert_rows_by_case[clean(row.get("case_id"))].append(row)
        # Keep only compact traces.  Some SARIF files are hundreds of MiB, so
        # retaining parsed documents in an LRU would unnecessarily consume
        # gigabytes during a long annotation session.
        self.sarif_traces: dict[str, dict[str, Any]] = {}
        self.sarif_cases_loaded: set[str] = set()
        self.sarif_lock = threading.Lock()

    def _job(self, row: dict[str, str], revision: str) -> dict[str, str]:
        return self.jobs.get((*case_key(row), revision), {})

    def _sha(self, row: dict[str, str], revision: str) -> str:
        field = "base_sha" if revision == "before" else "head_sha"
        direct = clean(row.get(field))
        job = self._job(row, revision)
        return direct or clean(job.get("checkout_ref")) or clean(job.get(field))

    def _cache_dir(self, row: dict[str, str]) -> Path:
        group = clean(row.get("group")).casefold()
        repo = clean(row.get("repo_name")).replace("/", "_") + ".git"
        return self.cache_dirs[group] / repo

    @staticmethod
    def _source_dir(job: dict[str, str]) -> Path | None:
        raw = clean(job.get("source_dir"))
        if not raw:
            return None
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = ROOT / path
        return path

    @staticmethod
    def _read_plain(path: Path) -> tuple[str | None, str]:
        try:
            if not path.is_file() or path.is_symlink():
                return None, "missing"
            payload = path.read_bytes()
            if len(payload) > MAX_TEXT_BYTES:
                payload = payload[:MAX_TEXT_BYTES]
                suffix = "\n\n[File truncated by review UI]\n"
            else:
                suffix = ""
            return payload.decode("utf-8", errors="replace") + suffix, "retained_source"
        except OSError as exc:
            return None, f"retained_source_error:{exc}"

    def read_revision_file(
        self, row: dict[str, str], revision: str, relative_path: str
    ) -> tuple[str | None, str]:
        path = safe_relative_path(relative_path)
        sha = self._sha(row, revision)
        cache = self._cache_dir(row)
        key = f"{cache}:{sha}:{path}"
        cached = self.file_cache.get(key)
        if cached is not None:
            return cached
        if cache.is_dir() and sha:
            env = dict(os.environ)
            env["GIT_NO_LAZY_FETCH"] = "1"
            try:
                result = subprocess.run(
                    ["git", f"--git-dir={cache}", "show", f"{sha}:{path}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    timeout=12,
                    check=False,
                )
                if result.returncode == 0:
                    payload = result.stdout[:MAX_TEXT_BYTES]
                    text = payload.decode("utf-8", errors="replace")
                    if len(result.stdout) > MAX_TEXT_BYTES:
                        text += "\n\n[File truncated by review UI]\n"
                    value = (text, "bare_cache")
                    self.file_cache.put(key, value)
                    return value

                # Distinguish a file that genuinely did not exist at this
                # revision from an unavailable blob in a partial clone.  The
                # tree lookup does not need the file blob itself.
                tree = subprocess.run(
                    ["git", f"--git-dir={cache}", "ls-tree", "-z", sha, "--", path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    timeout=12,
                    check=False,
                )
                if tree.returncode == 0 and not tree.stdout:
                    value = (None, "absent_at_revision")
                    self.file_cache.put(key, value)
                    return value
            except (OSError, subprocess.TimeoutExpired):
                pass
        job = self._job(row, revision)
        source = self._source_dir(job)
        if source:
            value = self._read_plain(source / Path(path))
            self.file_cache.put(key, value)
            return value
        value = (None, "unavailable")
        self.file_cache.put(key, value)
        return value

    def file_diff(
        self,
        row: dict[str, str],
        relative_path: str,
        before_text: str | None,
        head_text: str | None,
    ) -> tuple[str, str]:
        path = safe_relative_path(relative_path)
        base = self._sha(row, "before")
        head = self._sha(row, "after")
        cache = self._cache_dir(row)
        if cache.is_dir() and base and head:
            env = dict(os.environ)
            env["GIT_NO_LAZY_FETCH"] = "1"
            try:
                result = subprocess.run(
                    [
                        "git",
                        f"--git-dir={cache}",
                        "diff",
                        "--no-ext-diff",
                        "--unified=28",
                        base,
                        head,
                        "--",
                        path,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    timeout=18,
                    check=False,
                )
                if result.returncode == 0:
                    text = result.stdout.decode("utf-8", errors="replace")
                    return self._truncate_diff(text), "bare_cache"
            except (OSError, subprocess.TimeoutExpired):
                pass
        before_lines = (before_text or "").splitlines(keepends=True)
        head_lines = (head_text or "").splitlines(keepends=True)
        diff = "".join(
            difflib.unified_diff(
                before_lines,
                head_lines,
                fromfile=f"before/{path}",
                tofile=f"head/{path}",
                n=28,
            )
        )
        return self._truncate_diff(diff), "retained_source_fallback"

    def renamed_from(self, row: dict[str, str], new_path: str) -> str | None:
        """Return the base-side path when ``new_path`` is a detected rename."""

        path = safe_relative_path(new_path)
        base = self._sha(row, "before")
        head = self._sha(row, "after")
        cache = self._cache_dir(row)
        if not (cache.is_dir() and base and head):
            return None
        env = dict(os.environ)
        env["GIT_NO_LAZY_FETCH"] = "1"
        try:
            result = subprocess.run(
                [
                    "git",
                    f"--git-dir={cache}",
                    "diff",
                    "--name-status",
                    "--find-renames",
                    base,
                    head,
                    "--",
                    path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode:
            return None
        for raw_line in result.stdout.decode("utf-8", errors="replace").splitlines():
            fields = raw_line.split("\t")
            if len(fields) == 3 and fields[0].startswith("R") and fields[2] == path:
                try:
                    return safe_relative_path(fields[1])
                except ValueError:
                    return None
        return None

    @staticmethod
    def _truncate_diff(text: str) -> str:
        if len(text) <= MAX_DIFF_CHARS:
            return text
        return text[:MAX_DIFF_CHARS] + "\n\n[Diff truncated by review UI]\n"

    @staticmethod
    def snippet(text: str | None, line: int | None) -> dict[str, Any]:
        if text is None:
            return {"text": "", "start_line": 1, "focus_line": line, "available": False}
        lines = text.splitlines()
        if not lines:
            return {"text": "", "start_line": 1, "focus_line": line, "available": True}
        focus = min(max(line or 1, 1), len(lines))
        start = max(1, focus - SNIPPET_RADIUS)
        end = min(len(lines), focus + SNIPPET_RADIUS)
        numbered = "\n".join(
            f"{number:>6}  {lines[number - 1]}" for number in range(start, end + 1)
        )
        return {
            "text": numbered,
            "start_line": start,
            "focus_line": focus,
            "available": True,
        }

    @staticmethod
    def _sarif_location(location: dict[str, Any]) -> tuple[str, int | None]:
        physical = location.get("physicalLocation") or {}
        artifact = physical.get("artifactLocation") or {}
        region = physical.get("region") or {}
        return clean(artifact.get("uri")), int_line(region.get("startLine"))

    @staticmethod
    def _load_sarif(path: Path) -> dict[str, Any] | None:
        try:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None

    def _sarif_path(self, row: dict[str, str]) -> Path | None:
        job = self._job(row, "after")
        raw = clean(job.get("after_sarif")) or clean(job.get("sarif_path"))
        if not raw:
            return None
        path = Path(raw)
        if not path.is_absolute():
            path = ROOT / path
        return path

    @staticmethod
    def _result_score(row: dict[str, str], result: dict[str, Any]) -> int:
        wanted_rule = clean(row.get("rule_id"))
        wanted_path = clean(row.get("file_path"))
        wanted_line = int_line(row.get("start_line"))
        wanted_message = clean(row.get("message"))
        wanted_fingerprint = clean(row.get("fingerprint"))
        if clean(result.get("ruleId")) != wanted_rule:
            return -1
        locations = result.get("locations") or []
        result_path, result_line = (
            ContextProvider._sarif_location(locations[0]) if locations else ("", None)
        )
        result_message = clean((result.get("message") or {}).get("text"))
        score = 0
        if wanted_fingerprint:
            fingerprints = result.get("partialFingerprints") or {}
            if isinstance(fingerprints, dict):
                normalized = {
                    clean(key): clean(value)
                    for key, value in fingerprints.items()
                    if clean(key) and clean(value)
                }
                result_fingerprint = json.dumps(
                    normalized, ensure_ascii=True, sort_keys=True
                )
                if result_fingerprint == wanted_fingerprint:
                    score += 20
        if result_path == wanted_path:
            score += 6
        if wanted_line and result_line == wanted_line:
            score += 4
        if result_message == wanted_message:
            score += 5
        elif wanted_message and (
            wanted_message in result_message or result_message in wanted_message
        ):
            score += 2
        return score

    @classmethod
    def _compact_sarif_trace(cls, result: dict[str, Any] | None) -> dict[str, Any]:
        if not result:
            return {
                "matched": False,
                "primary_line": None,
                "related": [],
                "codeflow": [],
            }
        locations = result.get("locations") or []
        _, primary_line = cls._sarif_location(locations[0]) if locations else ("", None)
        related: list[dict[str, Any]] = []
        for item in result.get("relatedLocations") or []:
            path, line = cls._sarif_location(item)
            if path:
                related.append(
                    {
                        "file": path,
                        "line": line,
                        "message": clean((item.get("message") or {}).get("text")),
                    }
                )
        codeflow: list[dict[str, Any]] = []
        for flow in result.get("codeFlows") or []:
            for thread in flow.get("threadFlows") or []:
                for item in thread.get("locations") or []:
                    location = item.get("location") or {}
                    path, line = cls._sarif_location(location)
                    if path:
                        codeflow.append(
                            {
                                "file": path,
                                "line": line,
                                "message": clean((location.get("message") or {}).get("text")),
                            }
                        )
                    if len(codeflow) >= 100:
                        break
        return {
            "matched": True,
            "primary_line": primary_line,
            "related": related[:30],
            "codeflow": codeflow,
        }

    def _load_case_sarif_traces(self, row: dict[str, str]) -> None:
        case_id = clean(row.get("case_id"))
        # Only protect the shared cache checks/updates. Parsing a very large
        # SARIF document while holding the global lock would freeze unrelated
        # context requests.
        with self.sarif_lock:
            if case_id in self.sarif_cases_loaded:
                return
        candidates = self.alert_rows_by_case.get(case_id) or [row]
        path = self._sarif_path(row)
        document = self._load_sarif(path) if path else None
        by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
        if document:
            for run in document.get("runs", []):
                for result in run.get("results", []):
                    by_rule[clean(result.get("ruleId"))].append(result)
        compact: dict[str, dict[str, Any]] = {}
        for candidate in candidates:
            alert_id = clean(candidate.get("alert_id"))
            best: tuple[int, dict[str, Any]] | None = None
            for result in by_rule.get(clean(candidate.get("rule_id")), []):
                score = self._result_score(candidate, result)
                if best is None or score > best[0]:
                    best = (score, result)
            matched = best[1] if best and best[0] >= 6 else None
            compact[alert_id] = self._compact_sarif_trace(matched)
        with self.sarif_lock:
            self.sarif_traces.update(compact)
            self.sarif_cases_loaded.add(case_id)

    def sarif_trace(self, row: dict[str, str]) -> dict[str, Any]:
        alert_id = clean(row.get("alert_id"))
        if alert_id not in self.sarif_traces:
            self._load_case_sarif_traces(row)
        return self.sarif_traces.get(
            alert_id,
            {"matched": False, "primary_line": None, "related": [], "codeflow": []},
        )

    def changed_files(self, row: dict[str, str]) -> list[str]:
        base = self._sha(row, "before")
        head = self._sha(row, "after")
        cache = self._cache_dir(row)
        if not (cache.is_dir() and base and head):
            return []
        env = dict(os.environ)
        env["GIT_NO_LAZY_FETCH"] = "1"
        try:
            result = subprocess.run(
                ["git", f"--git-dir={cache}", "diff", "--name-status", base, head],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        if result.returncode:
            return []
        return result.stdout.decode("utf-8", errors="replace").splitlines()[:300]

    def context(self, row: dict[str, str]) -> dict[str, Any]:
        path = safe_relative_path(clean(row.get("file_path")))
        sarif = self.sarif_trace(row)
        line = int_line(row.get("start_line"))
        if line is None:
            line = sarif.get("primary_line")
        before_text, before_source = self.read_revision_file(row, "before", path)
        head_text, head_source = self.read_revision_file(row, "after", path)
        before_path = path
        if before_source == "absent_at_revision" and head_text is not None:
            old_path = self.renamed_from(row, path)
            if old_path:
                renamed_text, renamed_source = self.read_revision_file(
                    row, "before", old_path
                )
                if renamed_text is not None:
                    before_text = renamed_text
                    before_source = f"{renamed_source}:renamed"
                    before_path = old_path
        diff, diff_source = self.file_diff(row, path, before_text, head_text)

        related_context: list[dict[str, Any]] = []
        seen = {path}
        related_locations = [*sarif["related"], *sarif["codeflow"]]
        for location in related_locations:
            other_path = clean(location.get("file"))
            if not other_path or other_path in seen:
                continue
            try:
                other_path = safe_relative_path(other_path)
            except ValueError:
                continue
            seen.add(other_path)
            other_before, _ = self.read_revision_file(row, "before", other_path)
            other_head, _ = self.read_revision_file(row, "after", other_path)
            other_diff, _ = self.file_diff(row, other_path, other_before, other_head)
            related_context.append(
                {
                    "file": other_path,
                    "line": location.get("line"),
                    "message": location.get("message", ""),
                    "head": self.snippet(other_head, location.get("line")),
                    "diff": other_diff,
                }
            )
            if len(related_context) >= 8:
                break
        before_snippet = self.snippet(before_text, line)
        before_snippet["source_state"] = before_source
        head_snippet = self.snippet(head_text, line)
        head_snippet["source_state"] = head_source
        return {
            "alert_line": line,
            "before": before_snippet,
            "head": head_snippet,
            "diff": diff,
            "diff_empty": not bool(diff.strip()),
            "sources": {
                "before": before_source,
                "head": head_source,
                "diff": diff_source,
            },
            "paths": {"before": before_path, "head": path},
            "sarif": sarif,
            "related_context": related_context,
            "changed_files": self.changed_files(row) if not diff.strip() else [],
        }


def public_item(row: dict[str, str], *, reveal: bool) -> dict[str, Any]:
    item = {
        "alert_id": clean(row.get("alert_id")),
        "issue_domain": clean(row.get("issue_domain")),
        "rule_id": clean(row.get("rule_id")),
        "rule_name": clean(row.get("rule_name")),
        "file_path": clean(row.get("file_path")),
        "start_line": int_line(row.get("start_line")),
        "message": clean(row.get("message")),
        "language": clean(row.get("language")),
    }
    if reveal:
        evidence: Any = []
        try:
            evidence = json.loads(clean(row.get("evidence_json")) or "[]")
        except json.JSONDecodeError:
            evidence = []
        item["model_comparison"] = {
            "group": clean(row.get("group")),
            "repo_name": clean(row.get("repo_name")),
            "pr_number": clean(row.get("pr_number")),
            "condition_present": clean(row.get("condition_present")),
            "introduced_by_pr": clean(row.get("introduced_by_pr")),
            "valid_issue": clean(row.get("valid_issue")),
            "actionability": clean(row.get("actionability")),
            "confidence": clean(row.get("confidence")),
            "precision": clean(row.get("precision")),
            "problem_severity": clean(row.get("problem_severity")),
            "quality_category": clean(row.get("quality_category")),
            "rationale": clean(row.get("rationale")),
            "evidence": evidence,
        }
    return item


def label_to_dict(label: sqlite3.Row | None) -> dict[str, Any]:
    if label is None:
        return {
            "status": "unreviewed",
            "disposition": "",
            "human_actionability": "",
            "confidence": "",
            "notes": "",
            "flagged": False,
            "revision": 0,
        }
    result = dict(label)
    result["flagged"] = bool(result["flagged"])
    return result


class ReviewStore:
    def __init__(
        self,
        database: Path,
        output_dir: Path,
        *,
        record_timestamps: bool = True,
    ) -> None:
        self.database = database
        self.output_dir = output_dir
        self.record_timestamps = record_timestamps

    def progress(self) -> dict[str, int]:
        with connect_db(self.database) as connection:
            total = connection.execute("SELECT COUNT(*) FROM items").fetchone()[0]
            counts = {
                row["status"]: row["n"]
                for row in connection.execute(
                    "SELECT status,COUNT(*) AS n FROM labels GROUP BY status"
                )
            }
        reviewed = counts.get("completed", 0)
        return {
            "total": total,
            "reviewed": reviewed,
            "remaining": total - reviewed,
            "completed": counts.get("completed", 0),
            "needs_followup": counts.get("needs_followup", 0),
            "deferred": counts.get("deferred", 0),
            "draft": counts.get("draft", 0),
        }

    def queue(self) -> list[dict[str, Any]]:
        with connect_db(self.database) as connection:
            rows = connection.execute(
                """
                SELECT i.alert_id,i.ordinal,COALESCE(l.status,'unreviewed') AS status,
                       COALESCE(l.disposition,'') AS disposition,
                       COALESCE(l.flagged,0) AS flagged
                FROM items i LEFT JOIN labels l USING(alert_id)
                ORDER BY i.ordinal
                """
            ).fetchall()
        return [
            {
                "alert_id": row["alert_id"],
                "ordinal": row["ordinal"],
                "status": row["status"],
                "disposition": row["disposition"],
                "flagged": bool(row["flagged"]),
            }
            for row in rows
        ]

    def get_item(self, alert_id: str) -> tuple[dict[str, str], sqlite3.Row | None, int]:
        with connect_db(self.database) as connection:
            row = connection.execute(
                """
                SELECT i.payload_json,i.ordinal,l.*
                FROM items i LEFT JOIN labels l USING(alert_id)
                WHERE i.alert_id=?
                """,
                (alert_id,),
            ).fetchone()
        if row is None:
            raise KeyError(alert_id)
        payload = json.loads(row["payload_json"])
        label = None
        if row["status"] is not None:
            label_keys = {
                "status",
                "disposition",
                "human_condition_present",
                "human_introduced_by_pr",
                "human_valid_issue",
                "human_actionability",
                "confidence",
                "notes",
                "flagged",
                "revision",
                "started_at",
                "submitted_at",
                "updated_at",
            }
            label = {key: row[key] for key in label_keys}
        return payload, label, row["ordinal"]

    def _write_label(
        self,
        alert_id: str,
        *,
        status: str,
        disposition: str,
        actionability: str,
        confidence: str,
        notes: str,
        flagged: bool,
        event_type: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        if status not in ALLOWED_STATUS:
            raise ValueError("invalid status")
        if disposition and disposition not in ALLOWED_DISPOSITIONS:
            raise ValueError("invalid disposition")
        if confidence not in ALLOWED_CONFIDENCE:
            raise ValueError("invalid confidence")
        if actionability and actionability not in ALLOWED_ACTIONABILITY:
            raise ValueError("invalid actionability")
        if disposition:
            condition, introduced, valid = derive_human_fields(disposition)
        else:
            condition = introduced = valid = ""
        if disposition == "confirmed_valid":
            actionability = actionability or "not_assessed"
            if actionability not in ALLOWED_ACTIONABILITY:
                raise ValueError("invalid actionability")
        else:
            actionability = "not_assessed"
        if len(notes) > 10_000:
            raise ValueError("notes are limited to 10,000 characters")
        now = utc_now() if self.record_timestamps else ""
        with connect_db(self.database) as connection:
            connection.execute("BEGIN IMMEDIATE")
            exists = connection.execute(
                "SELECT 1 FROM items WHERE alert_id=?", (alert_id,)
            ).fetchone()
            if not exists:
                raise KeyError(alert_id)
            prior = connection.execute(
                "SELECT revision,started_at FROM labels WHERE alert_id=?", (alert_id,)
            ).fetchone()
            current_revision = prior["revision"] if prior else 0
            if current_revision != expected_revision:
                raise ReviewConflictError(
                    "该告警已在另一个页面中更新；请刷新页面后再提交",
                    current_revision,
                )
            revision = current_revision + 1
            started_at = prior["started_at"] if prior and prior["started_at"] else now
            submitted_at = now if status in {"completed", "needs_followup"} else ""
            values = (
                alert_id,
                status,
                disposition,
                condition,
                introduced,
                valid,
                actionability,
                confidence,
                notes,
                int(flagged),
                revision,
                started_at,
                submitted_at,
                now,
            )
            connection.execute(
                """
                INSERT INTO labels(
                    alert_id,status,disposition,human_condition_present,
                    human_introduced_by_pr,human_valid_issue,human_actionability,
                    confidence,notes,flagged,revision,started_at,submitted_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    status=excluded.status,
                    disposition=excluded.disposition,
                    human_condition_present=excluded.human_condition_present,
                    human_introduced_by_pr=excluded.human_introduced_by_pr,
                    human_valid_issue=excluded.human_valid_issue,
                    human_actionability=excluded.human_actionability,
                    confidence=excluded.confidence,
                    notes=excluded.notes,
                    flagged=excluded.flagged,
                    revision=excluded.revision,
                    started_at=excluded.started_at,
                    submitted_at=excluded.submitted_at,
                    updated_at=excluded.updated_at
                """,
                values,
            )
            event_payload = {
                "status": status,
                "disposition": disposition,
                "human_actionability": actionability,
                "confidence": confidence,
                "notes": notes,
                "flagged": bool(flagged),
                "revision": revision,
            }
            connection.execute(
                "INSERT INTO events(alert_id,event_type,event_json,created_at) VALUES (?,?,?,?)",
                (
                    alert_id,
                    event_type,
                    json.dumps(event_payload, ensure_ascii=False, separators=(",", ":")),
                    now,
                ),
            )
        return event_payload

    def save(self, alert_id: str, body: dict[str, Any], *, submit: bool) -> dict[str, Any]:
        disposition = clean(body.get("disposition"))
        actionability = clean(body.get("human_actionability"))
        confidence = clean(body.get("confidence"))
        notes = clean(body.get("notes"))
        flagged = bool(body.get("flagged", False))
        try:
            expected_revision = int(body.get("expected_revision", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid expected_revision") from exc
        if submit:
            if not disposition:
                raise ValueError("choose a disposition before submitting")
            status = "needs_followup" if disposition == "uncertain" else "completed"
            event_type = "submit"
        else:
            status = "draft"
            event_type = "draft"
        return self._write_label(
            alert_id,
            status=status,
            disposition=disposition,
            actionability=actionability,
            confidence=confidence,
            notes=notes,
            flagged=flagged,
            event_type=event_type,
            expected_revision=expected_revision,
        )

    def defer(self, alert_id: str, body: dict[str, Any]) -> dict[str, Any]:
        disposition = clean(body.get("disposition"))
        actionability = clean(body.get("human_actionability")) or "not_assessed"
        try:
            expected_revision = int(body.get("expected_revision", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid expected_revision") from exc
        return self._write_label(
            alert_id,
            status="deferred",
            disposition=disposition,
            actionability=actionability,
            confidence=clean(body.get("confidence")),
            notes=clean(body.get("notes")),
            flagged=bool(body.get("flagged", False)),
            event_type="defer",
            expected_revision=expected_revision,
        )

    def export(self) -> tuple[Path, Path, Path]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        csv_path = self.output_dir / "human_labels.csv"
        events_path = self.output_dir / "label_events.jsonl"
        manifest_path = self.output_dir / "review_manifest.json"
        with connect_db(self.database) as connection:
            labels = connection.execute(
                """
                SELECT i.ordinal,i.alert_id,i.case_id,i.payload_json,
                       COALESCE(l.status,'unreviewed') AS status,
                       COALESCE(l.disposition,'') AS disposition,
                       COALESCE(l.human_condition_present,'') AS human_condition_present,
                       COALESCE(l.human_introduced_by_pr,'') AS human_introduced_by_pr,
                       COALESCE(l.human_valid_issue,'') AS human_valid_issue,
                       COALESCE(l.human_actionability,'') AS human_actionability,
                       COALESCE(l.confidence,'') AS confidence,
                       COALESCE(l.notes,'') AS notes,
                       COALESCE(l.flagged,0) AS flagged,
                       COALESCE(l.revision,0) AS revision,
                       COALESCE(l.started_at,'') AS started_at,
                       COALESCE(l.submitted_at,'') AS submitted_at,
                       COALESCE(l.updated_at,'') AS updated_at
                FROM items i LEFT JOIN labels l USING(alert_id)
                ORDER BY i.ordinal
                """
            ).fetchall()
            events = connection.execute(
                "SELECT * FROM events ORDER BY event_id"
            ).fetchall()
            metadata = {
                row["key"]: row["value"]
                for row in connection.execute("SELECT key,value FROM meta")
            }
        export_rows: list[dict[str, Any]] = []
        for label in labels:
            record = dict(label)
            payload_raw = record.pop("payload_json")
            payload = json.loads(payload_raw)
            payload_sha256 = hashlib.sha256(
                payload_raw.encode("utf-8")
            ).hexdigest()
            export_rows.append(
                {
                    "ordinal": record.pop("ordinal"),
                    "alert_id": record.pop("alert_id"),
                    "case_id": record.pop("case_id"),
                    "group": clean(payload.get("group")),
                    "repo_name": clean(payload.get("repo_name")),
                    "pr_number": clean(payload.get("pr_number")),
                    "rule_id": clean(payload.get("rule_id")),
                    "file_path": clean(payload.get("file_path")),
                    "start_line": clean(payload.get("start_line")),
                    "issue_domain": clean(payload.get("issue_domain")),
                    "source_group": clean(payload.get("source_group")),
                    "source_row_number": clean(payload.get("source_row_number")),
                    "input_payload_sha256": payload_sha256,
                    **record,
                }
            )
        fieldnames = list(export_rows[0].keys()) if export_rows else []
        temporary_csv = csv_path.with_suffix(".csv.tmp")
        with temporary_csv.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(export_rows)
        temporary_csv.replace(csv_path)
        temporary_events = events_path.with_suffix(".jsonl.tmp")
        with temporary_events.open("w", encoding="utf-8") as handle:
            for row in events:
                handle.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
        temporary_events.replace(events_path)
        existing_manifest: dict[str, Any] = {}
        if manifest_path.exists():
            try:
                loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    existing_manifest = loaded
            except (OSError, json.JSONDecodeError):
                existing_manifest = {}
        manifest = {
            **existing_manifest,
            **metadata,
            "exported_at": utc_now(),
            "progress": self.progress(),
            "database": str(self.database.resolve()),
            "outputs": {
                "human_labels": {
                    "path": str(csv_path.resolve()),
                    "sha256": sha256_file(csv_path),
                },
                "label_events": {
                    "path": str(events_path.resolve()),
                    "sha256": sha256_file(events_path),
                },
            },
        }
        temporary_manifest = manifest_path.with_suffix(".json.tmp")
        temporary_manifest.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary_manifest.replace(manifest_path)
        return csv_path, events_path, manifest_path


APP_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CodeQL 告警人工复核</title>
<style>
:root{--bg:#f4f7fb;--panel:#fff;--ink:#172033;--muted:#687386;--line:#d9e1ec;--blue:#2457d6;--green:#08795c;--amber:#b15d00;--red:#b42318;--shadow:0 8px 30px rgba(24,39,75,.07)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
button,select,textarea{font:inherit}.top{position:sticky;top:0;z-index:20;background:#fff;border-bottom:1px solid var(--line);padding:10px 18px;display:flex;align-items:center;gap:14px}.brand{font-weight:750;font-size:17px}.progress{flex:1;display:flex;align-items:center;gap:10px}.bar{height:8px;background:#e8edf5;border-radius:9px;overflow:hidden;flex:1}.bar i{display:block;height:100%;background:var(--blue);width:0}.top button,.nav button{border:1px solid var(--line);background:#fff;border-radius:8px;padding:7px 11px;cursor:pointer}.layout{display:grid;grid-template-columns:minmax(0,1fr) 345px;gap:14px;padding:14px;max-width:1780px;margin:auto}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}.main{min-width:0}.issue{padding:15px 18px;border-bottom:1px solid var(--line)}.eyebrow{font-size:12px;color:var(--muted);letter-spacing:.05em;text-transform:uppercase}.title{font-size:17px;font-weight:720;margin:4px 0}.message{background:#f7f9fc;border-left:3px solid var(--blue);padding:9px 11px;margin-top:9px;white-space:pre-wrap}.tags{display:flex;flex-wrap:wrap;gap:7px;margin-top:10px}.tag{padding:3px 8px;border-radius:20px;background:#edf3ff;color:#214da8}.tabs{display:flex;gap:2px;padding:8px 10px 0;border-bottom:1px solid var(--line)}.tab{border:0;background:transparent;padding:9px 12px;cursor:pointer;color:var(--muted);border-bottom:2px solid transparent}.tab.active{color:var(--blue);border-color:var(--blue);font-weight:650}.pane{display:none;padding:12px}.pane.active{display:block}.codegrid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.codebox h3{font-size:12px;color:var(--muted);margin:0 0 5px}.code{margin:0;white-space:pre;overflow:auto;max-height:64vh;background:#0f1724;color:#d7e1f0;border-radius:8px;padding:12px;font:12.5px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.diff{min-height:330px}.notice{padding:10px;border-radius:8px;background:#fff7e8;color:#7c4900;margin-bottom:10px}.trace-item{border:1px solid var(--line);border-radius:8px;padding:9px;margin:7px 0}.side{position:sticky;top:64px;align-self:start;padding:15px}.side h2{font-size:16px;margin:0 0 4px}.help{color:var(--muted);font-size:12px;margin-bottom:12px}.choices{display:grid;gap:8px}.choice{display:flex;text-align:left;align-items:flex-start;gap:9px;border:1px solid var(--line);background:#fff;border-radius:9px;padding:10px;cursor:pointer}.choice:hover{border-color:#8aa7eb}.choice.selected{border:2px solid var(--blue);background:#f1f5ff;padding:9px}.key{display:inline-grid;place-items:center;width:22px;height:22px;border-radius:5px;background:#e8edf5;font-size:12px;font-weight:700}.action{margin:12px 0;display:none}.action.show{display:block}.action select,.confidence select,textarea{width:100%;border:1px solid var(--line);border-radius:8px;padding:8px;background:#fff}.confidence{margin:10px 0}textarea{min-height:82px;resize:vertical}.row{display:flex;align-items:center;gap:8px;margin:9px 0}.submit{width:100%;border:0;border-radius:9px;background:var(--blue);color:#fff;padding:11px;font-weight:700;cursor:pointer}.submit:disabled{opacity:.45;cursor:not-allowed}.secondary{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}.secondary button{border:1px solid var(--line);background:#fff;border-radius:8px;padding:8px;cursor:pointer}.saved{font-size:12px;color:var(--green);min-height:18px;text-align:center;margin-top:6px}.comparison{display:none;margin-top:12px;border-top:1px solid var(--line);padding-top:12px}.comparison.show{display:block}.comparison summary{cursor:pointer;font-weight:650;color:#67410d}.comparison pre{white-space:pre-wrap;max-height:260px;overflow:auto;background:#fff9ec;padding:8px;border-radius:7px}.nav{display:flex;justify-content:space-between;gap:8px;padding:8px 14px 14px}.muted{color:var(--muted)}.loading{padding:50px;text-align:center;color:var(--muted)}
.nav{align-items:center}.jump{display:flex;align-items:center;gap:7px;color:var(--muted)}.jump input{width:76px;border:1px solid var(--line);border-radius:7px;padding:6px 7px;text-align:center;font:inherit}.jump input:invalid{border-color:var(--red);outline-color:var(--red)}
@media(max-width:1050px){.layout{grid-template-columns:1fr}.side{position:static}.codegrid{grid-template-columns:1fr}.code{max-height:42vh}}
</style>
</head>
<body>
<header class="top"><div class="brand">CodeQL 告警人工复核</div><div class="progress"><span id="progressText">加载中</span><div class="bar"><i id="progressBar"></i></div></div><select id="queueFilter" aria-label="审核队列"><option value="unfinished">未完成</option><option value="completed">已完成</option><option value="followup">待复核 / 暂缓</option><option value="all">全部状态</option></select><select id="dispositionFilter" aria-label="人工判定结果"><option value="all">全部判定</option><option value="condition_absent">代码条件不存在</option><option value="not_pr_introduced">不是当前 PR 引入</option><option value="not_valid_issue">不构成有效问题</option><option value="confirmed_valid">确认有效</option><option value="flagged">已标记</option></select><button id="exportBtn">导出 CSV</button></header>
<div class="layout">
  <main class="card main">
    <section class="issue" id="issue"><div class="loading">正在加载审核队列…</div></section>
    <div class="tabs">
      <button class="tab active" data-tab="diffPane">PR 差异</button>
      <button class="tab" data-tab="codePane">Before / Head</button>
      <button class="tab" data-tab="tracePane">CodeQL 路径</button>
      <button class="tab" data-tab="relatedPane">关联文件</button>
    </div>
    <section class="pane active" id="diffPane"><div class="loading">正在读取本地 Git 上下文…</div></section>
    <section class="pane" id="codePane"></section>
    <section class="pane" id="tracePane"></section>
    <section class="pane" id="relatedPane"></section>
    <nav class="nav"><button id="prevBtn">← 上一条 (B)</button><div class="jump"><label for="pageInput">第</label><input id="pageInput" type="number" min="1" step="1" inputmode="numeric" aria-label="输入要跳转的页码"><span>/ <span id="pageTotal">2495</span></span><button id="jumpBtn">跳转</button></div><button id="nextBtn">下一条 →</button></nav>
  </main>
  <aside class="card side">
    <h2>你的判断</h2><div class="help">全量复核完成前不显示 AI/Human 来源和模型结论。数字键选择，Enter 提交。</div>
    <div class="choices" id="choices">
      <button class="choice" data-value="confirmed_valid"><span class="key">1</span><span><b>确认是有效问题</b><br><small>条件存在、由本 PR 引入且构成问题</small></span></button>
      <button class="choice" data-value="condition_absent"><span class="key">2</span><span><b>代码条件不存在</b><br><small>CodeQL 描述与实际代码不符</small></span></button>
      <button class="choice" data-value="not_pr_introduced"><span class="key">3</span><span><b>不是本 PR 引入</b><br><small>条件存在，但已在基线中存在或仅被移动/暴露</small></span></button>
      <button class="choice" data-value="not_valid_issue"><span class="key">4</span><span><b>不构成有效问题</b><br><small>条件由 PR 引入，但在项目语境中合理</small></span></button>
      <button class="choice" data-value="uncertain"><span class="key">5</span><span><b>不确定，稍后复核</b><br><small>当前上下文不足以可靠判断</small></span></button>
    </div>
    <div class="action" id="actionBox"><label><b>修复优先级（可选）</b><select id="actionability"><option value="">暂不判断</option><option value="must_fix">Must fix</option><option value="should_fix">Should fix</option><option value="optional">Optional</option><option value="no_fix">No fix</option><option value="uncertain">Uncertain</option></select></label></div>
    <div class="confidence"><label>判断置信度（可选）<select id="confidence"><option value="">不填写</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label></div>
    <label>备注（可选）<textarea id="notes" placeholder="记录关键依据或需要进一步查看的内容"></textarea></label>
    <div class="row"><input id="flagged" type="checkbox"><label for="flagged">标记为需要深入检查</label></div>
    <button class="submit" id="submitBtn" disabled>保存并进入下一条 (Enter)</button>
    <div class="secondary"><button id="draftBtn">保存草稿</button><button id="deferBtn">暂缓 (S)</button></div>
    <div class="saved" id="saved"></div>
    <details class="comparison" id="comparison"><summary>全量审核完成后的模型裁决对照</summary><div id="comparisonBody"></div></details>
  </aside>
</div>
<script>
const state={queue:[],index:0,item:null,label:null,context:null,loading:false,saving:false,request:0};
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,options={}){const r=await fetch(path,{headers:{'Content-Type':'application/json'},...options});const text=await r.text();let body={};try{body=JSON.parse(text)}catch{body={error:text}}if(!r.ok)throw new Error(body.error||r.statusText);return body}
function activeFilter(q){const mode=$('queueFilter').value;const statusMatch=mode==='completed'?q.status==='completed':mode==='followup'?['needs_followup','deferred'].includes(q.status):mode==='all'?true:q.status!=='completed';const disposition=$('dispositionFilter').value;const dispositionMatch=disposition==='all'?true:disposition==='flagged'?q.flagged:q.disposition===disposition;return statusMatch&&dispositionMatch}
function filteredIndices(){const result=[];state.queue.forEach((q,index)=>{if(activeFilter(q))result.push(index)});return result}
function currentId(){return state.queue[state.index]?.alert_id}
function renderProgress(p){$('progressText').textContent=`已完成 ${p.reviewed} / ${p.total} · 剩余 ${p.remaining} · 待复核 ${p.needs_followup} · 暂缓 ${p.deferred}`;$('progressBar').style.width=`${p.total?100*p.reviewed/p.total:0}%`}
function setSelected(v){document.querySelectorAll('.choice').forEach(b=>b.classList.toggle('selected',b.dataset.value===v));$('actionBox').classList.toggle('show',v==='confirmed_valid');validate()}
function validate(){const v=document.querySelector('.choice.selected')?.dataset.value||'';const empty=!state.item;$('submitBtn').disabled=empty||!v||state.saving;$('draftBtn').disabled=empty||state.saving;$('deferBtn').disabled=empty||state.saving;$('prevBtn').disabled=empty;$('nextBtn').disabled=empty;$('jumpBtn').disabled=empty}
function form(){return{disposition:document.querySelector('.choice.selected')?.dataset.value||'',human_actionability:$('actionability').value,confidence:$('confidence').value,notes:$('notes').value,flagged:$('flagged').checked,expected_revision:state.label?.revision||0}}
function loadForm(label){document.querySelectorAll('.choice').forEach(b=>b.classList.remove('selected'));if(label?.disposition)setSelected(label.disposition);else setSelected('');$('actionability').value=label?.human_actionability==='not_assessed'?'':(label?.human_actionability||'');$('confidence').value=label?.confidence||'';$('notes').value=label?.notes||'';$('flagged').checked=!!label?.flagged;$('actionBox').classList.toggle('show',label?.disposition==='confirmed_valid');validate()}
function code(text,fallback='[内容不可用]'){return `<pre class="code">${esc(text||fallback)}</pre>`}
function revisionCode(snippet){if(snippet?.available)return code(snippet.text);if(snippet?.source_state==='absent_at_revision')return code('', '[该文件在此版本中不存在]');return code('', '[无法从本地缓存读取此版本内容]')}
function renderItem(data){state.item=data.item;state.label=data.label;const i=data.item;const indices=filteredIndices();const filteredPosition=indices.indexOf(state.index)+1;$('issue').innerHTML=`<div class="eyebrow">${esc(i.issue_domain||'CodeQL')} · ${esc(i.language)}</div><div class="title">${esc(i.rule_id)}${i.rule_name?' · '+esc(i.rule_name):''}</div><div class="message">${esc(i.message)}</div><div class="tags"><span class="tag">${esc(i.file_path)}${i.start_line?' : '+i.start_line:''}</span><span class="tag">全量序号：${data.ordinal}</span></div>`;$('pageInput').max=String(indices.length);$('pageInput').value=String(filteredPosition);$('pageTotal').textContent=String(indices.length);loadForm(data.label);renderComparison(i.model_comparison);}
function renderComparison(model){const box=$('comparison');if(!model){box.classList.remove('show');$('comparisonBody').innerHTML='';return}box.classList.add('show');$('comparisonBody').innerHTML=`<p><b>来源：</b>${esc(model.group)} · ${esc(model.repo_name)} #${esc(model.pr_number)}</p><p><b>模型：</b>condition=${esc(model.condition_present)}, introduced=${esc(model.introduced_by_pr)}, valid=${esc(model.valid_issue)}, actionability=${esc(model.actionability)}, confidence=${esc(model.confidence)}</p><p><b>precision/severity/category：</b>${esc(model.precision)} / ${esc(model.problem_severity)} / ${esc(model.quality_category)}</p><p><b>理由：</b></p><pre>${esc(model.rationale)}</pre><p><b>模型证据：</b></p><pre>${esc(JSON.stringify(model.evidence,null,2))}</pre>`}
function renderContext(c){state.context=c;const warn=c.diff_empty?`<div class="notice">告警所在文件在 base/head 间没有文本变化。请结合 CodeQL 关联路径、关联文件以及下方 PR 变更文件列表判断跨文件影响。</div>`:'';$('diffPane').innerHTML=warn+code(c.diff,'[该文件无文本差异]')+(c.changed_files?.length?`<h3>PR 变更文件</h3>${code(c.changed_files.join('\n'))}`:'');$('codePane').innerHTML=`<div class="codegrid"><div class="codebox"><h3>BEFORE · ${esc(c.paths?.before||'')} · ${esc(c.sources.before)}</h3>${revisionCode(c.before)}</div><div class="codebox"><h3>HEAD · ${esc(c.paths?.head||'')} · ${esc(c.sources.head)}</h3>${revisionCode(c.head)}</div></div>`;const rel=c.sarif.related||[],flow=c.sarif.codeflow||[];$('tracePane').innerHTML=`<h3>Related locations</h3>${rel.length?rel.map(x=>`<div class="trace-item"><b>${esc(x.file)}:${esc(x.line||'?')}</b><br>${esc(x.message)}</div>`).join(''):'<p class="muted">无 relatedLocations 或未匹配原始 SARIF。</p>'}<h3>Code flow</h3>${flow.length?flow.map((x,n)=>`<div class="trace-item"><b>${n+1}. ${esc(x.file)}:${esc(x.line||'?')}</b><br>${esc(x.message)}</div>`).join(''):'<p class="muted">该告警没有 CodeQL code flow。</p>'}`;$('relatedPane').innerHTML=c.related_context?.length?c.related_context.map(x=>`<div class="trace-item"><b>${esc(x.file)}:${esc(x.line||'?')}</b> ${esc(x.message)}</div>${x.diff?code(x.diff):revisionCode(x.head)}`).join(''):'<p class="muted">没有额外关联文件上下文。</p>'}
async function load(index){if(!state.queue.length)return;const token=++state.request;state.loading=true;state.index=Math.max(0,Math.min(index,state.queue.length-1));const id=currentId();$('diffPane').innerHTML='<div class="loading">正在读取本地 Git 上下文…</div>';$('codePane').innerHTML='';$('tracePane').innerHTML='';$('relatedPane').innerHTML='';try{const data=await api(`/api/items/${encodeURIComponent(id)}`);if(token!==state.request)return;renderItem(data);const c=await api(`/api/items/${encodeURIComponent(id)}/context`);if(token!==state.request)return;renderContext(c.context);history.replaceState(null,'',`#${encodeURIComponent(id)}`)}catch(e){if(token===state.request)$('diffPane').innerHTML=`<div class="notice">加载失败：${esc(e.message)}</div>`}finally{if(token===state.request)state.loading=false}}
function renderEmpty(){++state.request;state.item=null;state.label=null;state.context=null;state.loading=false;$('issue').innerHTML='<div class="loading">当前筛选条件下没有告警。</div>';$('diffPane').innerHTML='<div class="loading">请切换右上角的审核队列。</div>';$('codePane').innerHTML='';$('tracePane').innerHTML='';$('relatedPane').innerHTML='';$('pageInput').value='';$('pageInput').max='0';$('pageTotal').textContent='0';document.querySelectorAll('.choice').forEach(b=>b.classList.remove('selected'));renderComparison(null);validate()}
function findNext(direction=1){const indices=filteredIndices();if(!indices.length)return null;const position=indices.indexOf(state.index);if(position<0)return direction<0?indices[indices.length-1]:indices[0];return indices[(position+direction+indices.length)%indices.length]}
function jumpToPage(){const input=$('pageInput');const indices=filteredIndices();const page=Number(input.value);if(!Number.isInteger(page)||page<1||page>indices.length){input.setCustomValidity(`请输入 1 到 ${indices.length} 之间的整数`);input.reportValidity();return}input.setCustomValidity('');$('saved').textContent='';load(indices[page-1])}
async function applyFilter(preferredIndex=null){const indices=filteredIndices();if(!indices.length){renderEmpty();return}if(preferredIndex!==null&&indices.includes(preferredIndex)){await load(preferredIndex);return}await load(indices[0])}
async function refresh(){const d=await api('/api/queue');state.queue=d.queue;renderProgress(d.progress);if(d.progress.remaining===0&&$('queueFilter').value==='unfinished')$('queueFilter').value='completed';const hash=decodeURIComponent(location.hash.slice(1));const hashedIndex=state.queue.findIndex(x=>x.alert_id===hash);await applyFilter(hashedIndex>=0?hashedIndex:null)}
async function save(kind){if(!state.item||state.saving)return;const alertId=state.item.alert_id;const oldIndex=state.index;state.saving=true;validate();try{const body=form();const d=await api(`/api/items/${encodeURIComponent(alertId)}/${kind}`,{method:'POST',body:JSON.stringify(body)});$('saved').textContent='已保存';const q=state.queue.find(x=>x.alert_id===alertId);if(q){q.status=d.label.status;q.disposition=d.label.disposition;q.flagged=d.label.flagged}renderProgress(d.progress);const indices=filteredIndices();if(indices.includes(oldIndex)&&kind==='draft'){state.label=d.label;loadForm(d.label)}else if(indices.length){const after=indices.find(i=>i>oldIndex);await load(after??indices[0])}else{renderEmpty()}}catch(e){$('saved').textContent=`保存失败：${e.message}`}finally{state.saving=false;validate()}}
document.querySelectorAll('.choice').forEach(b=>b.addEventListener('click',()=>setSelected(b.dataset.value)));$('actionability').addEventListener('change',validate);$('submitBtn').addEventListener('click',()=>save('submit'));$('draftBtn').addEventListener('click',()=>save('draft'));$('deferBtn').addEventListener('click',()=>save('defer'));$('prevBtn').addEventListener('click',()=>{const index=findNext(-1);if(index!==null)load(index)});$('nextBtn').addEventListener('click',()=>{const index=findNext(1);if(index!==null)load(index)});$('jumpBtn').addEventListener('click',jumpToPage);$('pageInput').addEventListener('input',e=>e.currentTarget.setCustomValidity(''));$('pageInput').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();jumpToPage()}});$('queueFilter').addEventListener('change',()=>applyFilter());$('dispositionFilter').addEventListener('change',()=>applyFilter());$('exportBtn').addEventListener('click',async()=>{try{const d=await api('/api/export',{method:'POST',body:'{}'});$('saved').textContent=`已导出 ${d.csv}`;location.href='/api/export.csv'}catch(e){$('saved').textContent=e.message}});document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===b));document.querySelectorAll('.pane').forEach(x=>x.classList.toggle('active',x.id===b.dataset.tab))}));document.addEventListener('keydown',e=>{if(['TEXTAREA','SELECT','INPUT'].includes(document.activeElement.tagName))return;if(e.key>='1'&&e.key<='5'){const b=document.querySelectorAll('.choice')[Number(e.key)-1];setSelected(b.dataset.value)}else if(e.key==='Enter'&&!$('submitBtn').disabled)save('submit');else if(e.key.toLowerCase()==='b'){const index=findNext(-1);if(index!==null)load(index)}else if(e.key.toLowerCase()==='s')save('defer')});refresh().catch(e=>$('issue').innerHTML=`<div class="notice">${esc(e.message)}</div>`);
</script>
</body></html>"""


class ReviewServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        store: ReviewStore,
        contexts: ContextProvider,
    ) -> None:
        super().__init__(address, handler)
        self.store = store
        self.contexts = contexts


class ReviewHandler(BaseHTTPRequestHandler):
    server: ReviewServer

    def version_string(self) -> str:
        return "CodeQLReviewUI/1"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))

    def _json(self, body: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, status: HTTPStatus, message: str) -> None:
        self._json({"error": message}, status)

    def _body(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            raise ValueError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length > 100_000:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def _item_parts(self) -> tuple[str, str] | None:
        path = urllib.parse.urlparse(self.path).path
        prefix = "/api/items/"
        if not path.startswith(prefix):
            return None
        tail = path[len(prefix) :]
        parts = tail.split("/", 1)
        return urllib.parse.unquote(parts[0]), parts[1] if len(parts) > 1 else ""

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/":
                payload = APP_HTML.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Frame-Options", "DENY")
                self.end_headers()
                self.wfile.write(payload)
                return
            if path == "/api/queue":
                self._json(
                    {
                        "queue": self.server.store.queue(),
                        "progress": self.server.store.progress(),
                    }
                )
                return
            if path == "/favicon.ico":
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/api/export.csv":
                csv_path, _, _ = self.server.store.export()
                payload = csv_path.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header(
                    "Content-Disposition", 'attachment; filename="human_labels.csv"'
                )
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            parts = self._item_parts()
            if parts:
                alert_id, operation = parts
                row, label, ordinal = self.server.store.get_item(alert_id)
                if operation == "context":
                    self._json({"context": self.server.contexts.context(row)})
                    return
                if operation:
                    self._error(HTTPStatus.NOT_FOUND, "unknown item endpoint")
                    return
                label_dict = label_to_dict(label)
                reveal = self.server.store.progress()["remaining"] == 0
                self._json(
                    {
                        "item": public_item(row, reveal=reveal),
                        "label": label_dict,
                        "ordinal": ordinal,
                    }
                )
                return
            self._error(HTTPStatus.NOT_FOUND, "not found")
        except KeyError:
            self._error(HTTPStatus.NOT_FOUND, "unknown alert_id")
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:  # pragma: no cover - last-resort HTTP boundary
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"internal error: {exc}")

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/api/export":
                csv_path, events_path, manifest_path = self.server.store.export()
                self._json(
                    {
                        "csv": str(csv_path),
                        "events": str(events_path),
                        "manifest": str(manifest_path),
                    }
                )
                return
            parts = self._item_parts()
            if not parts:
                self._error(HTTPStatus.NOT_FOUND, "not found")
                return
            alert_id, operation = parts
            body = self._body()
            if operation == "submit":
                label = self.server.store.save(alert_id, body, submit=True)
            elif operation == "draft":
                label = self.server.store.save(alert_id, body, submit=False)
            elif operation == "defer":
                label = self.server.store.defer(alert_id, body)
            else:
                self._error(HTTPStatus.NOT_FOUND, "unknown item endpoint")
                return
            self._json({"label": label, "progress": self.server.store.progress()})
        except ReviewConflictError as exc:
            self._json(
                {"error": str(exc), "current_revision": exc.current_revision},
                HTTPStatus.CONFLICT,
            )
        except KeyError:
            self._error(HTTPStatus.NOT_FOUND, "unknown alert_id")
        except (ValueError, json.JSONDecodeError) as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:  # pragma: no cover - last-resort HTTP boundary
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"internal error: {exc}")


def write_initial_manifest(
    output_dir: Path,
    *,
    input_path: Path,
    seed: int,
    item_n: int,
    review_scope: str = "complete_model_retained_census",
    per_alert_timestamps_recorded: bool = True,
) -> Path:
    if review_scope == "model_excluded_probability_sample":
        method_boundary = (
            "This review covers a frozen stratified probability sample of alerts "
            "excluded by the model adjudicator. Design weights from the sample CSV "
            "must be used to estimate alert-level false omission and screening "
            "sensitivity; the sample does not directly correct PR-level prevalence."
        )
    elif review_scope == "model_excluded_full_census":
        method_boundary = (
            "This review covers the complete frozen census of 4,629 alerts excluded "
            "by the model adjudicator. The prior 400-alert probability-audit decisions "
            "are imported as final human labels, and the remaining 4,229 alerts receive "
            "the same disposition-based human review. The model screen is auxiliary and "
            "does not define the final human-confirmed outcome."
        )
    elif review_scope == "independent_full_rereview_2379":
        method_boundary = (
            "This independent re-review covers all 2,379 alerts confirmed by two source "
            "reviewers. Reviewer A reviewed the model-retained census and confirmed "
            "2,246 alerts; Reviewer B reviewed the model-excluded census and confirmed "
            "133 alerts. Their labels, notes, and the model judgments are hidden from "
            "Reviewer C. Because both source labels are fixed to confirmed_valid, this "
            "review estimates Reviewer C's confirmation and disagreement rates; the "
            "separate outcome-stratified 200-alert audit remains the source of Cohen's "
            "kappa estimates."
        )
    else:
        method_boundary = (
            "This census checks the 2,495 model-retained alerts. It estimates confirmation "
            "within that retained set and does not estimate false negatives among alerts "
            "excluded by the model adjudicator."
        )
    manifest = {
        "schema_version": 1,
        "created_at": utc_now(),
        "review_scope": review_scope,
        "input": {
            "path": str(input_path.resolve()),
            "sha256": sha256_file(input_path),
            "rows": item_n,
        },
        "review_order_seed": seed,
        "per_alert_timestamps_recorded": per_alert_timestamps_recorded,
        "blinding": {
            "design": (
                "Provenance labels and model judgments are hidden until every alert has "
                "a final decision. Repository identity may still be inferable from code "
                "and paths, so this is not claimed as strict provenance blinding."
            ),
            "hidden_until_full_completion": [
                "group",
                "repository",
                "PR number",
                "case id",
                "task type",
                "model judgments",
                "model confidence",
                "model rationale",
                "model evidence",
                "CodeQL precision and severity",
            ],
            "visible": [
                "CodeQL rule and message",
                "base/head source",
                "file diff",
                "original SARIF related locations and code flow",
            ],
        },
        "decision_codebook": {
            "confirmed_valid": "condition present; introduced by PR; valid issue",
            "condition_absent": "CodeQL-described condition is not present",
            "not_pr_introduced": "condition present but not introduced by pending PR",
            "not_valid_issue": "condition present and introduced but not a valid issue in context",
            "uncertain": "available context is insufficient for a reliable decision",
        },
        "method_boundary": method_boundary,
    }
    path = output_dir / "review_manifest.json"
    if not path.exists():
        path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--ai-jobs", type=Path, default=DEFAULT_AI_JOBS)
    parser.add_argument("--human-jobs", type=Path, default=DEFAULT_HUMAN_JOBS)
    parser.add_argument("--ai-cache-dir", type=Path, default=DEFAULT_AI_CACHE)
    parser.add_argument("--human-cache-dir", type=Path, default=DEFAULT_HUMAN_CACHE)
    parser.add_argument("--seed", type=int, default=20260812)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--omit-review-timestamps",
        action="store_true",
        help=(
            "store empty per-alert started/submitted/updated/event time fields; "
            "administrative file metadata is unaffected"
        ),
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="permit a non-loopback bind (unsafe without an external access-control layer)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if args.host not in {"127.0.0.1", "localhost", "::1"} and not args.allow_remote:
        raise SystemExit(
            "Refusing non-loopback bind. Use SSH/VS Code port forwarding, or pass "
            "--allow-remote only behind an authenticated access-control layer."
        )
    paths = [args.input, args.ai_jobs, args.human_jobs]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise SystemExit("Missing required file(s): " + ", ".join(missing))
    rows = read_csv(args.input)
    declared_scopes = {
        clean(row.get("verification_audit_scope")) for row in rows
        if clean(row.get("verification_audit_scope"))
    }
    if len(declared_scopes) > 1:
        raise SystemExit(
            "Input contains multiple verification_audit_scope values: "
            + ", ".join(sorted(declared_scopes))
        )
    review_scope = (
        next(iter(declared_scopes))
        if declared_scopes
        else "complete_model_retained_census"
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    database = args.output_dir / "review.sqlite3"
    initialize_database(database, args.input, rows, seed=args.seed)
    backup = backup_database(database, args.output_dir)
    write_initial_manifest(
        args.output_dir,
        input_path=args.input,
        seed=args.seed,
        item_n=len(rows),
        review_scope=review_scope,
        per_alert_timestamps_recorded=not args.omit_review_timestamps,
    )
    store = ReviewStore(
        database,
        args.output_dir,
        record_timestamps=not args.omit_review_timestamps,
    )
    contexts = ContextProvider(
        ai_jobs=args.ai_jobs,
        human_jobs=args.human_jobs,
        ai_cache=args.ai_cache_dir,
        human_cache=args.human_cache_dir,
        alert_rows=rows,
    )
    try:
        server = ReviewServer(
            (args.host, args.port), ReviewHandler, store=store, contexts=contexts
        )
    except OSError as exc:
        if exc.errno == errno.EACCES:
            detail = (
                "服务器拒绝监听该端口；本机要求使用大于 20024 的用户端口，"
                "请例如传入 --port 30000"
            )
        elif exc.errno == errno.EADDRINUSE:
            detail = "端口已被占用；请例如传入 --port 30000"
        else:
            detail = str(exc)
        raise SystemExit(
            f"无法启动复核面板（{args.host}:{args.port}）：{detail}"
        ) from None
    progress = store.progress()
    print(
        f"CodeQL 人工复核面板已启动：http://{args.host}:{args.port}\n"
        f"进度：{progress['reviewed']}/{progress['total']}；结果：{args.output_dir}\n"
        f"远程服务器请使用 VS Code Ports 转发 {args.port}，或执行：\n"
        f"  ssh -L {args.port}:127.0.0.1:{args.port} <user>@<server>\n"
        f"然后在本机打开 http://127.0.0.1:{args.port}\n"
        "按 Ctrl+C 安全停止；每次点击都会立即写入 SQLite。",
        flush=True,
    )
    if backup:
        print(f"启动前备份：{backup}", flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\n正在导出最新人工标签…", flush=True)
    finally:
        server.server_close()
        csv_path, _, _ = store.export()
        print(f"已停止；最新标签：{csv_path}", flush=True)


if __name__ == "__main__":
    main()
