#!/usr/bin/env python3
"""Run resumable, provenance-blinded model adjudication of CodeQL alerts.

The command consumes a frame produced by
``prepare_codeql_alert_adjudication.py``.  It reconstructs one neutral PR
worktree at a time, executes one or more bounded alert batches, validates each
response without JSON repair, and removes the scratch worktree before moving
to the next PR.  Without ``--execute`` it performs an offline worktree and
prompt preflight only.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import csv
import fcntl
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Iterable
from urllib.parse import urlparse

from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, ResultMessage, query

import build_codeql_adjudication_worktree as worktree_builder
import codeql_alert_adjudication_protocol as protocol
import run_claude_code_review as sdk_review


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "1.0.0"
STATUS_FIELDS = (
    "batch_id",
    "case_id",
    "status",
    "attempts",
    "last_error",
    "total_cost_usd",
    "updated_at",
)
COMPATIBLE_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,199}$")
MAX_LINE_READ_FILE_BYTES = 256 * 1024


class AdjudicationRunError(ValueError):
    """Raised when execution would violate the frozen run protocol."""


def maximize_csv_field_limit() -> None:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


maximize_csv_field_limit()


def parse_args() -> argparse.Namespace:
    base = "data/experiments/security-and-quality/study_stars500"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--frame-dir",
        type=Path,
        default=f"{base}/reports/codeql_alert_adjudication_20260804_v5/frame",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--scratch-dir",
        type=Path,
        help="Temporary worktrees; defaults to OUTPUT_DIR/scratch and is cleaned per PR.",
    )
    parser.add_argument(
        "--ai-jobs", type=Path, default=f"{base}/ai/codeql_jobs.csv"
    )
    parser.add_argument(
        "--human-jobs", type=Path, default=f"{base}/human/codeql_jobs.csv"
    )
    parser.add_argument(
        "--ai-cache-dir", type=Path, default=f"{base}/ai/repos/.cache"
    )
    parser.add_argument(
        "--human-cache-dir", type=Path, default=f"{base}/human/repos/.cache"
    )
    parser.add_argument(
        "--prompt",
        type=Path,
        default="config/study/codeql_alert_adjudication_prompt.txt",
    )
    parser.add_argument(
        "--output-schema",
        type=Path,
        default="config/study/codeql_alert_adjudication_output_schema.json",
    )
    parser.add_argument(
        "--provider",
        choices=(*tuple(sdk_review.PROVIDER_DEFAULTS), "compatible"),
        default="deepseek",
    )
    parser.add_argument("--base-url")
    parser.add_argument("--api-key-env")
    parser.add_argument("--model")
    parser.add_argument(
        "--effort", choices=("low", "medium", "high", "xhigh", "max"), default="max"
    )
    parser.add_argument("--max-budget-usd", type=float, default=10.0)
    parser.add_argument("--max-turns", type=int, default=20)
    parser.add_argument(
        "--max-tool-calls",
        type=int,
        help=(
            "Optional maximum number of read-only tool calls per batch. "
            "Omit this option to impose no separate tool-call limit; "
            "max-turns and the read-only policy still apply."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Maximum PR worktrees/model invocations processed concurrently.",
    )
    parser.add_argument("--worktree-timeout", type=float, default=900)
    parser.add_argument("--case-id", action="append", dest="case_ids")
    parser.add_argument("--batch-id", action="append", dest="batch_ids")
    parser.add_argument("--limit-batches", type=int)
    parser.add_argument(
        "--resume", action="store_true", help="Resume pending/failed batches."
    )
    parser.add_argument(
        "--allow-protocol-amendment",
        "--allow-bounded-to-unbounded-amendment",
        dest="allow_bounded_to_unbounded_amendment",
        action="store_true",
        help=(
            "Allow a narrowly audited in-place protocol amendment, including "
            "removing a separate tool-call cap or increasing max-turns for "
            "persistent recovery cases. Existing completed batches are retained "
            "and the prior run config is archived."
        ),
    )
    parser.add_argument(
        "--stop-on-failure",
        action="store_true",
        help="Stop after the first worktree, API, or validation failure.",
    )
    parser.add_argument(
        "--failure-limit",
        type=int,
        help="Stop this invocation after this many independent failed PR cases.",
    )
    parser.add_argument(
        "--keep-failed-worktree",
        action="store_true",
        help="Retain only the most recent failed case scratch tree for debugging.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Make real model calls; otherwise run offline preflight only.",
    )
    return parser.parse_args()


class BoundedReadOnlyHook:
    """Enforce the read-only policy and an optional tool-call budget."""

    def __init__(
        self,
        limit: int | None = None,
        *,
        repo: Path | None = None,
        max_read_file_bytes: int = MAX_LINE_READ_FILE_BYTES,
    ) -> None:
        self.limit = limit
        self.repo = repo.resolve() if repo is not None else None
        self.max_read_file_bytes = max_read_file_bytes
        self.allowed_calls = 0
        self.denied_for_budget = 0
        self.denied_for_policy = 0
        self.denied_for_oversized_read = 0

    async def __call__(
        self, hook_input: dict[str, Any], _tool_use_id: str | None, _context: Any
    ) -> dict[str, Any]:
        tool_name = clean(hook_input.get("tool_name"))
        tool_input = hook_input.get("tool_input")
        tool_input = tool_input if isinstance(tool_input, dict) else {}
        read_only = tool_name in {"Read", "Glob", "Grep"} or (
            tool_name == "Bash"
            and sdk_review.is_read_only_bash(clean(tool_input.get("command")))
        )
        if not read_only:
            self.denied_for_policy += 1
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        f"Frozen adjudication denies non-read-only tool use: {tool_name}"
                    ),
                }
            }
        if tool_name == "Read" and self.repo is not None:
            raw_path = clean(tool_input.get("file_path"))
            candidate = Path(raw_path)
            if not candidate.is_absolute():
                candidate = self.repo / candidate
            try:
                resolved = candidate.resolve()
                resolved.relative_to(self.repo)
            except (OSError, ValueError):
                resolved = None
            if (
                resolved is not None
                and resolved.is_file()
                and resolved.stat().st_size > self.max_read_file_bytes
            ):
                self.denied_for_oversized_read += 1
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            "The requested file is too large for the line-oriented "
                            "Read tool. Use focused Grep or a bounded read-only Bash "
                            "command such as head -c; do not read the whole file."
                        ),
                    }
                }
        if self.limit is not None and self.allowed_calls >= self.limit:
            self.denied_for_budget += 1
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        "The frozen adjudication inspection budget is exhausted. "
                        "Do not request another tool. Return the complete final JSON "
                        "now, using uncertain where evidence remains insufficient."
                    ),
                }
            }
        self.allowed_calls += 1
        reason = (
            "Within the configured read-only budget."
            if self.limit is not None
            else "Read-only adjudication tool use is allowed."
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": reason,
            }
        }


def resolve(path: Path) -> Path:
    return path.expanduser().resolve() if path.is_absolute() else (ROOT / path).resolve()


def clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise AdjudicationRunError(f"invalid JSON file {path}: {exc}") from None
    if not isinstance(value, dict):
        raise AdjudicationRunError(f"JSON file must contain an object: {path}")
    return value


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def atomic_status(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=STATUS_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        temporary = Path(handle.name)
    temporary.replace(path)


def verify_frame(frame_dir: Path) -> dict[str, Any]:
    manifest = read_json(frame_dir / "manifest.json")
    for filename, record in manifest.get("outputs", {}).items():
        path = frame_dir / filename
        if not path.is_file() or sha256_file(path) != record.get("sha256"):
            raise AdjudicationRunError(f"frame output hash mismatch: {filename}")
    return manifest


def load_frame(frame_dir: Path) -> tuple[
    dict[str, dict[str, str]],
    dict[str, dict[str, str]],
    list[dict[str, str]],
]:
    cases = read_csv(frame_dir / "adjudication_prs.csv")
    alerts = read_csv(frame_dir / "adjudication_alerts.csv")
    batches = read_csv(frame_dir / "adjudication_batches.csv")
    case_by_id = {row["case_id"]: row for row in cases}
    alert_by_id = {row["alert_id"]: row for row in alerts}
    if len(case_by_id) != len(cases) or len(alert_by_id) != len(alerts):
        raise AdjudicationRunError("frame contains duplicate case or alert IDs")
    batch_ids: set[str] = set()
    covered: list[str] = []
    for batch in batches:
        batch_id = clean(batch.get("batch_id"))
        case_id = clean(batch.get("case_id"))
        if not batch_id or batch_id in batch_ids or case_id not in case_by_id:
            raise AdjudicationRunError("frame contains invalid/duplicate batch IDs")
        batch_ids.add(batch_id)
        try:
            ids = json.loads(batch["alert_ids_json"])
        except json.JSONDecodeError:
            raise AdjudicationRunError(f"batch alert list is invalid: {batch_id}") from None
        if not isinstance(ids, list) or len(ids) != int(batch["batch_alert_n"]):
            raise AdjudicationRunError(f"batch alert count mismatch: {batch_id}")
        for alert_id in ids:
            if alert_id not in alert_by_id:
                raise AdjudicationRunError(f"batch references unknown alert: {alert_id}")
            if alert_by_id[alert_id]["case_id"] != case_id:
                raise AdjudicationRunError(f"batch mixes PR cases: {batch_id}")
        covered.extend(ids)
    if len(covered) != len(set(covered)) or set(covered) != set(alert_by_id):
        raise AdjudicationRunError("batches do not partition all frame alerts")
    return case_by_id, alert_by_id, batches


def selected_batches(
    batches: list[dict[str, str]],
    *,
    case_ids: list[str] | None,
    batch_ids: list[str] | None,
    limit: int | None,
    statuses: dict[str, dict[str, str]],
    execute: bool,
) -> list[dict[str, str]]:
    available_cases = {row["case_id"] for row in batches}
    available_batches = {row["batch_id"] for row in batches}
    requested_cases = set(case_ids or [])
    requested_batches = set(batch_ids or [])
    if requested_cases - available_cases:
        raise AdjudicationRunError(
            f"unknown case IDs: {sorted(requested_cases - available_cases)}"
        )
    if requested_batches - available_batches:
        raise AdjudicationRunError(
            f"unknown batch IDs: {sorted(requested_batches - available_batches)}"
        )
    rows = [
        row
        for row in batches
        if (not requested_cases or row["case_id"] in requested_cases)
        and (not requested_batches or row["batch_id"] in requested_batches)
        and (
            not execute
            or statuses[row["batch_id"]]["status"] not in {"completed"}
        )
    ]
    if limit is not None:
        if limit < 1:
            raise AdjudicationRunError("limit-batches must be positive")
        rows = rows[:limit]
    return rows


def redact(text: str, api_key_env: str) -> str:
    secret = os.environ.get(api_key_env, "")
    return text.replace(secret, "[REDACTED]") if secret else text


def validate_compatible_base_url(value: str | None) -> str:
    raw = clean(value).rstrip("/")
    if not raw:
        raise AdjudicationRunError("compatible provider requires --base-url")
    parsed = urlparse(raw)
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme not in ({"http", "https"} if loopback else {"https"}):
        raise AdjudicationRunError(
            "compatible base URL must use HTTPS (HTTP is allowed only for loopback)"
        )
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AdjudicationRunError(
            "compatible base URL must not contain credentials, query, or fragment"
        )
    return raw


def resolve_adjudication_provider_config(args: argparse.Namespace) -> dict[str, str]:
    if args.provider != "compatible":
        model = args.model or (
            "deepseek-v4-pro[1m]" if args.provider == "deepseek" else ""
        )
        if not model:
            raise AdjudicationRunError("Anthropic provider requires --model")
        return sdk_review.resolve_provider_config(
            provider=args.provider,
            model=model,
            base_url=args.base_url,
            api_key_env=args.api_key_env,
            execute=args.execute,
        )

    model = clean(args.model)
    if not COMPATIBLE_MODEL_RE.fullmatch(model):
        raise AdjudicationRunError(
            "compatible provider requires a safe non-empty --model identifier"
        )
    api_key_env = sdk_review.validate_api_key_env(
        clean(args.api_key_env) or "MODEL_API_KEY", args.execute
    )
    return {
        "provider": "compatible",
        "base_url": validate_compatible_base_url(args.base_url),
        "requested_model": model,
        "resolved_backend_model": model,
        "api_key_env": api_key_env,
        "api_protocol": "anthropic-compatible",
    }


def build_adjudication_runtime_env(provider_config: dict[str, str]) -> dict[str, str]:
    if provider_config["provider"] != "compatible":
        return sdk_review.build_provider_runtime_env(provider_config)
    secret = os.environ.get(provider_config["api_key_env"])
    if not secret:
        raise AdjudicationRunError(
            f"execution requires {provider_config['api_key_env']}"
        )
    return {
        "ANTHROPIC_BASE_URL": provider_config["base_url"],
        "ANTHROPIC_MODEL": provider_config["requested_model"],
        "ANTHROPIC_AUTH_TOKEN": secret,
        "ANTHROPIC_API_KEY": secret,
    }


def attempt_directory(batch_root: Path, attempt: int) -> tuple[Path, int]:
    """Allocate the next unused attempt directory after an interrupted run.

    A process can be interrupted after creating an attempt directory but before
    persisting the new attempt number in ``batch_status.csv``.  Such an orphan
    is immutable audit evidence, so retain it and advance to the next number.
    """

    batch_root.mkdir(parents=True, exist_ok=True)
    requested_attempt = attempt
    skipped: list[str] = []
    while True:
        path = batch_root / f"attempt-{attempt:03d}"
        try:
            path.mkdir()
            break
        except FileExistsError:
            skipped.append(path.name)
            attempt += 1
    if skipped:
        atomic_json(
            path / "resume_recovery.json",
            {
                "schema_version": SCHEMA_VERSION,
                "recovered_at": datetime.now(timezone.utc).isoformat(),
                "requested_attempt": requested_attempt,
                "allocated_attempt": attempt,
                "retained_existing_attempt_directories": skipped,
                "reason": (
                    "existing attempt directory was retained after status lag or "
                    "process interruption"
                ),
            },
        )
    return path, attempt


def register_failure_unit(
    failure_units: set[str], failure_unit: str, limit: int | None
) -> tuple[bool, bool]:
    """Register one independent failure and report whether it opened the circuit."""

    if failure_unit in failure_units:
        return False, False
    failure_units.add(failure_unit)
    opened = limit is not None and len(failure_units) == limit
    return True, opened


def case_failure_unit(case_id: str) -> str:
    """Use one circuit-breaker unit for all failures from the same PR case."""

    return f"case:{case_id}"


def recorded_attempt_cost(attempt_dir: Path) -> float:
    """Return provider-recorded cost even when response validation failed."""

    path = attempt_dir / "result_metadata.json"
    if not path.is_file():
        return 0.0
    try:
        value = read_json(path).get("total_cost_usd")
        return float(value or 0)
    except (AdjudicationRunError, TypeError, ValueError):
        return 0.0


def oversized_alert_files(
    alerts: list[dict[str, str]],
    repo: Path,
    *,
    threshold_bytes: int = MAX_LINE_READ_FILE_BYTES,
) -> list[dict[str, Any]]:
    """Return in-repository alert files unsafe for line-oriented SDK Read."""

    oversized: dict[str, dict[str, Any]] = {}
    root = repo.resolve()
    for alert in alerts:
        relative = Path(clean(alert.get("file_path")).replace("\\", "/"))
        if relative.is_absolute() or ".." in relative.parts:
            continue
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if not candidate.is_file():
            continue
        size = candidate.stat().st_size
        if size > threshold_bytes:
            oversized[relative.as_posix()] = {
                "file": relative.as_posix(),
                "size_bytes": size,
                "threshold_bytes": threshold_bytes,
            }
    return [oversized[path] for path in sorted(oversized)]


def recoverable_prior_response(
    batch_root: Path,
    *,
    current_attempt_dir: Path,
    expected_alert_ids: list[str],
    schema: dict[str, Any],
    repo: Path,
) -> dict[str, Any] | None:
    """Recover a prior paid response without another model invocation.

    Prior attempt directories remain immutable.  A recovery is accepted only
    when the stored response passes the complete current schema, ID, evidence,
    and consistency validation against the newly reconstructed worktree.
    Protocol failures still require an audited logical normalization.  A
    response that had already passed protocol validation but was rejected only
    because the SDK sandbox changed the disposable worktree may be revalidated
    unchanged against the fresh reconstruction.
    """

    recovery_floor = 0
    semantic_readjudication_path = batch_root / "semantic_readjudication.json"
    if semantic_readjudication_path.is_file():
        try:
            recovery_floor = int(
                read_json(semantic_readjudication_path).get(
                    "ignore_recovery_attempts_through", 0
                )
            )
        except (AdjudicationRunError, TypeError, ValueError):
            recovery_floor = 0

    def attempt_number(path: Path) -> int:
        match = re.fullmatch(r"attempt-(\d+)", path.name)
        return int(match.group(1)) if match else 0

    candidates = sorted(
        (
            path
            for path in batch_root.glob("attempt-*")
            if path.is_dir()
            and path != current_attempt_dir
            and attempt_number(path) > recovery_floor
        ),
        key=attempt_number,
        reverse=True,
    )
    for prior_dir in candidates:
        failure_path = prior_dir / "failure.json"
        transcript_path = prior_dir / "raw_sdk_transcript.json"
        if not failure_path.is_file() or not transcript_path.is_file():
            continue
        try:
            failure = read_json(failure_path)
            failure_type = clean(failure.get("error_type"))
            failure_message = clean(failure.get("error_message"))
            mutation_revalidation = (
                failure_type == "AdjudicationRunError"
                and failure_message == "model changed the adjudication worktree"
            )
            protocol_normalization = failure_type == "AdjudicationProtocolError"
            if not mutation_revalidation and not protocol_normalization:
                continue
            response_path = prior_dir / "model_response.json"
            raw_response = read_json(response_path) if response_path.is_file() else None
            if raw_response is None:
                transcript = read_json(transcript_path)
                messages = transcript.get("messages")
                if not isinstance(messages, list):
                    continue
                raw_response = next(
                    (
                        message.get("structured_output")
                        for message in reversed(messages)
                        if isinstance(message, dict)
                        and isinstance(message.get("structured_output"), dict)
                    ),
                    None,
                )
                if raw_response is None:
                    exact_result = next(
                        (
                            message.get("result")
                            for message in reversed(messages)
                            if isinstance(message, dict)
                            and not message.get("is_error")
                            and isinstance(message.get("result"), str)
                        ),
                        None,
                    )
                    if exact_result is not None:
                        raw_response = protocol.parse_exact_json_document(
                            exact_result
                        )
            if not isinstance(raw_response, dict):
                continue
            response_for_validation, changes = (
                protocol.normalize_logically_entailed_attribution(raw_response)
            )
            if protocol_normalization and not changes:
                continue
            normalized = protocol.validate_response(
                response_for_validation,
                expected_alert_ids=expected_alert_ids,
                schema=schema,
                repo=repo,
            )
        except (AdjudicationRunError, protocol.AdjudicationProtocolError):
            continue
        return {
            "source_attempt": prior_dir.name,
            "source_transcript_sha256": sha256_file(transcript_path),
            "raw_response": raw_response,
            "normalized_response": normalized,
            "logical_normalizations": changes,
            "recovery_reason": (
                "fresh_worktree_revalidation_after_sdk_sandbox_mutation"
                if mutation_revalidation
                else "audited_logical_normalization"
            ),
        }
    return None


def complete_recovered_response(
    *,
    recovery: dict[str, Any],
    batch: dict[str, str],
    repo: Path,
    row: dict[str, str],
    preflight: dict[str, Any],
    attempt_dir: Path,
) -> dict[str, Any]:
    """Persist a newly validated recovery attempt without another model call."""

    raw_response = recovery["raw_response"]
    normalized = recovery["normalized_response"]
    logical_normalizations = recovery["logical_normalizations"]
    atomic_json(attempt_dir / "model_response.json", raw_response)
    if logical_normalizations:
        atomic_json(
            attempt_dir / "logical_normalizations.json",
            {
                "schema_version": SCHEMA_VERSION,
                "policy": (
                    "condition_present=no, valid_issue=no, and actionability=no_fix "
                    "logically imply introduced_by_pr=no"
                ),
                "changes": logical_normalizations,
            },
        )
    atomic_json(
        attempt_dir / "recovery_source.json",
        {
            "schema_version": SCHEMA_VERSION,
            "source_attempt": recovery["source_attempt"],
            "source_transcript_sha256": recovery["source_transcript_sha256"],
            "recovery_reason": recovery["recovery_reason"],
            "additional_model_call": False,
        },
    )
    response_path = attempt_dir / "adjudication_response.json"
    atomic_json(response_path, normalized)
    post_audit = sdk_review.audit_repo(repo, row)
    if sdk_review.worktree_identity_projection(post_audit) != (
        sdk_review.worktree_identity_projection(preflight["worktree"])
    ):
        raise AdjudicationRunError("worktree changed during response recovery")
    atomic_json(
        attempt_dir / "result_metadata.json",
        {
            "schema_version": SCHEMA_VERSION,
            "recovered_from_prior_structured_output": True,
            "source_attempt": recovery["source_attempt"],
            "recovery_reason": recovery["recovery_reason"],
            "additional_model_call": False,
            "total_cost_usd": 0.0,
            "logical_normalizations": logical_normalizations,
        },
    )
    execution = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "batch_id": batch["batch_id"],
        "case_id": batch["case_id"],
        "preflight_sha256": preflight["preflight_sha256"],
        "response_source": "prior_paid_response_revalidation",
        "recovered_from_attempt": recovery["source_attempt"],
        "recovery_reason": recovery["recovery_reason"],
        "additional_model_call": False,
        "latency_ms": 0,
        "num_turns": 0,
        "observed_tool_calls": 0,
        "observed_tool_names": [],
        "max_tool_calls": None,
        "total_cost_usd": 0.0,
        "logical_normalizations": logical_normalizations,
        "response_sha256": sha256_file(response_path),
        "post_worktree_audit": post_audit,
    }
    execution["execution_sha256"] = sha256_payload(execution)
    atomic_json(attempt_dir / "execution.json", execution)
    return execution


def acquire_run_lock(output_dir: Path) -> Any:
    """Hold a cross-process lock so two resumptions cannot share scratch state."""

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    lock_path = output_dir.parent / f".{output_dir.name}.lock"
    handle = lock_path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise AdjudicationRunError(
            f"another adjudication process is already using {output_dir}"
        ) from None
    handle.seek(0)
    handle.truncate()
    handle.write(
        json.dumps(
            {
                "pid": os.getpid(),
                "acquired_at": datetime.now(timezone.utc).isoformat(),
                "output_dir": str(output_dir),
            },
            sort_keys=True,
        )
        + "\n"
    )
    handle.flush()
    return handle


async def collect_adjudication(
    *,
    user_prompt: str,
    options: ClaudeAgentOptions,
    message_path: Path,
    query_fn: Callable[..., AsyncIterator[Any]] = query,
) -> tuple[list[Any], ResultMessage]:
    async def prompt_stream() -> AsyncIterator[dict[str, Any]]:
        yield {
            "type": "user",
            "session_id": "",
            "message": {"role": "user", "content": user_prompt},
            "parent_tool_use_id": None,
        }

    messages: list[Any] = []
    results: list[ResultMessage] = []
    stream_error: Exception | None = None
    with message_path.open("x", encoding="utf-8") as handle:
        try:
            async for message in query_fn(prompt=prompt_stream(), options=options):
                messages.append(message)
                handle.write(
                    json.dumps(
                        sdk_review.serialize(message),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                handle.flush()
                if isinstance(message, ResultMessage):
                    results.append(message)
        except Exception as exc:
            stream_error = exc
    # Some Claude Code versions emit one terminal error ResultMessage and then
    # raise the same error while closing the stream. Preserve the terminal
    # result so its turns, token usage, and provider-recorded cost are audited.
    if len(results) == 1:
        return messages, results[0]
    if stream_error is not None:
        raise stream_error
    if len(results) != 1:
        raise AdjudicationRunError(
            f"SDK returned {len(results)} ResultMessage objects; expected 1"
        )
    return messages, results[0]


def observed_tool_names(messages: Iterable[Any]) -> list[str]:
    """Extract actual local tool uses from the immutable SDK transcript."""

    names: list[str] = []
    allowed = set(sdk_review.READ_ONLY_TOOLS)
    for message in messages:
        serialized = sdk_review.serialize(message)
        if not isinstance(serialized, dict):
            continue
        content = serialized.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            name = clean(block.get("name"))
            if name in allowed and isinstance(block.get("input"), dict):
                names.append(name)
    return names


def response_from_result(
    result: ResultMessage,
    *,
    provider: str,
) -> tuple[dict[str, Any], str]:
    if result.is_error:
        detail = "; ".join(result.errors or []) or result.result or result.subtype
        raise AdjudicationRunError(f"model execution failed: {detail}")
    if provider in {"anthropic", "compatible"} and isinstance(
        result.structured_output, dict
    ):
        return result.structured_output, "sdk_structured_output"
    if provider in {"deepseek", "compatible"} and isinstance(result.result, str):
        return protocol.parse_exact_json_document(result.result), "exact_result_json"
    raise AdjudicationRunError("model did not return an accepted structured response")


def batch_constrained_output_schema(
    schema: dict[str, Any], alert_ids: list[str]
) -> dict[str, Any]:
    """Bind the frozen response schema to one batch's exact cardinality and IDs."""

    if not alert_ids or len(alert_ids) != len(set(alert_ids)):
        raise AdjudicationRunError(
            "batch output schema requires non-empty unique alert IDs"
        )
    constrained = copy.deepcopy(schema)
    try:
        adjudications = constrained["properties"]["adjudications"]
        alert_id_schema = adjudications["items"]["properties"]["alert_id"]
    except (KeyError, TypeError):
        raise AdjudicationRunError(
            "output schema lacks adjudications/items/alert_id"
        ) from None
    adjudications["minItems"] = len(alert_ids)
    adjudications["maxItems"] = len(alert_ids)
    alert_id_schema.clear()
    alert_id_schema["enum"] = list(alert_ids)
    return constrained


def build_run_config(
    *,
    args: argparse.Namespace,
    frame_dir: Path,
    frame_manifest: dict[str, Any],
    prompt_path: Path,
    schema_path: Path,
    provider_config: dict[str, str],
    jobs: dict[str, Path],
) -> dict[str, Any]:
    config = {
        "schema_version": SCHEMA_VERSION,
        "frame_manifest_sha256": sha256_file(frame_dir / "manifest.json"),
        "frame_scope": frame_manifest.get("scope", {}),
        "prompt_sha256": sha256_file(prompt_path),
        "output_schema_sha256": sha256_file(schema_path),
        "provider_config": provider_config,
        "effort": args.effort,
        "max_budget_usd": args.max_budget_usd,
        "max_turns": args.max_turns,
        "max_tool_calls": args.max_tool_calls,
        "failure_limit": args.failure_limit,
        "failure_circuit_unit": "pr_case",
        "worktree_timeout": args.worktree_timeout,
        "jobs": {
            group: {"path": str(path), "sha256": sha256_file(path)}
            for group, path in jobs.items()
        },
        "sdk_versions": sdk_review.sdk_versions(),
        "implementation": {
            path.name: {"sha256": sha256_file(path)}
            for path in (
                Path(__file__).resolve(),
                Path(worktree_builder.__file__).resolve(),
                Path(protocol.__file__).resolve(),
                Path(sdk_review.__file__).resolve(),
            )
        },
        "response_policy": {
            "anthropic": "provider structured output",
            "deepseek": "one exact raw or single-fenced JSON document",
            "compatible": (
                "batch-cardinality-and-ID-constrained provider structured output "
                "with exact raw or single-fenced JSON fallback"
            ),
            "json_repair": False,
            "field_synthesis": False,
            "logical_normalization": (
                "only condition_present=no, valid_issue=no, and "
                "actionability=no_fix imply introduced_by_pr=no; every change "
                "is persisted"
            ),
            "failed_response_recovery": (
                "reuse a prior paid response only when it passes every current "
                "validation on a fresh worktree; protocol failures still require "
                "the narrow audited logical normalization, while a response "
                "rejected solely for SDK sandbox worktree mutation is revalidated "
                "unchanged"
            ),
            "oversized_file_read_policy": (
                "disable the line-oriented Read tool for a batch when an alert "
                "file exceeds 256 KiB; retain focused Grep/Glob/read-only Bash"
            ),
            "exact_alert_id_partition": True,
        },
    }
    config["config_sha256"] = sha256_payload(config)
    return config


def initialize_or_resume(
    output_dir: Path,
    *,
    batches: list[dict[str, str]],
    run_config: dict[str, Any],
    resume: bool,
    allow_protocol_amendment: bool = False,
) -> tuple[dict[str, dict[str, str]], Path]:
    status_path = output_dir / "batch_status.csv"
    config_path = output_dir / "run_config.json"
    if resume:
        if not output_dir.is_dir() or not config_path.is_file() or not status_path.is_file():
            raise AdjudicationRunError("resume output is incomplete")
        rows = read_csv(status_path)
        statuses = {row["batch_id"]: row for row in rows}
        if len(statuses) != len(rows) or set(statuses) != {
            row["batch_id"] for row in batches
        }:
            raise AdjudicationRunError("resume batch-status inventory mismatch")
        existing = read_json(config_path)
        if existing.get("config_sha256") != run_config.get("config_sha256"):
            if not allow_protocol_amendment:
                raise AdjudicationRunError("resume run_config hash mismatch")
            record_protocol_amendment(
                output_dir,
                existing=existing,
                replacement=run_config,
                statuses=statuses,
            )
        return statuses, status_path
    if output_dir.exists():
        raise AdjudicationRunError(f"output directory already exists: {output_dir}")
    output_dir.mkdir(parents=True)
    atomic_json(config_path, run_config)
    statuses = {
        row["batch_id"]: {
            "batch_id": row["batch_id"],
            "case_id": row["case_id"],
            "status": "pending",
            "attempts": "0",
            "last_error": "",
            "total_cost_usd": "0",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        for row in batches
    }
    atomic_status(status_path, statuses.values())
    return statuses, status_path


def protocol_amendment_projection(config: dict[str, Any]) -> dict[str, Any]:
    """Remove only fields allowed to change in audited maintenance amendments."""

    projected = copy.deepcopy(config)
    projected.pop("config_sha256", None)
    projected["max_tool_calls"] = "<amended>"
    projected["max_turns"] = "<amended>"
    projected["prompt_sha256"] = "<amended>"
    projected["failure_circuit_unit"] = "<amended>"
    response_policy = projected.get("response_policy")
    if isinstance(response_policy, dict):
        response_policy["compatible"] = "<amended>"
        response_policy["logical_normalization"] = "<amended>"
        response_policy["failed_response_recovery"] = "<amended>"
        response_policy["oversized_file_read_policy"] = "<amended>"
    implementation = projected.get("implementation")
    if isinstance(implementation, dict):
        for name in (
            "run_codeql_alert_adjudication.py",
            "run_claude_code_review.py",
            "codeql_alert_adjudication_protocol.py",
        ):
            if name in implementation:
                implementation[name] = {"sha256": "<amended>"}
    return projected


def record_protocol_amendment(
    output_dir: Path,
    *,
    existing: dict[str, Any],
    replacement: dict[str, Any],
    statuses: dict[str, dict[str, str]],
) -> None:
    """Audit and apply a narrowly supported in-place protocol amendment."""

    old_limit = existing.get("max_tool_calls")
    new_limit = replacement.get("max_tool_calls")
    old_turns = existing.get("max_turns")
    new_turns = replacement.get("max_turns")
    turn_limit_increased = (
        isinstance(old_turns, int)
        and not isinstance(old_turns, bool)
        and isinstance(new_turns, int)
        and not isinstance(new_turns, bool)
        and new_turns > old_turns
    )
    turn_limit_changed = old_turns != new_turns
    prompt_changed = existing.get("prompt_sha256") != replacement.get(
        "prompt_sha256"
    )
    response_policy_changed = existing.get("response_policy") != replacement.get(
        "response_policy"
    )
    failure_unit_changed = existing.get("failure_circuit_unit") != replacement.get(
        "failure_circuit_unit"
    )
    if turn_limit_increased and old_limit == new_limit:
        amendment_kind = "increase recovery max-turns ceiling"
    elif turn_limit_changed:
        raise AdjudicationRunError(
            "unsupported max-turns amendment; the ceiling may only increase"
        )
    elif isinstance(old_limit, int) and old_limit > 0 and new_limit is None:
        if not prompt_changed:
            raise AdjudicationRunError(
                "tool-limit amendment expected the bounded prompt to change"
            )
        amendment_kind = "remove separate read-only tool-call cap"
    elif old_limit is None and new_limit is None:
        if response_policy_changed or failure_unit_changed:
            amendment_kind = (
                "compatible structured-output enforcement and case-scoped "
                "failure circuit"
            )
        elif prompt_changed:
            amendment_kind = (
                "evidence-path clarification and response-transport maintenance"
            )
        else:
            amendment_kind = "resume-safety implementation maintenance"
    else:
        raise AdjudicationRunError(
            "unsupported protocol amendment; only cap removal or audited "
            "prompt/implementation maintenance is allowed"
        )
    if protocol_amendment_projection(existing) != protocol_amendment_projection(
        replacement
    ):
        raise AdjudicationRunError(
            "run_config mismatch includes changes beyond the audited amendment"
        )

    history_dir = output_dir / "protocol_history"
    history_dir.mkdir(parents=True, exist_ok=True)
    old_hash = clean(existing.get("config_sha256"))
    if not old_hash:
        raise AdjudicationRunError("existing run config lacks a config hash")
    archive_path = history_dir / f"run_config_{old_hash}.json"
    if archive_path.exists() and read_json(archive_path) != existing:
        raise AdjudicationRunError("protocol history archive conflicts with run config")
    if not archive_path.exists():
        atomic_json(archive_path, existing)

    amendment_path = output_dir / "protocol_amendments.json"
    if amendment_path.exists():
        payload = read_json(amendment_path)
        amendments = payload.get("amendments")
        if not isinstance(amendments, list):
            raise AdjudicationRunError("invalid protocol amendment ledger")
    else:
        amendments = []
    new_hash = clean(replacement.get("config_sha256"))
    already_recorded = any(
        isinstance(row, dict)
        and row.get("from_config_sha256") == old_hash
        and row.get("to_config_sha256") == new_hash
        for row in amendments
    )
    if not already_recorded:
        counts = Counter(row.get("status", "") for row in statuses.values())
        amendments.append(
            {
                "amended_at": datetime.now(timezone.utc).isoformat(),
                "amendment": amendment_kind,
                "from_config_sha256": old_hash,
                "to_config_sha256": new_hash,
                "old_max_tool_calls": old_limit,
                "new_max_tool_calls": new_limit,
                "old_max_turns": old_turns,
                "new_max_turns": new_turns,
                "status_counts_at_amendment": dict(sorted(counts.items())),
                "completed_batches_retained": counts.get("completed", 0),
                "prior_config_archive": str(archive_path.relative_to(output_dir)),
            }
        )
        atomic_json(
            amendment_path,
            {"schema_version": SCHEMA_VERSION, "amendments": amendments},
        )
    atomic_json(output_dir / "run_config.json", replacement)


def write_manifest(
    output_dir: Path,
    statuses: dict[str, dict[str, str]],
    *,
    selected_n: int,
    execute: bool,
) -> None:
    counts = Counter(row["status"] for row in statuses.values())
    total_cost = sum(float(row.get("total_cost_usd") or 0) for row in statuses.values())
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "execute" if execute else "offline_preflight",
        "selected_batch_n_this_invocation": selected_n,
        "total_batch_n": len(statuses),
        "status_counts": dict(sorted(counts.items())),
        "recorded_total_cost_usd": total_cost,
        "complete": counts.get("completed", 0) == len(statuses),
        "credential_value_persisted": False,
    }
    manifest["manifest_sha256"] = sha256_payload(manifest)
    atomic_json(output_dir / "run_manifest.json", manifest)


def batch_alerts(
    batch: dict[str, str], alert_by_id: dict[str, dict[str, str]]
) -> list[dict[str, str]]:
    identifiers = json.loads(batch["alert_ids_json"])
    return [alert_by_id[identifier] for identifier in identifiers]


def build_preflight_record(
    *,
    batch: dict[str, str],
    alerts: list[dict[str, str]],
    user_prompt: str,
    row: dict[str, str],
    audit: dict[str, Any],
    run_config: dict[str, Any],
    execute: bool,
) -> dict[str, Any]:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "status": "execution_authorized" if execute else "offline_preflight_passed",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "batch_id": batch["batch_id"],
        "case_id": batch["case_id"],
        "alert_ids": [alert["alert_id"] for alert in alerts],
        "alert_input_sha256": sha256_payload(
            [protocol.prompt_projection(alert) for alert in alerts]
        ),
        "user_prompt_sha256": hashlib.sha256(user_prompt.encode("utf-8")).hexdigest(),
        "run_config_sha256": run_config["config_sha256"],
        "worktree": {**row, **audit},
        "authorship_fields_sent_to_model": [],
        "network_for_reviewer_tools": "denied",
        "worktree_mutation_allowed": False,
    }
    payload["preflight_sha256"] = sha256_payload(payload)
    return payload


async def execute_one_batch(
    *,
    batch: dict[str, str],
    alerts: list[dict[str, str]],
    repo: Path,
    row: dict[str, str],
    preflight: dict[str, Any],
    attempt_dir: Path,
    provider_config: dict[str, str],
    prompt_text: str,
    schema: dict[str, Any],
    effort: str,
    max_budget_usd: float,
    max_turns: int,
    max_tool_calls: int | None,
) -> dict[str, Any]:
    provider = provider_config["provider"]
    user_prompt = protocol.build_user_prompt(alerts, provider=provider)
    oversized_files = oversized_alert_files(alerts, repo)
    allowed_tools = list(sdk_review.READ_ONLY_TOOLS)
    if oversized_files:
        allowed_tools.remove("Read")
        user_prompt += (
            "\n\nThe line-oriented Read tool is intentionally unavailable for "
            "this batch because at least one alert file exceeds 256 KiB. Use "
            "focused Grep, Glob, or bounded read-only Bash/git commands. Never "
            "request the full contents of a large or single-line generated file."
        )
    enable_structured = provider in {"anthropic", "compatible"}
    expected_alert_ids = [alert["alert_id"] for alert in alerts]
    batch_schema = batch_constrained_output_schema(schema, expected_alert_ids)
    cli_schema, schema_transforms = sdk_review.normalize_output_schema_for_cli(
        batch_schema
    )
    schema_transforms.extend(
        [
            "bound_adjudication_array_to_batch_cardinality",
            "bound_alert_id_to_batch_enum",
        ]
    )
    tool_hook = BoundedReadOnlyHook(max_tool_calls, repo=repo)
    options = sdk_review.build_options(
        repo=repo,
        model=provider_config["requested_model"],
        effort=effort,
        max_budget_usd=max_budget_usd,
        max_turns=max_turns,
        protocol=prompt_text,
        output_schema=cli_schema,
        provider_runtime_env=build_adjudication_runtime_env(provider_config),
        enable_sdk_structured_output=enable_structured,
        enable_native_report_tool=False,
        hooks={
            "PreToolUse": [
                HookMatcher(
                    matcher=None,
                    hooks=[tool_hook],
                    timeout=10,
                )
            ]
        },
        allowed_tools=allowed_tools,
    )
    started = time.monotonic()
    messages, result = await collect_adjudication(
        user_prompt=user_prompt,
        options=options,
        message_path=attempt_dir / "raw_sdk_messages.jsonl",
    )
    latency_ms = round((time.monotonic() - started) * 1000)
    tool_names = observed_tool_names(messages)
    atomic_json(
        attempt_dir / "raw_sdk_transcript.json",
        {
            "schema_version": SCHEMA_VERSION,
            "preflight_sha256": preflight["preflight_sha256"],
            "messages": sdk_review.serialize(messages),
        },
    )
    atomic_json(
        attempt_dir / "result_metadata.json",
        {
            "schema_version": SCHEMA_VERSION,
            "latency_ms": latency_ms,
            "result_subtype": result.subtype,
            "is_error": result.is_error,
            "num_turns": result.num_turns,
            "observed_tool_calls": len(tool_names),
            "observed_tool_names": tool_names,
            "enabled_tools": allowed_tools,
            "oversized_alert_files": oversized_files,
            "hook_allowed_tool_calls": tool_hook.allowed_calls,
            "tool_calls_denied_for_budget": tool_hook.denied_for_budget,
            "tool_calls_denied_for_policy": tool_hook.denied_for_policy,
            "tool_calls_denied_for_oversized_read": (
                tool_hook.denied_for_oversized_read
            ),
            "max_tool_calls": max_tool_calls,
            "tool_call_budget_exceeded": (
                max_tool_calls is not None and len(tool_names) > max_tool_calls
            ),
            "total_cost_usd": result.total_cost_usd,
            "usage": sdk_review.serialize(result.usage),
            "model_usage": sdk_review.serialize(result.model_usage),
            "has_structured_output": isinstance(result.structured_output, dict),
            "structured_output_schema_sha256": sha256_payload(cli_schema),
            "structured_output_schema_transforms": schema_transforms,
            "result_text_sha256": (
                hashlib.sha256(result.result.encode("utf-8")).hexdigest()
                if isinstance(result.result, str)
                else None
            ),
        },
    )
    if max_tool_calls is not None and len(tool_names) > max_tool_calls:
        raise AdjudicationRunError(
            f"model used {len(tool_names)} tools; frozen limit is {max_tool_calls}"
        )
    raw_response, source = response_from_result(result, provider=provider)
    atomic_json(attempt_dir / "model_response.json", raw_response)
    response_for_validation, logical_normalizations = (
        protocol.normalize_logically_entailed_attribution(raw_response)
    )
    if logical_normalizations:
        atomic_json(
            attempt_dir / "logical_normalizations.json",
            {
                "schema_version": SCHEMA_VERSION,
                "policy": (
                    "condition_present=no, valid_issue=no, and "
                    "actionability=no_fix logically imply introduced_by_pr=no"
                ),
                "changes": logical_normalizations,
            },
        )
    normalized = protocol.validate_response(
        response_for_validation,
        expected_alert_ids=expected_alert_ids,
        schema=schema,
        repo=repo,
    )
    post_audit = sdk_review.audit_repo(repo, row)
    if sdk_review.worktree_identity_projection(post_audit) != (
        sdk_review.worktree_identity_projection(preflight["worktree"])
    ):
        raise AdjudicationRunError("model changed the adjudication worktree")
    response_path = attempt_dir / "adjudication_response.json"
    atomic_json(response_path, normalized)
    execution = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "batch_id": batch["batch_id"],
        "case_id": batch["case_id"],
        "preflight_sha256": preflight["preflight_sha256"],
        "response_source": source,
        "latency_ms": latency_ms,
        "num_turns": result.num_turns,
        "observed_tool_calls": len(tool_names),
        "observed_tool_names": tool_names,
        "enabled_tools": allowed_tools,
        "oversized_alert_files": oversized_files,
        "hook_allowed_tool_calls": tool_hook.allowed_calls,
        "tool_calls_denied_for_budget": tool_hook.denied_for_budget,
        "tool_calls_denied_for_policy": tool_hook.denied_for_policy,
        "tool_calls_denied_for_oversized_read": (
            tool_hook.denied_for_oversized_read
        ),
        "max_tool_calls": max_tool_calls,
        "total_cost_usd": result.total_cost_usd,
        "logical_normalizations": logical_normalizations,
        "response_sha256": sha256_file(response_path),
        "post_worktree_audit": post_audit,
    }
    execution["execution_sha256"] = sha256_payload(execution)
    atomic_json(attempt_dir / "execution.json", execution)
    return execution


def run(args: argparse.Namespace) -> None:
    frame_dir = resolve(args.frame_dir)
    output_dir = resolve(args.output_dir)
    scratch_dir = resolve(args.scratch_dir) if args.scratch_dir else output_dir / "scratch"
    ai_jobs = resolve(args.ai_jobs)
    human_jobs = resolve(args.human_jobs)
    prompt_path = resolve(args.prompt)
    schema_path = resolve(args.output_schema)
    frame_manifest = verify_frame(frame_dir)
    case_by_id, alert_by_id, batches = load_frame(frame_dir)
    if args.max_turns < 1:
        raise AdjudicationRunError("max-turns must be positive")
    if args.max_tool_calls is not None and (
        args.max_tool_calls < 1 or args.max_tool_calls >= args.max_turns
    ):
        raise AdjudicationRunError(
            "max-tool-calls must be positive and smaller than max-turns"
        )
    if args.failure_limit is not None and args.failure_limit < 1:
        raise AdjudicationRunError("failure-limit must be positive")
    if args.workers < 1 or args.workers > 16:
        raise AdjudicationRunError("workers must be between 1 and 16")
    if args.keep_failed_worktree and args.workers != 1:
        raise AdjudicationRunError(
            "--keep-failed-worktree requires --workers 1 to avoid retaining "
            "multiple large scratch trees"
        )
    sdk_review.validate_budget(args.max_budget_usd)
    provider_config = resolve_adjudication_provider_config(args)
    prompt_text = prompt_path.read_text(encoding="utf-8")
    schema = read_json(schema_path)
    run_config = build_run_config(
        args=args,
        frame_dir=frame_dir,
        frame_manifest=frame_manifest,
        prompt_path=prompt_path,
        schema_path=schema_path,
        provider_config=provider_config,
        jobs={"ai": ai_jobs, "human": human_jobs},
    )
    statuses, status_path = initialize_or_resume(
        output_dir,
        batches=batches,
        run_config=run_config,
        resume=args.resume,
        allow_protocol_amendment=args.allow_bounded_to_unbounded_amendment,
    )
    chosen = selected_batches(
        batches,
        case_ids=args.case_ids,
        batch_ids=args.batch_ids,
        limit=args.limit_batches,
        statuses=statuses,
        execute=args.execute,
    )
    if not chosen:
        write_manifest(output_dir, statuses, selected_n=0, execute=args.execute)
        print("没有待处理的 adjudication batch")
        return
    if not args.execute and args.limit_batches is None and not args.batch_ids and not args.case_ids:
        chosen = chosen[:1]
        print("离线模式默认只预检第一个 batch；用 --limit-batches 扩大范围。")

    job_index = worktree_builder.build_job_index(
        worktree_builder.read_jobs(ai_jobs),
        worktree_builder.read_jobs(human_jobs),
    )
    cache_dirs = {
        "ai": resolve(args.ai_cache_dir),
        "human": resolve(args.human_cache_dir),
    }
    selected_by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for batch in chosen:
        selected_by_case[batch["case_id"]].append(batch)

    processed = 0
    failure_units: set[str] = set()
    state_lock = threading.Lock()
    stop_event = threading.Event()
    scratch_dir.mkdir(parents=True, exist_ok=True)

    def persist_batch_result(
        batch: dict[str, str],
        *,
        result_status: str,
        attempt: int,
        error: str = "",
        cost: float = 0.0,
        failure_unit: str | None = None,
    ) -> None:
        nonlocal processed
        with state_lock:
            status = statuses[batch["batch_id"]]
            status["status"] = result_status
            status["attempts"] = str(attempt)
            status["last_error"] = error[-2000:]
            status["total_cost_usd"] = str(
                float(status.get("total_cost_usd") or 0) + cost
            )
            status["updated_at"] = datetime.now(timezone.utc).isoformat()
            processed += 1
            opened_now = False
            if result_status in {"failed", "worktree_failed"}:
                unit = failure_unit or f"batch:{batch['batch_id']}"
                _, opened_now = register_failure_unit(
                    failure_units, unit, args.failure_limit
                )
                if (
                    args.failure_limit is not None
                    and len(failure_units) >= args.failure_limit
                ):
                    stop_event.set()
            atomic_status(status_path, statuses.values())
            write_manifest(
                output_dir, statuses, selected_n=len(chosen), execute=args.execute
            )
            print(
                f"[{processed}/{len(chosen)}] {batch['batch_id']}: {result_status}",
                flush=True,
            )
            if opened_now:
                print(
                    "failure circuit opened after "
                    f"{len(failure_units)} independent failed PR cases; "
                    "no new cases will start",
                    flush=True,
                )

    def process_case(case_id: str, case_batches: list[dict[str, str]]) -> None:
        if stop_event.is_set():
            return
        case = case_by_id[case_id]
        keep_case = False
        try:
            row, repo = worktree_builder.build_case_worktree(
                case,
                job_index=job_index,
                cache_dirs=cache_dirs,
                scratch_root=scratch_dir,
                timeout_seconds=args.worktree_timeout,
            )
            audit = sdk_review.audit_repo(repo, row)
        except Exception as exc:
            error = redact(str(exc), provider_config["api_key_env"])
            for batch in case_batches:
                with state_lock:
                    attempt = int(statuses[batch["batch_id"]]["attempts"]) + 1
                persist_batch_result(
                    batch,
                    result_status="worktree_failed",
                    attempt=attempt,
                    error=error,
                    failure_unit=case_failure_unit(case_id),
                )
            if args.stop_on_failure:
                stop_event.set()
            return

        try:
            rebuild_before_next_batch = False
            for batch_index, batch in enumerate(case_batches):
                if stop_event.is_set():
                    break
                if rebuild_before_next_batch:
                    worktree_builder.remove_case_worktree(scratch_dir, case_id)
                    try:
                        row, repo = worktree_builder.build_case_worktree(
                            case,
                            job_index=job_index,
                            cache_dirs=cache_dirs,
                            scratch_root=scratch_dir,
                            timeout_seconds=args.worktree_timeout,
                        )
                        audit = sdk_review.audit_repo(repo, row)
                    except Exception as exc:
                        error = redact(str(exc), provider_config["api_key_env"])
                        for remaining in case_batches[batch_index:]:
                            with state_lock:
                                attempt = (
                                    int(statuses[remaining["batch_id"]]["attempts"])
                                    + 1
                                )
                            persist_batch_result(
                                remaining,
                                result_status="worktree_failed",
                                attempt=attempt,
                                error=(
                                    "fresh worktree reconstruction after a failed "
                                    f"batch also failed: {error}"
                                ),
                                failure_unit=case_failure_unit(case_id),
                            )
                        return
                    rebuild_before_next_batch = False
                with state_lock:
                    attempt = int(statuses[batch["batch_id"]]["attempts"]) + 1
                batch_root = output_dir / "invocations" / batch["batch_id"]
                attempt_dir, attempt = attempt_directory(batch_root, attempt)
                alerts = batch_alerts(batch, alert_by_id)
                user_prompt = protocol.build_user_prompt(
                    alerts, provider=provider_config["provider"]
                )
                preflight = build_preflight_record(
                    batch=batch,
                    alerts=alerts,
                    user_prompt=user_prompt,
                    row=row,
                    audit=audit,
                    run_config=run_config,
                    execute=args.execute,
                )
                atomic_json(attempt_dir / "preflight.json", preflight)
                if not args.execute:
                    persist_batch_result(
                        batch,
                        result_status="preflight_passed",
                        attempt=attempt,
                    )
                else:
                    try:
                        expected_alert_ids = [
                            alert["alert_id"] for alert in alerts
                        ]
                        recovery = recoverable_prior_response(
                            batch_root,
                            current_attempt_dir=attempt_dir,
                            expected_alert_ids=expected_alert_ids,
                            schema=schema,
                            repo=repo,
                        )
                        if recovery is not None:
                            execution = complete_recovered_response(
                                recovery=recovery,
                                batch=batch,
                                repo=repo,
                                row=row,
                                preflight=preflight,
                                attempt_dir=attempt_dir,
                            )
                        else:
                            execution = asyncio.run(
                                execute_one_batch(
                                    batch=batch,
                                    alerts=alerts,
                                    repo=repo,
                                    row=row,
                                    preflight=preflight,
                                    attempt_dir=attempt_dir,
                                    provider_config=provider_config,
                                    prompt_text=prompt_text,
                                    schema=schema,
                                    effort=args.effort,
                                    max_budget_usd=args.max_budget_usd,
                                    max_turns=args.max_turns,
                                    max_tool_calls=args.max_tool_calls,
                                )
                            )
                        cost = float(execution.get("total_cost_usd") or 0)
                        persist_batch_result(
                            batch,
                            result_status="completed",
                            attempt=attempt,
                            cost=cost,
                        )
                    except Exception as exc:
                        error = redact(str(exc), provider_config["api_key_env"])
                        failed_cost = recorded_attempt_cost(attempt_dir)
                        failure = {
                            "schema_version": SCHEMA_VERSION,
                            "status": "failed",
                            "failed_at": datetime.now(timezone.utc).isoformat(),
                            "batch_id": batch["batch_id"],
                            "case_id": case_id,
                            "error_type": type(exc).__name__,
                            "error_message": error,
                            "credential_value_persisted": False,
                        }
                        failure["failure_sha256"] = sha256_payload(failure)
                        atomic_json(attempt_dir / "failure.json", failure)
                        persist_batch_result(
                            batch,
                            result_status="failed",
                            attempt=attempt,
                            error=error,
                            cost=failed_cost,
                            failure_unit=case_failure_unit(case_id),
                        )
                        keep_case = args.keep_failed_worktree
                        # A failed SDK invocation may have changed disposable
                        # index/worktree state despite the read-only policy. Do
                        # not let that state cascade into later batches from the
                        # same PR: rebuild the exact frozen trees first.
                        rebuild_before_next_batch = not keep_case
                        if args.stop_on_failure:
                            stop_event.set()
                        if keep_case:
                            stop_event.set()
                            break
        finally:
            if not keep_case:
                worktree_builder.remove_case_worktree(scratch_dir, case_id)

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(process_case, case_id, case_batches)
            for case_id, case_batches in selected_by_case.items()
        ]
        for future in as_completed(futures):
            future.result()

    write_manifest(output_dir, statuses, selected_n=len(chosen), execute=args.execute)
    counts = Counter(row["status"] for row in statuses.values())
    print(
        "CodeQL alert adjudication invocation finished: "
        f"processed={processed} status={dict(sorted(counts.items()))} "
        f"output={output_dir}"
    )


def main() -> None:
    args = parse_args()
    output_dir = resolve(args.output_dir)
    lock = acquire_run_lock(output_dir)
    try:
        run(args)
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


if __name__ == "__main__":
    main()
