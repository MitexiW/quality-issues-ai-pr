#!/usr/bin/env python3
"""Validate and safely append one response for a frozen RQ3 invocation."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import summarize_llm_review_run as run_summary


SCHEMA_VERSION = "2.0.0"
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
ISSUE_FAMILIES = {"quality", "security"}
REQUIRED_FINDING_FIELDS = {
    "issue_family",
    "file_path",
    "line_start",
    "line_end",
    "hunk_header",
    "weakness_category",
    "severity",
    "explanation",
    "evidence",
    "recommendation",
}


class RecordingError(ValueError):
    """Raised when an attempt cannot be tied safely to the frozen run."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="校验并追加一个已冻结 RQ3 invocation 的原始响应"
    )
    parser.add_argument("--run-manifest", required=True)
    parser.add_argument("--invocation-id", required=True)
    parser.add_argument("--output-jsonl", required=True)
    parser.add_argument("--raw-response", required=True)
    parser.add_argument("--input-tokens", type=int)
    parser.add_argument("--output-tokens", type=int)
    parser.add_argument("--latency-ms", type=int)
    return parser.parse_args()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_response(payload: Any, namespace: str = "") -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or set(payload) != {"findings"}:
        raise ValueError("response 必须是仅含 findings 的 JSON object")
    findings = payload["findings"]
    if not isinstance(findings, list):
        raise ValueError("findings 必须是 array")
    normalized = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or set(finding) != REQUIRED_FINDING_FIELDS:
            raise ValueError(f"finding {index} 字段不符合冻结 schema")
        if finding["severity"] not in SEVERITIES:
            raise ValueError(f"finding {index} severity 无效")
        if finding["issue_family"] not in ISSUE_FAMILIES:
            raise ValueError(f"finding {index} issue_family 无效")
        for field in (
            "file_path",
            "weakness_category",
            "explanation",
            "evidence",
            "recommendation",
        ):
            if not isinstance(finding[field], str) or not finding[field].strip():
                raise ValueError(f"finding {index} {field} 不能为空")
        hunk_header = finding["hunk_header"]
        if hunk_header is not None and not isinstance(hunk_header, str):
            raise ValueError(f"finding {index} hunk_header 无效")
        for field in ("line_start", "line_end"):
            value = finding[field]
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
            ):
                raise ValueError(f"finding {index} {field} 无效")
        if (
            finding["line_start"] is not None
            and finding["line_end"] is not None
            and finding["line_end"] < finding["line_start"]
        ):
            raise ValueError(f"finding {index} line range 无效")
        normalized.append(
            {
                **finding,
                "model_finding_id": "mf-"
                + hashlib.sha256(
                    json.dumps(
                        [namespace, index, finding],
                        ensure_ascii=False,
                        sort_keys=True,
                    ).encode()
                ).hexdigest()[:20],
            }
        )
    return normalized


def validate_usage(value: int | None, label: str) -> int | None:
    if value is not None and (isinstance(value, bool) or value < 0):
        raise RecordingError(f"{label} must be a non-negative integer or omitted")
    return value


def validate_output_path(path: Path, run_dir: Path) -> Path:
    if path.suffix != ".jsonl":
        raise RecordingError("output path must have a .jsonl suffix")
    resolved_run = run_dir.resolve()
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(resolved_run)
    except ValueError:
        raise RecordingError(
            f"output path escapes the frozen run directory: {resolved}"
        ) from None
    if resolved == resolved_run:
        raise RecordingError("output path must be a file below the run directory")
    if path.is_symlink() or resolved.is_symlink():
        raise RecordingError("output path may not be a symbolic link")
    return resolved


def load_frozen_invocation(
    run_manifest_path: Path,
    invocation_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    manifest, plan, _, _ = run_summary.validate_run_manifest(run_manifest_path)
    matches = [row for row in plan if row["invocation_id"] == invocation_id]
    if len(matches) != 1:
        raise RecordingError(f"unknown invocation_id: {invocation_id}")
    return manifest, plan, matches[0]


def read_existing_attempts_locked(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return run_summary.read_jsonl(path, allow_empty=True)


def append_bytes_fsync(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short append while writing attempt")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def append_attempt_locked(
    output_path: Path,
    plan: list[dict[str, Any]],
    invocation: dict[str, Any],
    record_without_attempt_index: dict[str, Any],
) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = output_path.with_name(output_path.name + ".lock")
    lock_flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        lock_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_descriptor = os.open(lock_path, lock_flags, 0o600)
    try:
        with os.fdopen(lock_descriptor, "r+", encoding="utf-8") as lock_stream:
            fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX)
            if output_path.is_symlink():
                raise RecordingError("output path became a symbolic link")
            existing = read_existing_attempts_locked(output_path)
            if existing:
                run_summary.validate_and_collapse_attempts(plan, existing)
            invocation_attempts = [
                row
                for row in existing
                if row.get("invocation_id") == invocation["invocation_id"]
            ]
            if any(row.get("status") == "valid" for row in invocation_attempts):
                raise RecordingError(
                    f"{invocation['invocation_id']} already has a valid response"
                )
            attempt_index = len(invocation_attempts) + 1
            max_attempts = int(invocation["max_attempts"])
            if attempt_index > max_attempts:
                raise RecordingError(
                    f"{invocation['invocation_id']} exceeds max_attempts={max_attempts}"
                )
            record = {
                **record_without_attempt_index,
                "attempt_index": attempt_index,
                "retry_count": attempt_index - 1,
            }
            line = (
                json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            append_bytes_fsync(output_path, line)
            os.fsync(lock_stream.fileno())
            return record
    except Exception:
        # os.fdopen owns and closes lock_descriptor after successful creation.
        raise


def record_attempt(
    run_manifest_path: Path,
    invocation_id: str,
    output_path: Path,
    raw_response_path: Path,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    latency_ms: int | None = None,
) -> dict[str, Any]:
    input_tokens = validate_usage(input_tokens, "input_tokens")
    output_tokens = validate_usage(output_tokens, "output_tokens")
    latency_ms = validate_usage(latency_ms, "latency_ms")
    manifest_path = run_manifest_path.expanduser().resolve()
    manifest, plan, invocation = load_frozen_invocation(
        manifest_path, invocation_id
    )
    destination = validate_output_path(output_path, manifest_path.parent)
    raw = raw_response_path.read_text(encoding="utf-8")
    try:
        payload = json.loads(raw)
        findings = validate_response(payload, invocation_id)
        status = "valid"
        error = ""
    except (json.JSONDecodeError, ValueError) as exc:
        findings = []
        status = "invalid_json_or_schema"
        error = str(exc)
    record = {
        "schema_version": SCHEMA_VERSION,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "invocation_id": invocation["invocation_id"],
        "run_id": invocation["run_id"],
        "provider": invocation["provider"],
        "model_id": invocation["model_id"],
        "model_family": invocation["model_family"],
        "adapter_id": invocation["adapter_id"],
        "packet_id": invocation["packet_id"],
        "packet_sha256": invocation["packet_sha256"],
        "chunk_sha256": invocation["chunk_sha256"],
        "repetition": invocation["repetition"],
        "chunk_index": invocation["chunk_index"],
        "chunk_count": invocation["chunk_count"],
        "status": status,
        "error": error,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "latency_ms": latency_ms,
        "raw_response": raw,
        "raw_response_sha256": sha256_text(raw),
        "findings": findings,
        "run_manifest_content_sha256": manifest["manifest_content_sha256"],
    }
    return append_attempt_locked(destination, plan, invocation, record)


def main() -> None:
    args = parse_args()
    try:
        result = record_attempt(
            Path(args.run_manifest),
            args.invocation_id,
            Path(args.output_jsonl),
            Path(args.raw_response),
            args.input_tokens,
            args.output_tokens,
            args.latency_ms,
        )
    except (RecordingError, run_summary.SummaryError, OSError) as exc:
        raise SystemExit(str(exc)) from None
    print(
        json.dumps(
            {
                "invocation_id": result["invocation_id"],
                "attempt_index": result["attempt_index"],
                "status": result["status"],
                "findings": len(result["findings"]),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    if result["status"] != "valid":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
