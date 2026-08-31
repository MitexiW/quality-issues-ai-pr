#!/usr/bin/env python3
# RQ3 review experiment entry point.
"""Build leakage-checked, hashed, chunked packets for blind LLM PR review."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


BANNED_PACKET_KEYS = {
    "group",
    "repo_name",
    "pr_number",
    "agent",
    "case_control",
    "cwe",
    "sarif",
    "rule_id",
    "ground_truth",
    "confirmed_finding",
}
ATTRIBUTION_PATTERNS = [
    re.compile(
        r"(?im)^.*(?:generated|authored|created|written|made)"
        r"\s+(?:with|by|using)\s+\[?"
        r"(?:claude|chatgpt|codex|copilot|cursor|devin|coderabbit).*$"
    ),
    re.compile(r"(?im)^co-authored-by:.*(?:claude|codex|copilot|cursor|devin).*$"),
    re.compile(
        r"(?im)^.*(?:link to|view)\s+(?:the\s+)?"
        r"(?:claude|chatgpt|codex|copilot|cursor|devin)\s+run.*$"
    ),
    re.compile(r"(?is)<!--.*?(?:ellipsis|coderabbit|copilot|generated).*?-->"),
]
METADATA_TOOL_PATTERN = re.compile(
    r"(?i)\b(?:claude(?:\s+code)?|chatgpt|codex|copilot|cursor|devin|"
    r"coderabbit|ellipsis)\b"
)
METADATA_AI_ATTRIBUTION_PATTERN = re.compile(
    r"(?i)\b(?:AI[- ](?:generated|authored|written)|"
    r"(?:generated|authored|written)\s+(?:with|by|using)\s+AI|"
    r"AI\s+(?:coding\s+)?agent)\b"
)
LEAKAGE_PATTERNS = [
    (re.compile(r"(?i)\bCWE-\d+\b"), "[REDACTED_WEAKNESS_ID]"),
    (re.compile(r"(?i)\bCodeQL\b"), "[REDACTED_ANALYZER]"),
    (re.compile(r"(?i)\bSARIF\b"), "[REDACTED_ANALYZER_FORMAT]"),
]
DIFF_HEADER_PATTERN = re.compile(r"(?m)^diff --git .+$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="构建盲化 LLM PR review packets")
    parser.add_argument("--cases", required=True)
    parser.add_argument("--diffs", required=True, help="repo_name/pr_number/title/body/diff JSONL")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--prompt", default="config/study/llm_review_prompt.txt")
    parser.add_argument(
        "--schema", default="config/study/llm_review_output_schema.json"
    )
    parser.add_argument(
        "--selected-reference-alerts",
        help=(
            "仅含已选 positive cases 的 reference alerts；"
            "默认读取 cases CSV 同目录的 selected_reference_alerts.csv"
        ),
    )
    parser.add_argument(
        "--all-case-reference-alerts",
        help=(
            "所选 cases 的两类隐藏 actionable references；默认读取 cases CSV "
            "同目录的 all_case_reference_alerts.csv"
        ),
    )
    parser.add_argument("--max-chars", type=int, default=60000)
    return parser.parse_args()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_hash(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    )


def sanitize_text(value: str) -> str:
    result = value or ""
    for pattern in ATTRIBUTION_PATTERNS:
        result = pattern.sub("", result)
    for pattern, replacement in LEAKAGE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result.strip()


def sanitize_diff(value: str) -> str:
    """Redact analyzer labels without applying metadata identity rules to code."""
    result = value or ""
    for pattern, replacement in LEAKAGE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result.strip()


def repository_patterns(repo_name: str) -> tuple[re.Pattern[str], re.Pattern[str]]:
    normalized = str(repo_name or "").strip()
    basename = normalized.rsplit("/", 1)[-1]
    full = re.compile(re.escape(normalized), re.IGNORECASE)
    short = re.compile(
        rf"(?i)(?<![A-Za-z0-9]){re.escape(basename)}(?![A-Za-z0-9])"
    )
    return full, short


def pr_identity_patterns(
    repo_name: str,
    pr_number: str,
) -> list[re.Pattern[str]]:
    repo = re.escape(str(repo_name or "").strip())
    number = re.escape(str(pr_number or "").strip())
    return [
        re.compile(
            rf"(?i)https?://(?:api\.)?github\.com/"
            rf"(?:repos/)?{repo}/pulls?/{number}(?:[/?#][^\s)]*)?"
        ),
        re.compile(rf"(?i)(?<![A-Za-z0-9])(?:PR|pull request)\s*#?\s*{number}\b"),
        re.compile(rf"(?i)(?<![A-Za-z0-9])#{number}\b"),
        re.compile(rf"(?i)/pulls?/{number}\b"),
    ]


def sanitize_metadata_text(
    value: str,
    repo_name: str,
    pr_number: str,
) -> str:
    result = sanitize_text(value)
    for pattern in pr_identity_patterns(repo_name, pr_number):
        result = pattern.sub("[REDACTED_PR_IDENTITY]", result)
    full_repo, repo_basename = repository_patterns(repo_name)
    result = full_repo.sub("[REDACTED_REPOSITORY]", result)
    result = repo_basename.sub("[REDACTED_REPOSITORY]", result)
    result = METADATA_AI_ATTRIBUTION_PATTERN.sub(
        "[REDACTED_AUTHORSHIP_ATTRIBUTION]",
        result,
    )
    result = METADATA_TOOL_PATTERN.sub("[REDACTED_AUTHORSHIP_TOOL]", result)
    return result.strip()


def metadata_identity_leaks(
    value: str,
    repo_name: str,
    pr_number: str,
) -> list[str]:
    hits: list[str] = []
    full_repo, repo_basename = repository_patterns(repo_name)
    if full_repo.search(value):
        hits.append("full_repo_name")
    if repo_basename.search(value):
        hits.append("repo_basename")
    if any(
        pattern.search(value)
        for pattern in pr_identity_patterns(repo_name, pr_number)
    ):
        hits.append("pr_identity")
    if METADATA_TOOL_PATTERN.search(value):
        hits.append("authorship_tool")
    if METADATA_AI_ATTRIBUTION_PATTERN.search(value):
        hits.append("ai_attribution")
    return hits


def split_blocks(text: str, marker: re.Pattern[str]) -> list[str]:
    starts = [match.start() for match in marker.finditer(text)]
    if not starts:
        return [text] if text else []
    if starts[0] != 0:
        starts.insert(0, 0)
    starts.append(len(text))
    return [text[starts[i] : starts[i + 1]] for i in range(len(starts) - 1)]


def line_chunks(text: str, max_chars: int) -> list[str]:
    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if current and len(current) + len(line) > max_chars:
            chunks.append(current)
            current = ""
        if len(line) > max_chars:
            for start in range(0, len(line), max_chars):
                if current:
                    chunks.append(current)
                    current = ""
                chunks.append(line[start : start + max_chars])
        else:
            current += line
    if current:
        chunks.append(current)
    return chunks


def split_diff(diff: str, max_chars: int) -> list[str]:
    if max_chars < 100:
        raise ValueError("max_chars 过小")
    sanitized = sanitize_diff(diff)
    if len(sanitized) <= max_chars:
        return [sanitized]
    file_blocks = split_blocks(sanitized, re.compile(r"(?m)^diff --git "))
    units: list[str] = []
    for block in file_blocks:
        if len(block) <= max_chars:
            units.append(block)
            continue
        hunks = split_blocks(block, re.compile(r"(?m)^@@ "))
        for hunk in hunks:
            if len(hunk) <= max_chars:
                units.append(hunk)
            else:
                units.extend(line_chunks(hunk, max_chars))
    chunks: list[str] = []
    current = ""
    for unit in units:
        if current and len(current) + len(unit) > max_chars:
            chunks.append(current)
            current = ""
        if len(unit) > max_chars:
            chunks.extend(line_chunks(unit, max_chars))
        else:
            current += unit
    if current:
        chunks.append(current)
    return [chunk for chunk in chunks if chunk]


def chunk_file_contexts(chunks: list[str]) -> list[list[str]]:
    """Carry file identity separately when a hunk-only chunk lacks its header."""
    contexts: list[list[str]] = []
    last_header = ""
    for chunk in chunks:
        headers = DIFF_HEADER_PATTERN.findall(chunk)
        if headers:
            last_header = headers[-1]
            contexts.append(headers)
        else:
            contexts.append([last_header] if last_header else [])
    return contexts


def read_csv(path: Path) -> list[dict[str, str]]:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            break
        except OverflowError:
            limit //= 10
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        temporary = Path(stream.name)
    temporary.replace(path)


def validate_packet(
    packet: dict[str, Any],
    repo_name: str = "",
    pr_number: str = "",
) -> None:
    serialized = json.dumps(packet, ensure_ascii=False).lower()
    bad_keys = BANNED_PACKET_KEYS & set(packet)
    if bad_keys:
        raise ValueError(f"packet 泄漏禁止字段: {sorted(bad_keys)}")
    for pattern, _ in LEAKAGE_PATTERNS:
        if pattern.search(serialized):
            raise ValueError(f"packet 文本仍含禁止模式: {pattern.pattern}")
    if repo_name:
        metadata = "\n".join(
            [
                str(packet.get("title", "")),
                str(packet.get("description", "")),
            ]
        )
        identity_hits = metadata_identity_leaks(
            metadata,
            repo_name,
            pr_number,
        )
        if identity_hits:
            raise ValueError(
                "packet metadata 身份泄漏: "
                + ", ".join(sorted(identity_hits))
            )


def build_packets(
    cases: list[dict[str, str]],
    diffs: list[dict[str, Any]],
    max_chars: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    required_cases = {
        "case_id",
        "case_control",
        "group",
        "repo_name",
        "pr_number",
        "split",
    }
    by_pr = {}
    for row in diffs:
        key = (str(row.get("repo_name", "")).lower(), str(row.get("pr_number", "")))
        if key in by_pr:
            raise ValueError(f"diff 重复: {key}")
        by_pr[key] = row
    packets = []
    keys = []
    for case in cases:
        missing = required_cases - case.keys()
        if missing:
            raise ValueError(f"case 缺少字段: {sorted(missing)}")
        key = (case["repo_name"].lower(), case["pr_number"])
        source = by_pr.get(key)
        if source is None:
            raise ValueError(f"case 缺少 diff: {case['repo_name']}#{case['pr_number']}")
        packet_id = "packet-" + hashlib.sha256(case["case_id"].encode()).hexdigest()[:20]
        chunks = split_diff(str(source.get("diff", "")), max_chars)
        if not chunks:
            raise ValueError(f"case diff 为空: {case['case_id']}")
        contexts = chunk_file_contexts(chunks)
        chunk_rows = [
            {
                "chunk_index": index,
                "chunk_count": len(chunks),
                "file_context": contexts[index - 1],
                "diff": chunk,
                "chunk_sha256": sha256_bytes(chunk.encode("utf-8")),
            }
            for index, chunk in enumerate(chunks, start=1)
        ]
        packet = {
            "packet_id": packet_id,
            "title": sanitize_metadata_text(
                str(source.get("title", "")),
                case["repo_name"],
                case["pr_number"],
            ),
            "description": sanitize_metadata_text(
                str(source.get("body", "")),
                case["repo_name"],
                case["pr_number"],
            ),
            "chunks": chunk_rows,
            "chunking": {
                "algorithm": "file_then_hunk_then_line_v1",
                "max_chars": max_chars,
                "all_chunks_required": True,
            },
        }
        validate_packet(packet, case["repo_name"], case["pr_number"])
        packet["packet_sha256"] = canonical_hash(packet)
        packets.append(packet)
        keys.append(
            {
                **case,
                "packet_id": packet_id,
                "packet_sha256": packet["packet_sha256"],
                "chunk_count": len(chunks),
            }
        )
    return packets, keys


def audit_packet_artifacts(
    cases: list[dict[str, str]],
    diffs: list[dict[str, Any]],
    packets: list[dict[str, Any]],
    keys: list[dict[str, str]],
    selected_references: list[dict[str, str]],
    max_chars: int,
    all_case_references: list[dict[str, str]] | None = None,
    expected_pilot_case_n: int | None = None,
) -> dict[str, Any]:
    failures: Counter[str] = Counter()
    case_by_id = {row.get("case_id", ""): row for row in cases}
    key_by_packet = {row.get("packet_id", ""): row for row in keys}
    diff_by_pr = {
        (
            str(row.get("repo_name", "")).lower(),
            str(row.get("pr_number", "")),
        ): row
        for row in diffs
    }
    if len(case_by_id) != len(cases):
        failures["duplicate_case_id"] += len(cases) - len(case_by_id)
    if len(key_by_packet) != len(keys):
        failures["duplicate_packet_id_in_key"] += len(keys) - len(key_by_packet)
    if len(packets) != len(cases):
        failures["packet_case_count_mismatch"] += abs(len(packets) - len(cases))
    if len(keys) != len(cases):
        failures["key_case_count_mismatch"] += abs(len(keys) - len(cases))
    unique_pr_n = len(
        {
            (
                row.get("group", ""),
                str(row.get("repo_name", "")).lower(),
                row.get("pr_number", ""),
            )
            for row in cases
        }
    )
    if unique_pr_n != len(cases):
        failures["duplicate_pr_across_cases"] += len(cases) - unique_pr_n

    splits = {row.get("split", "") for row in cases}
    if splits == {"pilot"} and expected_pilot_case_n is not None:
        if expected_pilot_case_n % 8:
            raise ValueError("expected_pilot_case_n 必须能被 8 整除")
        expected_per_stratum = expected_pilot_case_n // 8
        expected_pilot_distribution = {
            (family, case_control, group): expected_per_stratum
            for family in ("quality", "security")
            for case_control in ("positive", "control")
            for group in ("ai", "human")
        }
        actual_pilot_distribution = Counter(
            (
                row.get("target_family", ""),
                row.get("case_control", ""),
                row.get("group", ""),
            )
            for row in cases
        )
        if len(cases) != expected_pilot_case_n:
            failures["pilot_case_count_mismatch"] += abs(
                len(cases) - expected_pilot_case_n
            )
        if actual_pilot_distribution != expected_pilot_distribution:
            failures["pilot_distribution_mismatch"] += 1

    reconstructed_chunk_n = 0
    identity_leak_n = 0
    for packet in packets:
        packet_id = str(packet.get("packet_id", ""))
        key_row = key_by_packet.get(packet_id)
        if key_row is None:
            failures["packet_missing_key"] += 1
            continue
        case = case_by_id.get(key_row.get("case_id", ""))
        if case is None:
            failures["key_missing_case"] += 1
            continue
        stored_hash = str(packet.get("packet_sha256", ""))
        unhashed_packet = {
            field: value
            for field, value in packet.items()
            if field != "packet_sha256"
        }
        if canonical_hash(unhashed_packet) != stored_hash:
            failures["packet_hash_mismatch"] += 1
        if key_row.get("packet_sha256", "") != stored_hash:
            failures["key_packet_hash_mismatch"] += 1
        chunks = packet.get("chunks")
        if not isinstance(chunks, list) or not chunks:
            failures["empty_or_invalid_chunks"] += 1
            continue
        expected_indexes = list(range(1, len(chunks) + 1))
        actual_indexes = [chunk.get("chunk_index") for chunk in chunks]
        if actual_indexes != expected_indexes:
            failures["chunk_index_mismatch"] += 1
        for chunk in chunks:
            reconstructed_chunk_n += 1
            diff_text = str(chunk.get("diff", ""))
            if len(diff_text) > max_chars:
                failures["chunk_over_limit"] += 1
            if chunk.get("chunk_count") != len(chunks):
                failures["chunk_count_mismatch"] += 1
            if chunk.get("chunk_sha256") != sha256_bytes(
                diff_text.encode("utf-8")
            ):
                failures["chunk_hash_mismatch"] += 1
            file_context = chunk.get("file_context")
            if not isinstance(file_context, list):
                failures["chunk_invalid_file_context"] += 1
                file_context = []
            if "diff --git " not in diff_text and not file_context:
                failures["chunk_missing_file_identity"] += 1
        source = diff_by_pr.get(
            (
                str(case.get("repo_name", "")).lower(),
                str(case.get("pr_number", "")),
            )
        )
        if source is None:
            failures["case_missing_source_diff"] += 1
        elif "".join(str(chunk.get("diff", "")) for chunk in chunks) != sanitize_diff(
            str(source.get("diff", ""))
        ):
            failures["diff_reconstruction_mismatch"] += 1
        metadata = "\n".join(
            [
                str(packet.get("title", "")),
                str(packet.get("description", "")),
            ]
        )
        hits = metadata_identity_leaks(
            metadata,
            str(case.get("repo_name", "")),
            str(case.get("pr_number", "")),
        )
        identity_leak_n += len(hits)
        if hits:
            failures["metadata_identity_leak"] += len(hits)

    positive_cases = {
        row["case_id"]: row
        for row in cases
        if row.get("case_control") == "positive"
    }
    references_by_case = Counter(
        row.get("case_id", "") for row in selected_references
    )
    for row in selected_references:
        case_id = row.get("case_id", "")
        case = positive_cases.get(case_id)
        if case is None:
            failures["reference_not_positive_case"] += 1
        elif row.get("target_family", "") != case.get("target_family", ""):
            failures["reference_family_mismatch"] += 1
    for case_id, case in positive_cases.items():
        expected = int(float(str(case.get("silver_finding_n", 0))))
        if references_by_case[case_id] != expected:
            failures["reference_count_mismatch"] += 1

    all_references = (
        all_case_references
        if all_case_references is not None
        else [
            {
                **row,
                "case_target_family": row.get("target_family", ""),
                "reference_family": row.get("target_family", ""),
                "reference_role": "target_reference",
            }
            for row in selected_references
        ]
    )
    selected_identities = {
        (
            row.get("case_id", ""),
            row.get("target_family", ""),
            row.get("rule_id", ""),
            row.get("file_path", ""),
            row.get("start_line", ""),
            row.get("fingerprint", ""),
        )
        for row in selected_references
    }
    all_target_identities: set[tuple[str, ...]] = set()
    for row in all_references:
        case_id = row.get("case_id", "")
        case = case_by_id.get(case_id)
        if case is None:
            failures["all_reference_unknown_case"] += 1
            continue
        target_family = case.get("target_family", "")
        reference_family = (
            row.get("reference_family", "")
            or row.get("target_family", "")
        )
        expected_role = (
            "target_reference"
            if reference_family == target_family
            else "off_target_reference"
        )
        if row.get("case_target_family", target_family) != target_family:
            failures["all_reference_case_family_mismatch"] += 1
        if row.get("reference_role", expected_role) != expected_role:
            failures["all_reference_role_mismatch"] += 1
        if reference_family not in {"quality", "security"}:
            failures["all_reference_invalid_family"] += 1
        if expected_role == "target_reference":
            if case.get("case_control") != "positive":
                failures["target_reference_on_control"] += 1
            all_target_identities.add(
                (
                    case_id,
                    reference_family,
                    row.get("rule_id", ""),
                    row.get("file_path", ""),
                    row.get("start_line", ""),
                    row.get("fingerprint", ""),
                )
            )
    if all_target_identities != selected_identities:
        failures["selected_all_reference_mismatch"] += 1

    distribution = Counter(
        (
            row.get("target_family", ""),
            row.get("case_control", ""),
            row.get("group", ""),
        )
        for row in cases
    )
    return {
        "schema_version": "1.0.0",
        "status": "passed" if not failures else "failed",
        "checks": {
            "packet_case_count": len(packets) == len(cases),
            "case_key_count": len(keys) == len(cases),
            "unique_case_ids": len(case_by_id) == len(cases),
            "unique_prs": unique_pr_n == len(cases),
            "identity_leakage_zero": identity_leak_n == 0,
            "packet_hashes_complete": not any(
                name in failures
                for name in {
                    "packet_hash_mismatch",
                    "key_packet_hash_mismatch",
                }
            ),
            "chunk_hashes_complete": not any(
                name in failures
                for name in {
                    "chunk_hash_mismatch",
                    "chunk_count_mismatch",
                    "chunk_index_mismatch",
                    "chunk_over_limit",
                    "chunk_missing_file_identity",
                    "chunk_invalid_file_context",
                }
            ),
            "diff_reconstruction_complete": (
                failures.get("diff_reconstruction_mismatch", 0) == 0
                and failures.get("case_missing_source_diff", 0) == 0
            ),
            "selected_reference_counts_conserved": (
                failures.get("reference_not_positive_case", 0) == 0
                and failures.get("reference_family_mismatch", 0) == 0
                and failures.get("reference_count_mismatch", 0) == 0
            ),
            "all_family_reference_set_valid": not any(
                name in failures
                for name in {
                    "all_reference_unknown_case",
                    "all_reference_case_family_mismatch",
                    "all_reference_role_mismatch",
                    "all_reference_invalid_family",
                    "target_reference_on_control",
                    "selected_all_reference_mismatch",
                }
            ),
        },
        "counts": {
            "case_n": len(cases),
            "unique_pr_n": unique_pr_n,
            "packet_n": len(packets),
            "chunk_n": reconstructed_chunk_n,
            "selected_reference_alert_n": len(selected_references),
            "all_case_reference_alert_n": len(all_references),
            "off_target_reference_alert_n": sum(
                (
                    row.get("reference_role")
                    or (
                        "target_reference"
                        if row.get("reference_family", "")
                        == row.get("case_target_family", "")
                        else "off_target_reference"
                    )
                )
                == "off_target_reference"
                for row in all_references
            ),
            "metadata_identity_leak_n": identity_leak_n,
        },
        "case_distribution": {
            "|".join(str(value) for value in key): count
            for key, count in sorted(distribution.items())
        },
        "failures": dict(sorted(failures.items())),
    }


def main() -> None:
    args = parse_args()
    cases_path = Path(args.cases)
    diffs_path = Path(args.diffs)
    prompt_path = Path(args.prompt)
    schema_path = Path(args.schema)
    output = Path(args.output_dir)
    selected_references_path = (
        Path(args.selected_reference_alerts)
        if args.selected_reference_alerts
        else cases_path.parent / "selected_reference_alerts.csv"
    )
    all_references_path = (
        Path(args.all_case_reference_alerts)
        if args.all_case_reference_alerts
        else cases_path.parent / "all_case_reference_alerts.csv"
    )
    if not selected_references_path.exists():
        raise FileNotFoundError(
            "缺少 selected reference alerts: "
            f"{selected_references_path}"
        )
    if not all_references_path.exists():
        raise FileNotFoundError(
            "缺少 all-case reference alerts: "
            f"{all_references_path}"
        )
    cases = read_csv(cases_path)
    diffs = read_jsonl(diffs_path)
    selected_references = read_csv(selected_references_path)
    all_references = read_csv(all_references_path)
    packets, keys = build_packets(cases, diffs, args.max_chars)
    write_jsonl(output / "llm_review_packets.jsonl", packets)
    if keys:
        output.mkdir(parents=True, exist_ok=True)
        with (output / "llm_review_case_key.csv").open(
            "w", newline="", encoding="utf-8"
        ) as stream:
            writer = csv.DictWriter(stream, fieldnames=list(keys[0]))
            writer.writeheader()
            writer.writerows(keys)
    audit = audit_packet_artifacts(
        cases,
        diffs,
        read_jsonl(output / "llm_review_packets.jsonl"),
        read_csv(output / "llm_review_case_key.csv"),
        selected_references,
        args.max_chars,
        all_references,
        (
            40
            if cases
            and {row.get("split", "") for row in cases} == {"pilot"}
            else None
        ),
    )
    audit_path = output / "packet_audit.json"
    audit_path.write_text(
        json.dumps(audit, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    if audit["status"] != "passed":
        raise RuntimeError(
            "packet 完整性/泄漏审计失败: "
            + json.dumps(audit["failures"], ensure_ascii=False)
        )
    manifest = {
        "schema_version": "1.1.0",
        "cases_sha256": sha256_file(cases_path),
        "diffs_sha256": sha256_file(diffs_path),
        "selected_reference_alerts_sha256": sha256_file(
            selected_references_path
        ),
        "all_case_reference_alerts_sha256": sha256_file(
            all_references_path
        ),
        "prompt_sha256": sha256_file(prompt_path),
        "schema_sha256": sha256_file(schema_path),
        "packet_file_sha256": sha256_file(output / "llm_review_packets.jsonl"),
        "case_key_sha256": sha256_file(output / "llm_review_case_key.csv"),
        "packet_audit_sha256": sha256_file(audit_path),
        "packet_n": len(packets),
        "chunk_n": sum(len(row["chunks"]) for row in packets),
        "selected_reference_alert_n": len(selected_references),
        "all_case_reference_alert_n": len(all_references),
        "max_chars": args.max_chars,
    }
    (output / "packet_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"已生成盲化 packet {len(packets)} 个: {output}")


if __name__ == "__main__":
    main()
