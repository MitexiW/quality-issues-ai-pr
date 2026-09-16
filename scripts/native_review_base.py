#!/usr/bin/env python3
"""Run a blinded, read-only Claude Agent SDK /code-review invocation.

The command consumes worktrees produced by prepare_claude_review_worktrees.py.
It performs an offline preflight by default.  A real API request is made only
when --execute is supplied explicitly and the configured API-key environment
variable is non-empty.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import dataclasses
import hashlib
import importlib.metadata
import json
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Sequence

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    PermissionResultAllow,
    PermissionResultDeny,
    ResultMessage,
    ToolUseBlock,
    query,
)
import claude_agent_sdk

import record_llm_review_output as response_validation


SCHEMA_VERSION = "1.4.0"
CLAUDE_MODEL_RE = re.compile(r"^claude-[a-z0-9][a-z0-9.-]*$")
DEEPSEEK_MODEL_RE = re.compile(
    r"^deepseek-v4-(?:pro(?:\[1m\])?|flash)$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
PROVIDER_DEFAULTS = {
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/anthropic",
        "api_key_env": "ANTHROPIC_AUTH_TOKEN",
    },
}
NEUTRAL_AUTHOR = "RQ3 Benchmark <rq3-benchmark@invalid>"
READ_ONLY_TOOLS = ("Read", "Glob", "Grep", "Bash")
REPORT_FINDINGS_TOOL = "ReportFindings"
DISALLOWED_TOOLS = (
    "Write",
    "Edit",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
)
READ_ONLY_GIT_SUBCOMMANDS = {
    "diff",
    "grep",
    "log",
    "ls-files",
    "rev-list",
    "rev-parse",
    "show",
    "status",
}
READ_ONLY_EXECUTABLES = {
    "cat",
    "cut",
    "file",
    "find",
    "grep",
    "head",
    "rg",
    "sed",
    "sort",
    "tail",
    "uniq",
    "wc",
}
SHELL_MUTATION_RE = re.compile(r"[;&|><`\n\r]|\$\(")
WORKTREE_KEY_FIELDS = {
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
}
WORKTREE_IDENTITY_AUDIT_FIELDS = (
    "pending_diff_sha256",
    "base_tree_sha",
    "status_sha256",
)
NATIVE_REPORT_TOP_LEVEL_FIELDS = {"level", "findings"}
NATIVE_REPORT_REQUIRED_FINDING_FIELDS = {
    "file",
    "summary",
    "failure_scenario",
}
NATIVE_REPORT_OPTIONAL_FINDING_FIELDS = {
    "line",
    "short_summary",
    "category",
    "verdict",
    "outcome",
}
NATIVE_REPORT_LEVELS = {"low", "medium", "high", "xhigh", "max"}
NATIVE_REPORT_VERDICTS = {"CONFIRMED", "PLAUSIBLE"}
NATIVE_REPORT_OUTCOMES = {"fixed", "skipped", "no_change_needed"}
FENCED_BLOCK_RE = re.compile(
    r"```(?P<label>[^\n`]*)\n(?P<body>.*?)\n```",
    re.DOTALL,
)


class ClaudeReviewError(ValueError):
    """Raised when an invocation cannot be executed without violating protocol."""


class InvalidModelOutputError(ClaudeReviewError):
    """Raised when a successful model call violates the response contract."""


class ProviderRequestError(ClaudeReviewError):
    """Provider/transport failed; this is not an assessed, unrecovered issue."""


def is_provider_error_text(value: object) -> bool:
    # Claude CLI can emit an API error as a success ResultMessage. Match only
    # its leading diagnostic, not error strings quoted inside real findings.
    return isinstance(value, str) and value.lstrip().startswith("API Error:")


def has_recorded_provider_error(directory: Path) -> bool:
    stream = directory / "raw_sdk_messages.jsonl"
    if not stream.exists():
        return False
    with stream.open(encoding="utf-8") as source:
        for line in source:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue  # An active or interrupted writer may leave a partial line.
            if is_provider_error_text(record.get("result")):
                return True
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="预检或执行盲化、只读的 Claude Agent SDK /code-review"
    )
    parser.add_argument("--worktree-root", required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument(
        "--provider",
        required=True,
        choices=tuple(PROVIDER_DEFAULTS),
        help="实际提供模型推理的 API provider；与 Claude Code review surface 区分",
    )
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--effort",
        required=True,
        choices=("low", "medium", "high", "xhigh", "max"),
    )
    parser.add_argument(
        "--max-budget-usd",
        required=False,
        type=float,
        help=(
            "传给 SDK 的 best-effort 限额；对 DeepSeek compatible endpoint "
            "不是可靠的 provider 侧硬支出上限"
        ),
    )
    parser.add_argument("--no-sdk-budget", action="store_true", help="Explicitly disable SDK dollar limit")
    parser.add_argument("--max-turns", type=int, default=30)
    parser.add_argument(
        "--prompt",
        default="config/study/claude_code_review_prompt.txt",
    )
    parser.add_argument(
        "--output-schema",
        default="config/study/llm_review_output_schema.json",
    )
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--base-url",
        help="provider endpoint；省略时使用所选 provider 的官方默认值",
    )
    parser.add_argument(
        "--api-key-env",
        help="只记录并读取环境变量名；省略时使用所选 provider 的默认变量",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="实际调用模型；未提供时仅执行离线 preflight",
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


def worktree_identity_projection(audit: dict[str, Any]) -> dict[str, Any]:
    try:
        return {key: audit[key] for key in WORKTREE_IDENTITY_AUDIT_FIELDS}
    except KeyError as exc:
        raise ClaudeReviewError(
            f"worktree audit lacks identity field: {exc.args[0]}"
        ) from None


def canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def run_git(repo: Path, arguments: list[str]) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
        },
    )
    if result.returncode:
        raise ClaudeReviewError(
            f"Git audit failed ({result.returncode}): git {' '.join(arguments)}: "
            f"{result.stderr.strip()}"
        )
    return result.stdout


def run_git_bytes(repo: Path, arguments: list[str]) -> bytes:
    """Run a Git audit command without universal-newline byte rewriting."""
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        check=False,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
        },
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ClaudeReviewError(
            f"Git audit failed ({result.returncode}): git {' '.join(arguments)}: "
            f"{detail}"
        )
    return result.stdout


def read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ClaudeReviewError(f"{label} does not exist: {path}") from None
    except json.JSONDecodeError as exc:
        raise ClaudeReviewError(
            f"{label} is invalid JSON: {path}:{exc.lineno}"
        ) from None


def normalize_output_schema_for_cli(
    output_schema: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    normalized = json.loads(json.dumps(output_schema))
    transforms: list[str] = []
    declared_draft = normalized.get("$schema")
    if declared_draft == "https://json-schema.org/draft/2020-12/schema":
        # Claude Code CLI 2.1.220 rejects the 2020-12 meta-schema URI even
        # though this experiment schema uses only keywords supported by its
        # default dialect. Removing only the dialect declaration preserves all
        # validation constraints while retaining the original frozen file.
        del normalized["$schema"]
        transforms.append("removed_top_level_draft_2020_12_declaration")
    return normalized, transforms


def read_worktree_key(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            fields = set(reader.fieldnames or [])
            rows = list(reader)
    except FileNotFoundError:
        raise ClaudeReviewError(f"worktree key does not exist: {path}") from None
    except csv.Error as exc:
        raise ClaudeReviewError(f"worktree key is invalid CSV: {exc}") from None
    if fields != WORKTREE_KEY_FIELDS:
        raise ClaudeReviewError(
            "worktree key schema mismatch: "
            f"missing={sorted(WORKTREE_KEY_FIELDS - fields)} "
            f"extra={sorted(fields - WORKTREE_KEY_FIELDS)}"
        )
    if not rows:
        raise ClaudeReviewError("worktree key must not be empty")
    return rows


def load_case(worktree_root: Path, case_id: str) -> tuple[dict[str, str], Path]:
    manifest_path = worktree_root / "manifest.json"
    manifest = read_json(manifest_path, "worktree manifest")
    if not isinstance(manifest, dict):
        raise ClaudeReviewError("worktree manifest must be an object")
    if manifest.get("status") != "passed":
        raise ClaudeReviewError("worktree manifest status must be passed")
    key_path = worktree_root / "worktree_key.csv"
    output = manifest.get("outputs", {}).get("worktree_key", {})
    if output.get("sha256") != sha256_file(key_path):
        raise ClaudeReviewError("worktree key hash does not match manifest")
    matches = [row for row in read_worktree_key(key_path) if row["case_id"] == case_id]
    if len(matches) != 1:
        raise ClaudeReviewError(f"case_id must resolve exactly once: {case_id}")
    row = matches[0]
    relative = Path(row["worktree_relpath"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ClaudeReviewError("worktree path must stay below worktree root")
    repo = (worktree_root / relative).resolve()
    try:
        repo.relative_to(worktree_root.resolve())
    except ValueError:
        raise ClaudeReviewError("worktree path escapes worktree root") from None
    if not repo.is_dir():
        raise ClaudeReviewError(f"review repository does not exist: {repo}")
    return row, repo


def audit_repo(repo: Path, row: dict[str, str]) -> dict[str, Any]:
    expected_hash = row["pending_diff_sha256"]
    if not SHA256_RE.fullmatch(expected_hash):
        raise ClaudeReviewError("pending_diff_sha256 is invalid")
    if run_git(repo, ["remote"]).strip():
        raise ClaudeReviewError("review repository must not have a remote")
    if run_git(repo, ["rev-list", "--count", "HEAD"]).strip() != "1":
        raise ClaudeReviewError("review repository must have exactly one commit")
    author = run_git(repo, ["log", "-1", "--format=%an <%ae>"]).strip()
    if author != NEUTRAL_AUTHOR:
        raise ClaudeReviewError(f"review repository author is not neutral: {author}")
    tree = run_git(repo, ["rev-parse", "HEAD^{tree}"]).strip()
    if tree != row["base_tree_sha"]:
        raise ClaudeReviewError("review repository base tree hash changed")
    staged_tree = run_git(repo, ["write-tree"]).strip()
    if staged_tree != row["head_tree_sha"]:
        raise ClaudeReviewError("review repository staged head tree hash changed")
    unstaged = run_git_bytes(
        repo,
        ["diff", "--binary", "--no-ext-diff", "--no-color"],
    )
    if unstaged:
        raise ClaudeReviewError("review repository contains unstaged tracked changes")
    diff = run_git_bytes(
        repo,
        ["diff", "--cached", "HEAD", "--binary", "--no-ext-diff", "--no-color"],
    )
    if not diff.strip():
        raise ClaudeReviewError("review repository pending diff is empty")
    actual_hash = sha256_bytes(diff)
    changed_paths = run_git_bytes(
        repo,
        ["diff", "--cached", "HEAD", "--name-only", "-z", "--no-ext-diff"],
    )
    changed_file_n = len(
        [path for path in changed_paths.split(b"\0") if path]
    )
    if changed_file_n != int(row["changed_file_n"]):
        raise ClaudeReviewError("review repository changed-file count changed")
    status = run_git(repo, ["status", "--porcelain=v1"])
    if any(line.startswith("?? ") for line in status.splitlines()):
        raise ClaudeReviewError("review repository contains unaudited untracked files")
    return {
        "pending_diff_sha256": actual_hash,
        "recorded_pending_diff_sha256": expected_hash,
        "pending_diff_hash_matches_recorded": actual_hash == expected_hash,
        "base_tree_sha": tree,
        "head_tree_sha": staged_tree,
        "changed_file_n": changed_file_n,
        "status_sha256": sha256_bytes(status.encode("utf-8")),
    }


def validate_model(model: str, provider: str = "anthropic") -> str:
    model = model.strip()
    if provider == "anthropic" and CLAUDE_MODEL_RE.fullmatch(model):
        return model
    if provider == "deepseek" and DEEPSEEK_MODEL_RE.fullmatch(model):
        return model
    if provider == "anthropic":
        raise ClaudeReviewError(
            "model must be a full Claude model ID beginning with 'claude-'; "
            "aliases such as opus or sonnet are not frozen identifiers"
        )
    if provider == "deepseek":
        raise ClaudeReviewError(
            "DeepSeek model must be one of deepseek-v4-pro, "
            "deepseek-v4-pro[1m], or deepseek-v4-pro[1m]"
        )
    raise ClaudeReviewError(f"unsupported provider: {provider}")


def resolve_backend_model(provider: str, model: str) -> str:
    if provider == "deepseek" and model.endswith("[1m]"):
        return model.removesuffix("[1m]")
    return model


def validate_base_url(provider: str, value: str | None) -> str:
    try:
        expected = str(PROVIDER_DEFAULTS[provider]["base_url"])
    except KeyError:
        raise ClaudeReviewError(f"unsupported provider: {provider}") from None
    actual = (value or expected).strip().rstrip("/")
    if actual != expected:
        raise ClaudeReviewError(
            f"{provider} base URL must be the frozen official endpoint: {expected}"
        )
    return actual


def validate_budget(value: float) -> float:
    if not (value > 0 and value <= 1000):
        raise ClaudeReviewError("max-budget-usd must be > 0 and <= 1000")
    return value


def validate_api_key_env(name: str, execute: bool) -> str:
    if not ENV_NAME_RE.fullmatch(name):
        raise ClaudeReviewError("api-key-env must be an uppercase environment name")
    if execute and not os.environ.get(name):
        raise ClaudeReviewError(
            f"--execute requires a non-empty {name} environment variable"
        )
    return name


def resolve_provider_config(
    *,
    provider: str,
    model: str,
    base_url: str | None,
    api_key_env: str | None,
    execute: bool,
) -> dict[str, str]:
    if provider not in PROVIDER_DEFAULTS:
        raise ClaudeReviewError(f"unsupported provider: {provider}")
    requested_model = validate_model(model, provider)
    resolved_key_env = api_key_env or str(
        PROVIDER_DEFAULTS[provider]["api_key_env"]
    )
    return {
        "provider": provider,
        "base_url": validate_base_url(provider, base_url),
        "requested_model": requested_model,
        "resolved_backend_model": resolve_backend_model(
            provider, requested_model
        ),
        "api_key_env": validate_api_key_env(resolved_key_env, execute),
        "api_protocol": "anthropic-compatible",
    }


def resolve_response_contract(provider: str) -> dict[str, Any]:
    if provider == "deepseek":
        return {
            "mode": "claude_code_report_findings_tool",
            "provider_constrained_decoding": False,
            "sdk_output_format_sent": False,
            "preferred_sdk_field": "assistant_tool_use",
            "native_tool_name": REPORT_FINDINGS_TOOL,
            "json_repair": False,
            "field_synthesis": False,
            "arbitrary_markdown_fence_stripping": False,
            "strict_single_fenced_json_array_extraction": True,
            "inline_fallback": "one_fenced_json_array_locally_validated",
            "reason": (
                "DeepSeek Anthropic compatibility supports only effort in "
                "output_config; the bundled local /code-review workflow "
                "provides its own typed, read-only ReportFindings tool, while "
                "DeepSeek may return the same native finding objects in one "
                "fenced JSON array instead of issuing the client-side tool call"
            ),
        }
    if provider == "anthropic":
        return {
            "mode": "sdk_structured_output",
            "provider_constrained_decoding": True,
            "sdk_output_format_sent": True,
            "preferred_sdk_field": "structured_output",
            "json_repair": False,
            "markdown_fence_stripping": False,
            "reason": "Anthropic structured outputs are enabled for this adapter",
        }
    raise ClaudeReviewError(f"unsupported provider: {provider}")


def build_provider_runtime_env(provider_config: dict[str, str]) -> dict[str, str]:
    key_env = provider_config["api_key_env"]
    secret = os.environ.get(key_env)
    if not secret:
        raise ClaudeReviewError(
            f"execution requires a non-empty {key_env} environment variable"
        )
    runtime_env = {
        "ANTHROPIC_BASE_URL": provider_config["base_url"],
        "ANTHROPIC_MODEL": provider_config["requested_model"],
    }
    if provider_config["provider"] == "deepseek":
        # DeepSeek documents ANTHROPIC_AUTH_TOKEN for Claude Code.  The
        # bundled CLI's --bare mode documents ANTHROPIC_API_KEY as its only
        # accepted Anthropic-compatible credential, so provide the same
        # in-memory secret under both names to the child process.  Neither
        # value is serialized.
        runtime_env["ANTHROPIC_AUTH_TOKEN"] = secret
        runtime_env["ANTHROPIC_API_KEY"] = secret
    else:
        runtime_env["ANTHROPIC_API_KEY"] = secret
        runtime_env["ANTHROPIC_AUTH_TOKEN"] = ""
    return runtime_env


def is_read_only_bash(command: str) -> bool:
    if not command.strip() or SHELL_MUTATION_RE.search(command):
        return False
    try:
        words = shlex.split(command)
    except ValueError:
        return False
    if not words:
        return False
    executable = Path(words[0]).name
    if executable == "git":
        return len(words) >= 2 and words[1] in READ_ONLY_GIT_SUBCOMMANDS
    if executable == "find" and any(
        word in {"-delete", "-exec", "-execdir", "-fprint", "-fls", "-ok"}
        for word in words[1:]
    ):
        return False
    if executable == "sed" and any(
        word == "-i" or word.startswith("-i") for word in words[1:]
    ):
        return False
    if executable == "sort" and any(
        word == "-o" or word.startswith("--output") for word in words[1:]
    ):
        return False
    return executable in READ_ONLY_EXECUTABLES


async def read_only_permission(
    tool_name: str,
    tool_input: dict[str, Any],
    _context: Any,
) -> PermissionResultAllow | PermissionResultDeny:
    if tool_name in {"Read", "Glob", "Grep"}:
        return PermissionResultAllow()
    if tool_name == REPORT_FINDINGS_TOOL:
        return PermissionResultAllow()
    if tool_name == "Bash" and is_read_only_bash(str(tool_input.get("command", ""))):
        return PermissionResultAllow()
    return PermissionResultDeny(
        message=f"RQ3 benchmark denies non-read-only tool use: {tool_name}",
        interrupt=False,
    )


def serialize(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: serialize(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, dict):
        return {str(key): serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [serialize(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


def sdk_versions() -> dict[str, str]:
    package_version = importlib.metadata.version("claude-agent-sdk")
    cli = Path(claude_agent_sdk.__file__).resolve().parent / "_bundled/claude"
    if not cli.is_file():
        raise ClaudeReviewError(f"bundled Claude Code CLI not found: {cli}")
    result = subprocess.run(
        [str(cli), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ClaudeReviewError(
            f"cannot read bundled Claude Code version: {result.stderr.strip()}"
        )
    return {
        "claude_agent_sdk": package_version,
        "bundled_claude_code_cli": result.stdout.strip(),
    }


def build_options(
    *,
    repo: Path,
    model: str,
    effort: str,
    max_budget_usd: float,
    max_turns: int,
    protocol: str,
    output_schema: dict[str, Any],
    provider_runtime_env: dict[str, str] | None = None,
    enable_sdk_structured_output: bool = True,
    enable_native_report_tool: bool = False,
    can_use_tool: Callable[..., Any] | None = None,
    hooks: dict[str, list[Any]] | None = None,
    allowed_tools: Sequence[str] | None = None,
) -> ClaudeAgentOptions:
    tools = list(READ_ONLY_TOOLS if allowed_tools is None else allowed_tools)
    unknown_tools = set(tools) - set(READ_ONLY_TOOLS)
    if unknown_tools:
        raise ClaudeReviewError(
            f"unsupported read-only tools requested: {sorted(unknown_tools)}"
        )
    if len(tools) != len(set(tools)):
        raise ClaudeReviewError("allowed read-only tools must be unique")
    if enable_native_report_tool:
        tools.append(REPORT_FINDINGS_TOOL)
    return ClaudeAgentOptions(
        # The SDK defaults to a 1 MiB JSONL message buffer.  Read-only Bash or
        # Grep results from large repositories can legitimately exceed that
        # size even when the final adjudication is small.  Keep the transport
        # ceiling comfortably above observed messages without changing the
        # model context, turn budget, or response-validation protocol.
        max_buffer_size=64 * 1024 * 1024,
        tools=tools,
        system_prompt={
            "type": "preset",
            "preset": "claude_code",
            "append": protocol,
            "exclude_dynamic_sections": False,
        },
        mcp_servers={},
        strict_mcp_config=True,
        permission_mode="default",
        max_turns=max_turns,
        max_budget_usd=max_budget_usd,
        disallowed_tools=list(DISALLOWED_TOOLS),
        model=model,
        cwd=repo,
        env={
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GH_TOKEN": "",
            "GITHUB_TOKEN": "",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            **(provider_runtime_env or {}),
        },
        extra_args={
            "bare": None,
            "no-session-persistence": None,
            "no-chrome": None,
        },
        can_use_tool=can_use_tool or read_only_permission,
        setting_sources=[],
        sandbox={
            "enabled": True,
            "autoAllowBashIfSandboxed": False,
            "allowUnsandboxedCommands": False,
            "network": {
                "allowedDomains": [],
                "deniedDomains": ["*"],
                "allowManagedDomainsOnly": True,
                "allowAllUnixSockets": False,
                "allowLocalBinding": False,
            },
        },
        effort=effort,  # type: ignore[arg-type]
        output_format=(
            {"type": "json_schema", "schema": output_schema}
            if enable_sdk_structured_output
            else None
        ),
        hooks=hooks,
    )


async def collect_review(
    options: ClaudeAgentOptions,
    query_fn: Callable[..., AsyncIterator[Any]] = query,
    on_message: Callable[[Any], None] | None = None,
) -> tuple[list[Any], ResultMessage]:
    async def prompt_stream() -> AsyncIterator[dict[str, Any]]:
        yield {
            "type": "user",
            "session_id": "",
            "message": {"role": "user", "content": "/code-review"},
            "parent_tool_use_id": None,
        }

    messages: list[Any] = []
    result_messages: list[ResultMessage] = []
    async for message in query_fn(prompt=prompt_stream(), options=options):
        messages.append(message)
        if on_message is not None:
            on_message(message)
        if isinstance(message, ResultMessage):
            result_messages.append(message)
    if len(result_messages) != 1:
        raise ClaudeReviewError(
            f"SDK returned {len(result_messages)} ResultMessage objects; expected 1"
        )
    return messages, result_messages[0]


def extract_review_response(
    result: ResultMessage,
    *,
    messages: list[Any],
    repo: Path,
    expected_effort: str,
    response_contract: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    if is_provider_error_text(result.result):
        raise ProviderRequestError("Provider API request failed; inspect retained SDK transcript")
    if result.is_error:
        detail = "; ".join(result.errors or []) or result.result or result.subtype
        raise ClaudeReviewError(f"Claude review failed: {detail}")
    if response_contract["mode"] == "claude_code_report_findings_tool":
        calls = native_report_calls(messages)
        if calls:
            response = extract_native_report_findings(
                messages,
                repo=repo,
                expected_effort=expected_effort,
            )
            source = "claude_code_report_findings_tool"
        else:
            response = extract_fenced_native_report(
                result.result,
                repo=repo,
            )
            source = "result_text_single_fenced_native_json_array"
    elif (
        response_contract["mode"] == "sdk_structured_output"
        and isinstance(result.structured_output, dict)
    ):
        response = result.structured_output
        source = "sdk_structured_output"
        response_validation.validate_response(response)
    else:
        raise ClaudeReviewError(
            "Claude review did not return provider-guaranteed structured_output"
        )
    return response, source


def changed_paths(repo: Path) -> set[str]:
    return {
        line.strip()
        for line in run_git(
            repo,
            ["diff", "HEAD", "--name-only", "--no-ext-diff", "--no-color"],
        ).splitlines()
        if line.strip()
    }


def validate_native_finding(
    finding: Any,
    *,
    index: int,
    repo: Path,
    allow_absolute_under_repo: bool = False,
) -> dict[str, Any]:
    if not isinstance(finding, dict):
        raise ClaudeReviewError(
            f"{REPORT_FINDINGS_TOOL} finding {index} must be an object"
        )
    fields = set(finding)
    allowed_fields = (
        NATIVE_REPORT_REQUIRED_FINDING_FIELDS
        | NATIVE_REPORT_OPTIONAL_FINDING_FIELDS
    )
    if not NATIVE_REPORT_REQUIRED_FINDING_FIELDS.issubset(fields):
        missing = sorted(NATIVE_REPORT_REQUIRED_FINDING_FIELDS - fields)
        raise ClaudeReviewError(
            f"{REPORT_FINDINGS_TOOL} finding {index} missing fields: {missing}"
        )
    if fields - allowed_fields:
        raise ClaudeReviewError(
            f"{REPORT_FINDINGS_TOOL} finding {index} has unsupported fields: "
            f"{sorted(fields - allowed_fields)}"
        )
    normalized = dict(finding)
    for field in ("file", "summary", "failure_scenario"):
        value = normalized[field]
        if not isinstance(value, str) or not value.strip():
            raise ClaudeReviewError(
                f"{REPORT_FINDINGS_TOOL} finding {index} {field} must be non-empty"
            )
        normalized[field] = value.strip()
    path = Path(normalized["file"].replace("\\", "/"))
    if path.is_absolute():
        if not allow_absolute_under_repo:
            raise ClaudeReviewError(
                f"{REPORT_FINDINGS_TOOL} finding {index} file must be repo-relative"
            )
        try:
            path = path.resolve().relative_to(repo.resolve())
        except ValueError:
            raise ClaudeReviewError(
                f"{REPORT_FINDINGS_TOOL} finding {index} absolute file escapes "
                "the reviewed repository"
            ) from None
    if ".." in path.parts:
        raise ClaudeReviewError(
            f"{REPORT_FINDINGS_TOOL} finding {index} file must be repo-relative"
        )
    relative_path = path.as_posix().removeprefix("./")
    if not relative_path:
        raise ClaudeReviewError(
            f"{REPORT_FINDINGS_TOOL} finding {index} file must be repo-relative"
        )
    normalized["file"] = relative_path
    if "line" in normalized:
        line = normalized["line"]
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            raise ClaudeReviewError(
                f"{REPORT_FINDINGS_TOOL} finding {index} line must be a "
                "positive integer"
            )
    for field, maximum in (("short_summary", 60), ("category", 40)):
        if field in normalized:
            value = normalized[field]
            if not isinstance(value, str) or not value.strip():
                raise ClaudeReviewError(
                    f"{REPORT_FINDINGS_TOOL} finding {index} {field} must be "
                    "non-empty"
                )
            if len(value) > maximum:
                raise ClaudeReviewError(
                    f"{REPORT_FINDINGS_TOOL} finding {index} {field} exceeds "
                    f"{maximum} characters"
                )
            normalized[field] = value.strip()
    if (
        "verdict" in normalized
        and normalized["verdict"] not in NATIVE_REPORT_VERDICTS
    ):
        raise ClaudeReviewError(
            f"{REPORT_FINDINGS_TOOL} finding {index} verdict is invalid"
        )
    if "outcome" in normalized:
        if normalized["outcome"] not in NATIVE_REPORT_OUTCOMES:
            raise ClaudeReviewError(
                f"{REPORT_FINDINGS_TOOL} finding {index} outcome is invalid"
            )
        raise ClaudeReviewError(
            f"{REPORT_FINDINGS_TOOL} finding {index} unexpectedly reports an "
            "outcome although --fix was not enabled"
        )
    return normalized


def audit_finding_scope(
    findings: list[dict[str, Any]],
    *,
    repo: Path,
) -> dict[str, Any]:
    """Record semantic path violations as reviewer outcomes, not run failures."""
    pending_paths = changed_paths(repo)
    rows = []
    for index, finding in enumerate(findings):
        relative_path = str(finding.get("file", ""))
        rows.append(
            {
                "finding_index": index,
                "file": relative_path,
                "in_pending_diff": relative_path in pending_paths,
                "exists_in_reviewed_repository": (repo / relative_path).is_file(),
            }
        )
    return {
        "finding_n": len(rows),
        "in_pending_diff_n": sum(row["in_pending_diff"] for row in rows),
        "outside_pending_diff_n": sum(
            not row["in_pending_diff"] for row in rows
        ),
        "nonexistent_file_n": sum(
            not row["exists_in_reviewed_repository"] for row in rows
        ),
        "findings": rows,
    }


def native_report_calls(messages: list[Any]) -> list[ToolUseBlock]:
    return [
        block
        for message in messages
        if isinstance(message, AssistantMessage)
        for block in message.content
        if isinstance(block, ToolUseBlock)
        and block.name == REPORT_FINDINGS_TOOL
    ]


def extract_native_report_findings(
    messages: list[Any],
    *,
    repo: Path,
    expected_effort: str,
) -> dict[str, Any]:
    calls = native_report_calls(messages)
    if len(calls) != 1:
        raise ClaudeReviewError(
            f"Claude Code emitted {len(calls)} {REPORT_FINDINGS_TOOL} tool "
            "calls; expected exactly 1. Prose or fenced JSON is not repaired."
        )
    payload = calls[0].input
    if not isinstance(payload, dict) or set(payload) - NATIVE_REPORT_TOP_LEVEL_FIELDS:
        raise ClaudeReviewError(
            f"{REPORT_FINDINGS_TOOL} input has an invalid top-level schema"
        )
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ClaudeReviewError(
            f"{REPORT_FINDINGS_TOOL} input must contain a findings array"
        )
    if len(findings) > 32:
        raise ClaudeReviewError(
            f"{REPORT_FINDINGS_TOOL} contains more than 32 findings"
        )
    level = payload.get("level")
    if level is not None:
        if level not in NATIVE_REPORT_LEVELS:
            raise ClaudeReviewError(
                f"{REPORT_FINDINGS_TOOL} level is invalid: {level!r}"
            )
        if level != expected_effort:
            raise ClaudeReviewError(
                f"{REPORT_FINDINGS_TOOL} level {level!r} does not match "
                f"requested effort {expected_effort!r}"
            )
    normalized_findings = [
        validate_native_finding(
            finding,
            index=index,
            repo=repo,
        )
        for index, finding in enumerate(findings)
    ]
    return {
        "level": level,
        "findings": normalized_findings,
    }


def extract_fenced_native_report(
    result_text: str | None,
    *,
    repo: Path,
) -> dict[str, Any]:
    if not isinstance(result_text, str) or not result_text.strip():
        raise ClaudeReviewError(
            "DeepSeek returned neither ReportFindings nor non-empty result text"
        )
    blocks = list(FENCED_BLOCK_RE.finditer(result_text))
    json_blocks = [
        match
        for match in blocks
        if match.group("label").strip().casefold() == "json"
    ]
    if len(blocks) != 1 or len(json_blocks) != 1:
        raise ClaudeReviewError(
            "DeepSeek inline fallback must contain exactly one fenced JSON "
            "block and no other fenced blocks; no repair was applied"
        )
    try:
        payload = json.loads(json_blocks[0].group("body"))
    except json.JSONDecodeError as exc:
        raise ClaudeReviewError(
            "DeepSeek inline finding array is invalid JSON "
            f"(line {exc.lineno}, column {exc.colno}); no repair was applied"
        ) from None
    if not isinstance(payload, list):
        raise ClaudeReviewError(
            "DeepSeek inline fallback JSON must be an array; no repair was applied"
        )
    if len(payload) > 32:
        raise ClaudeReviewError(
            "DeepSeek inline fallback contains more than 32 findings"
        )
    findings = [
        validate_native_finding(
            finding,
            index=index,
            repo=repo,
            allow_absolute_under_repo=True,
        )
        for index, finding in enumerate(payload)
    ]
    return {"level": None, "findings": findings}


def ensure_new_output(path: Path) -> None:
    if path.exists():
        raise ClaudeReviewError(f"output directory already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir()


def build_failure_record(
    *,
    preflight: dict[str, Any],
    error: Exception,
    api_key_env: str,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    message = str(error)
    secret = os.environ.get(api_key_env, "")
    if secret:
        message = message.replace(secret, "[REDACTED]")
    failure = {
        "schema_version": SCHEMA_VERSION,
        "status": "failed",
        "failed_at_utc": datetime.now(timezone.utc).isoformat(),
        "preflight_sha256": preflight["preflight_sha256"],
        "error_type": type(error).__name__,
        "error_message": message,
        "credential_value_persisted": False,
    }
    if output_dir is not None:
        artifacts = {}
        for name in (
            "raw_sdk_messages.jsonl",
            "raw_sdk_transcript.json",
            "result_metadata.json",
        ):
            path = output_dir / name
            if path.is_file():
                artifacts[name] = {
                    "path": name,
                    "sha256": sha256_file(path),
                }
        if artifacts:
            failure["retained_artifacts"] = artifacts
    failure["failure_sha256"] = sha256_bytes(canonical_bytes(failure))
    return failure


def build_preflight(
    *,
    case_id: str,
    row: dict[str, str],
    worktree_root: Path,
    repo: Path,
    audit: dict[str, Any],
    model: str,
    effort: str,
    max_budget_usd: float,
    max_turns: int,
    prompt_path: Path,
    schema_path: Path,
    cli_output_schema: dict[str, Any],
    schema_transforms: list[str],
    provider_config: dict[str, str],
    response_contract: dict[str, Any],
    execute: bool,
) -> dict[str, Any]:
    enabled_tools = list(READ_ONLY_TOOLS)
    if response_contract["mode"] == "claude_code_report_findings_tool":
        enabled_tools.append(REPORT_FINDINGS_TOOL)
    native_contract = {
        "tool_name": REPORT_FINDINGS_TOOL,
        "top_level_fields": sorted(NATIVE_REPORT_TOP_LEVEL_FIELDS),
        "required_finding_fields": sorted(
            NATIVE_REPORT_REQUIRED_FINDING_FIELDS
        ),
        "optional_finding_fields": sorted(
            NATIVE_REPORT_OPTIONAL_FINDING_FIELDS
        ),
        "maximum_findings": 32,
        "accepted_response_sources": [
            "claude_code_report_findings_tool",
            "result_text_single_fenced_native_json_array",
        ],
        "inline_fallback_policy": {
            "exact_fenced_block_n": 1,
            "required_fence_label": "json",
            "payload_type": "array",
            "absolute_path_normalization": "only_when_below_reviewed_repo",
        },
        "path_policy": (
            "stored_repo_relative; outside-diff or nonexistent paths are "
            "retained as reviewer outcomes and audited separately"
        ),
        "line_policy": "positive_integer_when_present",
        "normalization": (
            "trim_strings; normalize absolute path only below reviewed repo"
        ),
        "json_or_prose_repair": False,
        "field_synthesis": False,
    }
    native_contract["contract_sha256"] = sha256_bytes(
        canonical_bytes(native_contract)
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "status": "execution_authorized" if execute else "dry_run_preflight_passed",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "review_surface": "Claude Agent SDK local /code-review",
        "case_id": case_id,
        "model": model,
        "model_backend": provider_config,
        "effort": effort,
        "max_budget_usd": max_budget_usd,
        "budget_control": {
            "sdk_max_budget_usd": max_budget_usd,
            "semantics": (
                "no_sdk_dollar_limit" if max_budget_usd is None else
                "best_effort_not_a_hard_provider_spend_cap"
                if provider_config["provider"] == "deepseek"
                else "sdk_budget_limit"
            ),
            "provider_side_spend_guard_present": False,
        },
        "max_turns": max_turns,
        "api_key_env": provider_config["api_key_env"],
        "sdk_versions": sdk_versions(),
        "worktree": {
            "manifest_path": str((worktree_root / "manifest.json").resolve()),
            "manifest_sha256": sha256_file(worktree_root / "manifest.json"),
            "repo_path": str(repo),
            "base_tree_sha": row["base_tree_sha"],
            **audit,
        },
        "protocol": {
            "path": str(prompt_path.resolve()),
            "sha256": sha256_file(prompt_path),
        },
        "output_schema": {
            "path": str(schema_path.resolve()),
            "sha256": sha256_file(schema_path),
            "cli_schema_sha256": (
                sha256_bytes(canonical_bytes(cli_output_schema))
                if response_contract["sdk_output_format_sent"]
                else None
            ),
            "cli_compatibility_transforms": schema_transforms,
            "sent_to_cli": response_contract["sdk_output_format_sent"],
            "role": (
                "provider_structured_output_contract"
                if response_contract["sdk_output_format_sent"]
                else "not_used_by_native_report_tool"
            ),
        },
        "native_report_contract": (
            native_contract
            if response_contract["mode"]
            == "claude_code_report_findings_tool"
            else None
        ),
        "response_contract": response_contract,
        "permissions": {
            "tools": enabled_tools,
            "disallowed_tools": list(DISALLOWED_TOOLS),
            "bash_policy": "explicit read-only allowlist",
            "network_for_reviewer_tools": "denied",
            "remote_present": False,
            "session_persistence": False,
        },
    }
    payload["preflight_sha256"] = sha256_bytes(canonical_bytes(payload))
    return payload


async def execute_review(
    *,
    preflight: dict[str, Any],
    options: ClaudeAgentOptions,
    repo: Path,
    row: dict[str, str],
    output_dir: Path,
    response_contract: dict[str, Any],
    query_fn: Callable[..., AsyncIterator[Any]] = query,
) -> dict[str, Any]:
    started = time.monotonic()
    message_stream_path = output_dir / "raw_sdk_messages.jsonl"
    with message_stream_path.open("x", encoding="utf-8") as message_stream:
        def retain_message(message: Any) -> None:
            message_stream.write(
                json.dumps(
                    serialize(message),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
            message_stream.flush()

        messages, result = await collect_review(
            options,
            query_fn=query_fn,
            on_message=retain_message,
        )
    latency_ms = round((time.monotonic() - started) * 1000)
    transcript = {
        "schema_version": SCHEMA_VERSION,
        "preflight_sha256": preflight["preflight_sha256"],
        "messages": serialize(messages),
    }
    raw_path = output_dir / "raw_sdk_transcript.json"
    raw_path.write_text(
        json.dumps(transcript, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    result_metadata = {
        "schema_version": SCHEMA_VERSION,
        "preflight_sha256": preflight["preflight_sha256"],
        "latency_ms": latency_ms,
        "result_subtype": result.subtype,
        "is_error": result.is_error,
        "num_turns": result.num_turns,
        "total_cost_usd": result.total_cost_usd,
        "usage": serialize(result.usage),
        "model_usage": serialize(result.model_usage),
        "has_structured_output": isinstance(result.structured_output, dict),
        "result_text_sha256": (
            sha256_bytes(result.result.encode("utf-8"))
            if isinstance(result.result, str)
            else None
        ),
    }
    result_metadata_path = output_dir / "result_metadata.json"
    result_metadata_path.write_text(
        json.dumps(result_metadata, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    try:
        response, response_source = extract_review_response(
            result,
            messages=messages,
            repo=repo,
            expected_effort=preflight["effort"],
            response_contract=response_contract,
        )
    except ClaudeReviewError as exc:
        if result.is_error or isinstance(exc, ProviderRequestError):
            raise
        raise InvalidModelOutputError(str(exc)) from None
    finding_scope_audit = audit_finding_scope(
        response["findings"],
        repo=repo,
    )
    post_audit = audit_repo(repo, row)
    if worktree_identity_projection(post_audit) != worktree_identity_projection(
        preflight["worktree"]
    ):
        raise ClaudeReviewError("reviewer changed the worktree during execution")
    response_path = output_dir / "review_response.json"
    response_path.write_text(
        json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    execution = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "preflight_sha256": preflight["preflight_sha256"],
        "latency_ms": latency_ms,
        "result_subtype": result.subtype,
        "num_turns": result.num_turns,
        "total_cost_usd": result.total_cost_usd,
        "usage": serialize(result.usage),
        "model_usage": serialize(result.model_usage),
        "response_source": response_source,
        "response_contract": response_contract,
        "raw_sdk_messages": {
            "path": message_stream_path.name,
            "sha256": sha256_file(message_stream_path),
        },
        "raw_sdk_transcript": {
            "path": raw_path.name,
            "sha256": sha256_file(raw_path),
        },
        "result_metadata": {
            "path": result_metadata_path.name,
            "sha256": sha256_file(result_metadata_path),
        },
        "review_response": {
            "path": response_path.name,
            "sha256": sha256_file(response_path),
        },
        "finding_scope_audit": finding_scope_audit,
        "post_review_worktree_audit": post_audit,
    }
    execution["execution_sha256"] = sha256_bytes(canonical_bytes(execution))
    return execution


def main() -> None:
    args = parse_args()
    try:
        worktree_root = Path(args.worktree_root).expanduser().resolve()
        prompt_path = Path(args.prompt).expanduser().resolve()
        schema_path = Path(args.output_schema).expanduser().resolve()
        output_dir = Path(args.output_dir).expanduser().resolve()
        provider_config = resolve_provider_config(
            provider=args.provider,
            model=args.model,
            base_url=args.base_url,
            api_key_env=args.api_key_env,
            execute=args.execute,
        )
        response_contract = resolve_response_contract(args.provider)
        model = provider_config["requested_model"]
        if args.no_sdk_budget:
            if args.max_budget_usd is not None:
                raise ClaudeReviewError("--no-sdk-budget conflicts with --max-budget-usd")
            max_budget_usd = None
        else:
            if args.max_budget_usd is None:
                raise ClaudeReviewError("Provide --max-budget-usd or explicitly --no-sdk-budget")
            max_budget_usd = validate_budget(args.max_budget_usd)
        if args.max_turns < 1:
            raise ClaudeReviewError("max-turns must be >= 1")
        protocol = prompt_path.read_text(encoding="utf-8")
        output_schema = read_json(schema_path, "output schema")
        if not isinstance(output_schema, dict):
            raise ClaudeReviewError("output schema must be an object")
        if response_contract["sdk_output_format_sent"]:
            cli_output_schema, schema_transforms = normalize_output_schema_for_cli(
                output_schema
            )
        else:
            cli_output_schema, schema_transforms = output_schema, []
        row, repo = load_case(worktree_root, args.case_id)
        audit = audit_repo(repo, row)
        preflight = build_preflight(
            case_id=args.case_id,
            row=row,
            worktree_root=worktree_root,
            repo=repo,
            audit=audit,
            model=model,
            effort=args.effort,
            max_budget_usd=max_budget_usd,
            max_turns=args.max_turns,
            prompt_path=prompt_path,
            schema_path=schema_path,
            cli_output_schema=cli_output_schema,
            schema_transforms=schema_transforms,
            provider_config=provider_config,
            response_contract=response_contract,
            execute=args.execute,
        )
        ensure_new_output(output_dir)
        (output_dir / "preflight.json").write_text(
            json.dumps(preflight, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if not args.execute:
            print(
                "Claude /code-review 离线 preflight 通过；"
                "未提供 --execute，未调用模型、未产生费用"
            )
            return
        if max_budget_usd is None:
            print("SDK dollar limit disabled; API charges still apply.", flush=True)
        elif provider_config["provider"] == "deepseek":
            print(
                "WARNING: --max-budget-usd 对 DeepSeek compatible endpoint "
                "不是可靠的硬支出上限；批量运行必须另设 provider-side 总支出保护。",
                file=sys.stderr,
            )
        options = build_options(
            repo=repo,
            model=model,
            effort=args.effort,
            max_budget_usd=max_budget_usd,
            max_turns=args.max_turns,
            protocol=protocol,
            output_schema=cli_output_schema,
            provider_runtime_env=build_provider_runtime_env(provider_config),
            enable_sdk_structured_output=response_contract[
                "sdk_output_format_sent"
            ],
            enable_native_report_tool=(
                response_contract["mode"]
                == "claude_code_report_findings_tool"
            ),
        )
        try:
            execution = asyncio.run(
                execute_review(
                    preflight=preflight,
                    options=options,
                    repo=repo,
                    row=row,
                    output_dir=output_dir,
                    response_contract=response_contract,
                )
            )
        except (
            ClaudeReviewError,
            claude_agent_sdk.ClaudeSDKError,
            OSError,
            ValueError,
        ) as exc:
            failure = build_failure_record(
                preflight=preflight,
                error=exc,
                api_key_env=provider_config["api_key_env"],
                output_dir=output_dir,
            )
            (output_dir / "failure.json").write_text(
                json.dumps(
                    failure,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            raise ClaudeReviewError(
                f"Claude Code review failed; details recorded in "
                f"{output_dir / 'failure.json'}: {failure['error_message']}"
            ) from exc
        (output_dir / "execution.json").write_text(
            json.dumps(execution, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            "Claude Code /code-review 完成："
            f"provider={provider_config['provider']}，"
            f"model={provider_config['resolved_backend_model']}，"
            f"case={args.case_id}，turns={execution['num_turns']}，"
            f"cost_usd={execution['total_cost_usd']}"
        )
    except (ClaudeReviewError, OSError) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
