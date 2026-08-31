#!/usr/bin/env python3
# RQ3 review experiment entry point.
"""Read and record DeepSeek account balance without invoking a model."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_ENDPOINT = "https://api.deepseek.com/user/balance"


class BalanceCheckError(RuntimeError):
    """Raised when the read-only provider balance check cannot be completed."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="只读查询 DeepSeek 余额；不调用模型，不产生推理费用"
    )
    parser.add_argument("--api-key-env", default="ANTHROPIC_AUTH_TOKEN")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def fetch_balance(
    *,
    api_key_env: str,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: float = 30.0,
) -> dict[str, Any]:
    if endpoint != DEFAULT_ENDPOINT:
        raise BalanceCheckError(
            f"refusing non-official DeepSeek balance endpoint: {endpoint}"
        )
    if timeout <= 0:
        raise BalanceCheckError("timeout must be positive")
    token = os.environ.get(api_key_env, "")
    if not token:
        raise BalanceCheckError(f"environment variable is empty: {api_key_env}")
    request = urllib.request.Request(
        endpoint,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "aipr-codeql-rq3-balance-check/1.0",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        raise BalanceCheckError(
            f"DeepSeek balance endpoint returned HTTP {exc.code}"
        ) from None
    except urllib.error.URLError as exc:
        raise BalanceCheckError(
            f"DeepSeek balance request failed: {exc.reason}"
        ) from None
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BalanceCheckError(
            f"DeepSeek balance response is not valid JSON: {exc}"
        ) from None
    if not isinstance(value, dict):
        raise BalanceCheckError("DeepSeek balance response must be a JSON object")
    if not isinstance(value.get("is_available"), bool):
        raise BalanceCheckError("DeepSeek balance response lacks boolean is_available")
    balances = value.get("balance_infos")
    if not isinstance(balances, list):
        raise BalanceCheckError("DeepSeek balance response lacks balance_infos")
    sanitized: list[dict[str, str]] = []
    expected = {
        "currency",
        "total_balance",
        "granted_balance",
        "topped_up_balance",
    }
    for index, balance in enumerate(balances):
        if not isinstance(balance, dict) or not expected.issubset(balance):
            raise BalanceCheckError(f"invalid balance_infos entry at index {index}")
        sanitized.append({field: str(balance[field]) for field in sorted(expected)})
    result: dict[str, Any] = {
        "schema_version": "1.0.0",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "endpoint": endpoint,
        "request_type": "read_only_balance_check",
        "model_invocation": False,
        "api_key_env": api_key_env,
        "api_key_persisted": False,
        "is_available": value["is_available"],
        "balance_infos": sanitized,
    }
    result["record_sha256"] = hashlib.sha256(canonical_bytes(result)).hexdigest()
    return result


def main() -> None:
    args = parse_args()
    try:
        result = fetch_balance(
            api_key_env=args.api_key_env,
            endpoint=args.endpoint,
            timeout=args.timeout,
        )
    except BalanceCheckError as exc:
        raise SystemExit(f"DeepSeek 余额查询失败: {exc}") from None
    rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        output = args.output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            raise SystemExit(f"拒绝覆盖已有余额记录: {output}")
        output.write_text(rendered, encoding="utf-8")
        print(f"DeepSeek 余额记录已保存（无 API key）: {output}")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
