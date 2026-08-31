"""Prompt construction and strict response validation for alert adjudication."""

from __future__ import annotations

import copy
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Sequence

import jsonschema


FENCED_JSON_RE = re.compile(r"\A\s*```json\s*\n(?P<body>.*)\n```\s*\Z", re.DOTALL)
PROMPT_ALERT_FIELDS = (
    "alert_id",
    "rule_id",
    "rule_name",
    "problem_severity",
    "precision",
    "issue_domain",
    "quality_category",
    "rule_tags",
    "file_path",
    "start_line",
    "message",
)


class AdjudicationProtocolError(ValueError):
    """Raised when an input or model response violates the frozen protocol."""


def normalize_logically_entailed_attribution(
    payload: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Canonicalize one logically forced attribution value.

    This is deliberately narrower than response repair.  It never creates a
    row or field and never changes the model's condition/validity/actionability
    judgment.  When the model has already said that the reported condition is
    absent, that the alert is invalid, and that no fix is warranted, the
    condition cannot simultaneously have been introduced by the PR.  Some
    compatible structured-output providers nevertheless emit ``uncertain`` or
    ``yes`` for that dependent field.  Preserve an explicit audit record while
    canonicalizing only this logical consequence.
    """

    normalized = copy.deepcopy(payload)
    changes: list[dict[str, str]] = []
    rows = normalized.get("adjudications")
    if not isinstance(rows, list):
        return normalized, changes
    for row in rows:
        if not isinstance(row, dict):
            continue
        if (
            row.get("condition_present") == "no"
            and row.get("valid_issue") == "no"
            and row.get("actionability") == "no_fix"
            and row.get("introduced_by_pr") in {"yes", "uncertain"}
        ):
            previous = str(row["introduced_by_pr"])
            row["introduced_by_pr"] = "no"
            changes.append(
                {
                    "alert_id": clean(row.get("alert_id")),
                    "field": "introduced_by_pr",
                    "from": previous,
                    "to": "no",
                    "rule": "condition_present=no logically implies introduced_by_pr=no",
                }
            )
    return normalized, changes


def clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def prompt_projection(alert: dict[str, str]) -> dict[str, str]:
    projected = {field: clean(alert.get(field)) for field in PROMPT_ALERT_FIELDS}
    if not projected["alert_id"] or not projected["rule_id"]:
        raise AdjudicationProtocolError("alert lacks alert_id or rule_id")
    path = Path(projected["file_path"].replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.as_posix():
        raise AdjudicationProtocolError(
            f"alert has unsafe file path: {projected['alert_id']}"
        )
    projected["file_path"] = path.as_posix()
    return projected


def build_user_prompt(
    alerts: Sequence[dict[str, str]],
    *,
    provider: str,
) -> str:
    if not alerts:
        raise AdjudicationProtocolError("adjudication batch must not be empty")
    projected = [prompt_projection(alert) for alert in alerts]
    identifiers = [row["alert_id"] for row in projected]
    if len(identifiers) != len(set(identifiers)):
        raise AdjudicationProtocolError("adjudication batch has duplicate alert IDs")
    payload = json.dumps(projected, ensure_ascii=False, indent=2, sort_keys=True)
    exact_partition = (
        f"The response must contain exactly {len(projected)} adjudications, "
        "with every supplied alert_id appearing exactly once. An empty or "
        "partial adjudications array is invalid."
    )
    ending = (
        "Return one exact JSON document conforming to the supplied schema. "
        "Do not wrap it in Markdown."
        if provider == "anthropic"
        else (
            "Return one exact JSON document, either as raw JSON or inside one "
            "```json fenced block. Do not include prose or any other fenced block."
        )
    )
    return "\n\n".join(
        [
            "Adjudicate the following frozen alert batch. Inspect the repository "
            "before deciding; do not merely restate rule metadata.",
            payload,
            exact_partition,
            ending,
        ]
    )


def parse_exact_json_document(text: str) -> dict[str, Any]:
    stripped = text.strip()
    match = FENCED_JSON_RE.fullmatch(stripped)
    candidate = match.group("body") if match else stripped
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError as exc:
        # Compatible endpoints sometimes wrap an otherwise exact response in
        # one JSON fence plus a short prose sentence. Accept only that
        # unambiguous presentation wrapper; never alter JSON or synthesize
        # fields.
        fenced = list(
            re.finditer(
                r"```json\s*\n(?P<body>.*?)\n```",
                stripped,
                re.DOTALL | re.IGNORECASE,
            )
        )
        if len(fenced) != 1 or stripped.count("```") != 2:
            raise AdjudicationProtocolError(
                "model result is not raw JSON or one unambiguous fenced JSON "
                f"document (line {exc.lineno}, column {exc.colno}); "
                "no repair was applied"
            ) from None
        try:
            payload = json.loads(fenced[0].group("body"))
        except json.JSONDecodeError as fenced_exc:
            raise AdjudicationProtocolError(
                "the single fenced response is not valid JSON "
                f"(line {fenced_exc.lineno}, column {fenced_exc.colno}); "
                "no repair was applied"
            ) from None
    if not isinstance(payload, dict):
        raise AdjudicationProtocolError("model result must be a JSON object")
    return payload


def normalized_evidence(
    repo: Path, raw_path: Any, revision: Any
) -> tuple[str, str, bytes]:
    path = Path(clean(raw_path).replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.as_posix():
        raise AdjudicationProtocolError("evidence path must be repository-relative")
    revision_name = clean(revision)
    if revision_name == "head":
        resolved = (repo / path).resolve()
        try:
            resolved.relative_to(repo.resolve())
        except ValueError:
            raise AdjudicationProtocolError("evidence path escapes repository") from None
        if not resolved.is_file():
            raise AdjudicationProtocolError(
                f"evidence file does not exist in head tree: {path.as_posix()}"
            )
        payload = resolved.read_bytes()
    elif revision_name == "before":
        result = subprocess.run(
            ["git", "show", f"HEAD:{path.as_posix()}"],
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={
                **os.environ,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_NO_LAZY_FETCH": "1",
            },
        )
        if result.returncode:
            raise AdjudicationProtocolError(
                f"evidence file does not exist in before tree: {path.as_posix()}"
            )
        payload = result.stdout
    else:
        raise AdjudicationProtocolError(
            f"evidence revision must be before or head: {revision_name}"
        )
    return revision_name, path.as_posix(), payload


def validate_response(
    payload: dict[str, Any],
    *,
    expected_alert_ids: Sequence[str],
    schema: dict[str, Any],
    repo: Path,
) -> dict[str, Any]:
    try:
        jsonschema.Draft202012Validator(schema).validate(payload)
    except jsonschema.ValidationError as exc:
        location = "/".join(str(part) for part in exc.absolute_path)
        raise AdjudicationProtocolError(
            f"model response violates schema at {location or '<root>'}: {exc.message}"
        ) from None
    rows = payload.get("adjudications")
    if not isinstance(rows, list):
        raise AdjudicationProtocolError("adjudications must be an array")
    expected = list(expected_alert_ids)
    observed = [clean(row.get("alert_id")) for row in rows]
    if len(observed) != len(set(observed)):
        raise AdjudicationProtocolError("model response contains duplicate alert IDs")
    if set(observed) != set(expected) or len(observed) != len(expected):
        raise AdjudicationProtocolError(
            "model response alert IDs do not exactly match the requested batch: "
            f"missing={sorted(set(expected) - set(observed))} "
            f"extra={sorted(set(observed) - set(expected))}"
        )

    by_id = {clean(row["alert_id"]): dict(row) for row in rows}
    normalized_rows: list[dict[str, Any]] = []
    for alert_id in expected:
        row = by_id[alert_id]
        condition = row["condition_present"]
        validity = row["valid_issue"]
        actionability = row["actionability"]
        if condition == "no" and validity != "no":
            raise AdjudicationProtocolError(
                f"{alert_id}: condition_present=no requires valid_issue=no"
            )
        if condition == "no" and row["introduced_by_pr"] != "no":
            raise AdjudicationProtocolError(
                f"{alert_id}: condition_present=no requires introduced_by_pr=no"
            )
        if condition == "no" and actionability != "no_fix":
            raise AdjudicationProtocolError(
                f"{alert_id}: condition_present=no requires actionability=no_fix"
            )
        if condition == "uncertain" and (
            validity != "uncertain"
            or row["introduced_by_pr"] != "uncertain"
            or actionability != "uncertain"
        ):
            raise AdjudicationProtocolError(
                f"{alert_id}: uncertain condition requires uncertain validity, "
                "attribution, and actionability"
            )
        if validity in {"no", "contextual_exception"} and actionability != "no_fix":
            raise AdjudicationProtocolError(
                f"{alert_id}: invalid/contextual alerts require actionability=no_fix"
            )
        if validity == "uncertain" and actionability != "uncertain":
            raise AdjudicationProtocolError(
                f"{alert_id}: uncertain validity requires uncertain actionability"
            )
        if actionability in {"must_fix", "should_fix", "optional"} and validity != "yes":
            raise AdjudicationProtocolError(
                f"{alert_id}: actionable decision requires valid_issue=yes"
            )
        evidence_rows: list[dict[str, Any]] = []
        for evidence in row["evidence"]:
            revision, relative, payload = normalized_evidence(
                repo, evidence["file"], evidence["revision"]
            )
            line = int(evidence["line"])
            line_n = len(payload.splitlines())
            if line > max(line_n, 1):
                raise AdjudicationProtocolError(
                    f"{alert_id}: {revision} evidence line {line} exceeds "
                    f"{relative} length {line_n}"
                )
            evidence_rows.append(
                {
                    "revision": revision,
                    "file": relative,
                    "line": line,
                    "explanation": clean(evidence["explanation"]),
                }
            )
        row["alert_id"] = alert_id
        row["rationale"] = clean(row["rationale"])
        row["evidence"] = evidence_rows
        normalized_rows.append(row)
    return {"adjudications": normalized_rows}
