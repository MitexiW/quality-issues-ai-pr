#!/usr/bin/env python3
"""Match LLM reports to CodeQL reference alerts and compute guarded RQ3 metrics."""

from __future__ import annotations

import argparse
import csv
import json
import hashlib
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="评估盲化 LLM Quality/Security alert recovery")
    parser.add_argument("--case-key", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--silver-findings")
    source.add_argument("--confirmed-findings", help="已弃用的兼容别名")
    parser.add_argument("--outputs", required=True)
    parser.add_argument("--adjudication")
    parser.add_argument("--matches-output", required=True)
    parser.add_argument("--metrics-output", required=True)
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def normalize_path(value: str) -> str:
    return re.sub(r"^(?:a|b)/", "", (value or "").replace("\\", "/").lower())


def normalize_weakness(value: str) -> set[str]:
    words = set(re.findall(r"[a-z0-9]+", (value or "").lower()))
    stop = {
        "cwe",
        "security",
        "vulnerability",
        "issue",
        "weakness",
        "uncontrolled",
        "externally",
        "data",
        "information",
        "improper",
        "use",
    }
    return words - stop


QUALITY_CATEGORIES = {
    "correctness_reliability",
    "maintainability",
    "performance_efficiency",
    "portability",
    "other_quality",
}
SECURITY_DISTINCTIVE_TOKENS = {
    "csrf",
    "cryptography",
    "redos",
    "ssrf",
    "xss",
}


CWE_ALIASES = {
    "014": "compiler optimization sensitive memory clearing memset deletion",
    "020": "input validation sanitization escaping encoding",
    "022": "path traversal filesystem path",
    "023": "path traversal filesystem path",
    "036": "path traversal filesystem path",
    "073": "path traversal filesystem path",
    "078": "command injection shell operating system",
    "079": "xss cross site scripting html",
    "080": "sanitization encoding escaping",
    "088": "command injection argument shell",
    "094": "code execution",
    "099": "path traversal filesystem path",
    "116": "output encoding escaping sanitization",
    "117": "log logging forging",
    "134": "format string",
    "184": "incomplete validation blacklist",
    "190": "integer overflow",
    "197": "numeric truncation conversion",
    "200": "sensitive information disclosure exfiltration",
    "209": "stack trace exception disclosure",
    "250": "privilege execution",
    "252": "unchecked return error handling",
    "307": "rate limiting authentication attempts",
    "312": "cleartext sensitive information",
    "327": "cryptography algorithm",
    "338": "randomness random predictable",
    "352": "csrf cross site request forgery",
    "359": "privacy sensitive information",
    "367": "race condition time check use",
    "377": "temporary file",
    "378": "temporary file permissions",
    "384": "session fixation",
    "400": "resource exhaustion denial service",
    "434": "file upload write",
    "471": "prototype pollution object modification",
    "497": "system information disclosure",
    "532": "sensitive log logging",
    "570": "expression always false",
    "601": "open redirect url redirection",
    "730": "regular expression regex redos",
    "755": "exception error handling",
    "770": "resource allocation exhaustion",
    "834": "loop excessive iteration",
    "912": "hidden functionality file write",
    "915": "prototype pollution object modification",
    "918": "ssrf server side request forgery",
    "1333": "redos regular expression regex polynomial",
}


def truth_weakness_descriptor(truth: dict[str, str]) -> str:
    parts = [
        truth.get("quality_category", ""),
        truth.get("weakness_category", ""),
        truth.get("rule_id", ""),
        truth.get("rule_name", ""),
        truth.get("cwe", ""),
    ]
    cwe_ids = re.findall(r"CWE[-_ ]?(\d+)", truth.get("cwe", ""), re.I)
    parts.extend(CWE_ALIASES.get(identifier, "") for identifier in cwe_ids)
    return " ".join(part for part in parts if part)


def interval_overlap(
    first_start: Any, first_end: Any, second_start: Any, second_end: Any
) -> bool:
    try:
        a0 = int(first_start)
        a1 = int(first_end or first_start)
        b0 = int(second_start)
        b1 = int(second_end or second_start)
    except (TypeError, ValueError):
        return False
    return max(a0, b0) <= min(a1, b1)


def weakness_compatible(first: str, second: str) -> bool:
    a = normalize_weakness(first)
    b = normalize_weakness(second)
    overlap = a & b
    return bool(
        a
        and b
        and (
            len(overlap) >= 2
            or bool(overlap & SECURITY_DISTINCTIVE_TOKENS)
            or (a == b and len(a) == 1)
        )
    )


def category_compatible(model: dict[str, Any], truth: dict[str, str]) -> bool:
    family = alert_family(truth)
    reported = str(model.get("weakness_category", "")).strip().casefold()
    if family == "quality":
        expected = str(truth.get("quality_category", "")).strip().casefold()
        return (
            expected in QUALITY_CATEGORIES
            and reported == expected
        )
    if family == "security":
        return weakness_compatible(
            reported,
            truth_weakness_descriptor(truth),
        )
    return False


def alert_family(row: dict[str, Any]) -> str:
    family = str(
        row.get("alert_category") or row.get("issue_family") or ""
    ).strip().lower()
    if family in {"quality", "security"}:
        return family
    if str(row.get("is_quality_alert", "")).lower() in {"1", "true", "yes"}:
        return "quality"
    if str(row.get("is_security_alert", "")).lower() in {"1", "true", "yes"}:
        return "security"
    return ""


def silver_finding_id(row: dict[str, Any]) -> str:
    existing = str(
        row.get("silver_finding_id") or row.get("finding_id") or ""
    ).strip()
    if existing:
        return existing
    identity = [
        row.get("case_id", ""),
        row.get("rule_id", ""),
        normalize_path(str(row.get("file_path", ""))),
        row.get("start_line", ""),
        row.get("fingerprint", ""),
        row.get("message", ""),
    ]
    return "sf-" + hashlib.sha256(
        json.dumps(identity, ensure_ascii=False).encode()
    ).hexdigest()[:20]


def attach_truths_to_cases(
    case_key: list[dict[str, str]],
    truths: list[dict[str, str]],
) -> list[dict[str, str]]:
    positive_cases = [
        row for row in case_key if row.get("case_control") == "positive"
    ]
    attached: list[dict[str, str]] = []
    for truth in truths:
        if truth.get("case_id"):
            attached.append(truth)
            continue
        family = alert_family(truth)
        candidates = [
            case
            for case in positive_cases
            if case.get("repo_name", "").lower()
            == truth.get("repo_name", "").lower()
            and case.get("pr_number", "") == truth.get("pr_number", "")
            and (not family or case.get("target_family", "") == family)
            and (
                not truth.get("group")
                or case.get("group", "").lower()
                == truth.get("group", "").lower()
            )
        ]
        if len(candidates) != 1:
            raise ValueError(
                "silver finding 无法唯一关联 case: "
                f"{truth.get('repo_name')}#{truth.get('pr_number')} "
                f"family={family or 'unknown'} candidates={len(candidates)}"
            )
        attached.append({**truth, "case_id": candidates[0]["case_id"]})
    return attached


def exact_candidate(model: dict[str, Any], truth: dict[str, str]) -> bool:
    model_family = alert_family(model)
    truth_family = alert_family(truth)
    if model_family and truth_family and model_family != truth_family:
        return False
    if normalize_path(str(model.get("file_path", ""))) != normalize_path(
        truth.get("file_path", "")
    ):
        return False
    location = interval_overlap(
        model.get("line_start"),
        model.get("line_end"),
        truth.get("start_line"),
        truth.get("end_line") or truth.get("start_line"),
    )
    same_hunk = bool(
        model.get("hunk_header")
        and truth.get("hunk_header")
        and model["hunk_header"].strip() == truth["hunk_header"].strip()
    )
    return (location or same_hunk) and category_compatible(model, truth)


def collapse_output_attempts(
    outputs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse append-only retries to one final record per review job.

    Historical invalid attempts remain auditable in the source JSONL but do
    not make a subsequently successful job incomplete. More than one valid
    response for the same job is rejected because it would make the selected
    model output ambiguous.
    """

    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for output in outputs:
        job = (
            output.get("run_id", ""),
            output.get("model_id", ""),
            output.get("packet_id", ""),
            int(output.get("repetition", 1)),
            int(output.get("chunk_index", 1)),
        )
        grouped[job].append(output)
    collapsed: list[dict[str, Any]] = []
    for job, attempts in grouped.items():
        valid = [row for row in attempts if row.get("status") == "valid"]
        if len(valid) > 1:
            raise ValueError(f"同一 RQ3 job 有多个 valid response: {job}")
        collapsed.append(valid[0] if valid else attempts[-1])
    return sorted(
        collapsed,
        key=lambda row: (
            row.get("run_id", ""),
            row.get("model_id", ""),
            int(row.get("repetition", 1)),
            row.get("packet_id", ""),
            int(row.get("chunk_index", 1)),
        ),
    )


def build_matches(
    case_key: list[dict[str, str]],
    truths: list[dict[str, str]],
    outputs: list[dict[str, Any]],
    adjudications: list[dict[str, str]],
) -> list[dict[str, Any]]:
    key_by_packet = {row["packet_id"]: row for row in case_key}
    truths_by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for truth in truths:
        truths_by_case[truth["case_id"]].append(truth)
    adjudication = {
        row["model_finding_id"]: row
        for row in adjudications
        if row.get("model_finding_id")
    }
    rows: list[dict[str, Any]] = []
    for output in outputs:
        if output.get("status") != "valid":
            continue
        key = key_by_packet.get(output["packet_id"])
        if key is None:
            raise ValueError(f"输出引用未知 packet_id: {output['packet_id']}")
        for finding in output.get("findings", []):
            target_family = key.get("target_family", "")
            model_family = alert_family(finding)
            case_truths = truths_by_case.get(key["case_id"], [])
            target_truths = [
                truth
                for truth in case_truths
                if alert_family(truth) == target_family
            ]
            normalized_model_path = normalize_path(
                str(finding.get("file_path", ""))
            )
            file_candidates = [
                truth
                for truth in target_truths
                if normalized_model_path
                == normalize_path(truth.get("file_path", ""))
            ]
            location_candidates = [
                truth
                for truth in file_candidates
                if interval_overlap(
                    finding.get("line_start"),
                    finding.get("line_end"),
                    truth.get("start_line"),
                    truth.get("end_line") or truth.get("start_line"),
                )
                or bool(
                    finding.get("hunk_header")
                    and truth.get("hunk_header")
                    and str(finding["hunk_header"]).strip()
                    == str(truth["hunk_header"]).strip()
                )
            ]
            candidates = [
                truth
                for truth in case_truths
                if exact_candidate(finding, truth)
            ]
            decision = adjudication.get(finding["model_finding_id"], {})
            matched_reference_family = ""
            reference_role = ""
            if len(candidates) == 1:
                linked = silver_finding_id(candidates[0])
                matched_reference_family = alert_family(candidates[0])
                reference_role = (
                    "target_reference"
                    if matched_reference_family == target_family
                    else "off_target_reference"
                )
                status = (
                    "compatible_location_recovery"
                    if reference_role == "target_reference"
                    else "off_target_reference_recovery"
                )
            elif len(candidates) > 1:
                linked = ""
                status = "ambiguous_semantic_candidate"
            else:
                linked = ""
                if model_family and model_family != target_family:
                    status = "off_target_family_report"
                elif not finding.get("line_start") and not finding.get(
                    "hunk_header"
                ):
                    status = "invalid_or_unlocalized_report"
                else:
                    status = "unmatched_to_codeql"
            rows.append(
                {
                    "run_id": output.get("run_id", ""),
                    "model_id": output.get("model_id", ""),
                    "repetition": output.get("repetition", 1),
                    "chunk_index": output.get("chunk_index", 1),
                    "packet_id": output["packet_id"],
                    "case_id": key["case_id"],
                    "case_control": key["case_control"],
                    "target_family": target_family,
                    "group": key["group"],
                    "repo_name": key["repo_name"],
                    "pr_number": key["pr_number"],
                    "model_finding_id": finding["model_finding_id"],
                    "silver_finding_id": linked,
                    "matched_reference_family": matched_reference_family,
                    "reference_role": reference_role,
                    "match_status": status,
                    "automatic_exact_candidate_n": len(candidates),
                    "issue_family": finding.get("issue_family", ""),
                    "file_path": finding.get("file_path", ""),
                    "line_start": finding.get("line_start"),
                    "line_end": finding.get("line_end"),
                    "weakness_category": finding.get("weakness_category", ""),
                    "severity": finding.get("severity", ""),
                    "is_target_family_report": int(
                        model_family == target_family
                    ),
                    "target_reference_file_candidate_n": len(file_candidates),
                    "target_reference_location_candidate_n": len(
                        location_candidates
                    ),
                    "adjudication_decision": decision.get("decision", ""),
                    "adjudication_reference_id": (
                        decision.get("silver_finding_id")
                        or decision.get("confirmed_finding_id", "")
                    ),
                    "requires_adjudication": 0,
                }
            )
    return rows


def safe_ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else math.nan


def metrics(
    case_key: list[dict[str, str]],
    truths: list[dict[str, str]],
    matches: list[dict[str, Any]],
    outputs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    all_truths_by_case: dict[str, set[str]] = defaultdict(set)
    target_truths_by_case: dict[str, set[str]] = defaultdict(set)
    case_by_id = {row["case_id"]: row for row in case_key}
    for truth in truths:
        case = case_by_id.get(truth["case_id"])
        if case is None:
            raise ValueError(
                f"reference 引用未知 case_id: {truth['case_id']}"
            )
        finding_id = silver_finding_id(truth)
        all_truths_by_case[truth["case_id"]].add(finding_id)
        if alert_family(truth) == case.get("target_family", ""):
            target_truths_by_case[truth["case_id"]].add(finding_id)
    key_by_packet = {row["packet_id"]: row for row in case_key}
    output_strata = set()
    for output in outputs:
        key_row = key_by_packet.get(output.get("packet_id", ""))
        if key_row is None:
            raise ValueError(f"输出引用未知 packet_id: {output.get('packet_id', '')}")
        output_strata.add(
            (
                output.get("run_id", ""),
                output.get("model_id", ""),
                int(output.get("repetition", 1)),
                key_row["group"],
                key_row.get("target_family", ""),
            )
        )
    strata = sorted(output_strata)
    result = []
    for run_id, model_id, repetition, group, target_family in strata:
        relevant_cases = [
            row
            for row in case_key
            if row["group"] == group
            and row.get("target_family", "") == target_family
        ]
        case_ids = {row["case_id"] for row in relevant_cases}
        all_rows = [
            row
            for row in matches
            if row["run_id"] == run_id
            and row["model_id"] == model_id
            and int(row["repetition"]) == repetition
            and row["group"] == group
            and next(
                (
                    item.get("target_family", "")
                    for item in relevant_cases
                    if item["case_id"] == row["case_id"]
                ),
                "",
            )
            == target_family
        ]
        rows = [
            row
            for row in all_rows
            if bool(
                int(
                    row.get(
                        "is_target_family_report",
                        alert_family(row) in {"", target_family},
                    )
                )
            )
        ]
        stratum_outputs = []
        for output in outputs:
            key_row = key_by_packet[output["packet_id"]]
            if (
                output.get("run_id", "") == run_id
                and output.get("model_id", "") == model_id
                and int(output.get("repetition", 1)) == repetition
                and key_row["group"] == group
                and key_row.get("target_family", "") == target_family
            ):
                stratum_outputs.append(output)
        outputs_by_packet: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for output in stratum_outputs:
            outputs_by_packet[output["packet_id"]].append(output)
        reviewed_case_ids = set()
        invalid_output_n = 0
        for case in relevant_cases:
            packet_outputs = outputs_by_packet.get(case["packet_id"], [])
            expected_chunks = int(case.get("chunk_count") or 1)
            valid_chunks = {
                int(output.get("chunk_index", 1))
                for output in packet_outputs
                if output.get("status") == "valid"
            }
            invalid_output_n += sum(
                output.get("status") != "valid" for output in packet_outputs
            )
            if valid_chunks == set(range(1, expected_chunks + 1)):
                reviewed_case_ids.add(case["case_id"])
        missing_case_n = len(case_ids - reviewed_case_ids)
        ambiguous = sum(
            row["match_status"] == "ambiguous_semantic_candidate" for row in rows
        )
        matched_truth = {
            row["silver_finding_id"]
            for row in rows
            if row["match_status"] == "compatible_location_recovery"
            and row["silver_finding_id"]
        }
        truth_ids = set().union(
            *(target_truths_by_case.get(case_id, set()) for case_id in case_ids)
        )
        positive_cases = {
            row["case_id"]
            for row in relevant_cases
            if row.get("case_control") == "positive"
        }
        detected_cases = {
            row["case_id"]
            for row in rows
            if row["silver_finding_id"]
            in target_truths_by_case.get(row["case_id"], set())
        }
        unmatched_statuses = {
            "unmatched_to_codeql",
            "invalid_or_unlocalized_report",
        }
        unmatched = sum(
            row["match_status"] in unmatched_statuses for row in rows
        )
        control_ids = {
            row["case_id"]
            for row in relevant_cases
            if row["case_control"] == "control"
        }
        controls_with_unmatched = {
            row["case_id"]
            for row in rows
            if row["case_id"] in control_ids
            and row["match_status"] in unmatched_statuses
        }
        localized_truth_ids = {
            row["silver_finding_id"]
            for row in rows
            if row["match_status"] == "compatible_location_recovery"
            and row["silver_finding_id"]
            and bool(row["file_path"])
            and (bool(row["line_start"]) or bool(row.get("line_end")))
        }
        result.append(
            {
                "run_id": run_id,
                "model_id": model_id,
                "repetition": repetition,
                "group": group,
                "target_family": target_family,
                "metrics_status": "incomplete"
                if missing_case_n or invalid_output_n
                else "complete",
                "ambiguous_semantic_candidate_n": ambiguous,
                "invalid_output_n": invalid_output_n,
                "reviewed_case_n": len(reviewed_case_ids),
                "missing_case_n": missing_case_n,
                "case_n": len(relevant_cases),
                "positive_case_n": len(positive_cases),
                "control_case_n": len(control_ids),
                "silver_finding_n": len(truth_ids),
                "recovered_silver_finding_n": len(matched_truth & truth_ids),
                "silver_alert_recovery_rate": safe_ratio(
                    len(matched_truth & truth_ids), len(truth_ids)
                ),
                "hit_positive_pr_n": len(detected_cases & positive_cases),
                "positive_pr_hit_rate": safe_ratio(
                    len(detected_cases & positive_cases), len(positive_cases)
                ),
                "llm_finding_n": len(rows),
                "off_target_family_report_n": sum(
                    row["match_status"]
                    in {
                        "off_target_family_report",
                        "off_target_reference_recovery",
                    }
                    for row in all_rows
                ),
                "off_target_reference_recovery_n": sum(
                    row["match_status"] == "off_target_reference_recovery"
                    for row in all_rows
                ),
                "unmatched_report_n": unmatched,
                "unmatched_reports_per_pr": safe_ratio(
                    unmatched, len(relevant_cases)
                ),
                "control_pr_with_unmatched_report_n": len(
                    controls_with_unmatched
                ),
                "control_pr_unmatched_report_rate": safe_ratio(
                    len(controls_with_unmatched), len(control_ids)
                ),
                "localized_recovered_alert_n": len(
                    localized_truth_ids & truth_ids
                ),
                "localization_rate": safe_ratio(
                    len(localized_truth_ids & truth_ids),
                    len(matched_truth & truth_ids),
                ),
                "target_report_with_reference_file_n": sum(
                    int(row.get("target_reference_file_candidate_n", 0)) > 0
                    for row in rows
                ),
                "target_report_file_localization_rate": safe_ratio(
                    sum(
                        int(row.get("target_reference_file_candidate_n", 0))
                        > 0
                        for row in rows
                    ),
                    len(rows),
                ),
                "target_report_with_reference_location_n": sum(
                    int(row.get("target_reference_location_candidate_n", 0))
                    > 0
                    for row in rows
                ),
                "target_report_line_hunk_localization_rate": safe_ratio(
                    sum(
                        int(
                            row.get(
                                "target_reference_location_candidate_n",
                                0,
                            )
                        )
                        > 0
                        for row in rows
                    ),
                    len(rows),
                ),
            }
        )
    return result


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    args = parse_args()
    case_key = read_csv(Path(args.case_key))
    silver_path = args.silver_findings or args.confirmed_findings
    truths = attach_truths_to_cases(
        case_key,
        read_csv(Path(silver_path)),
    )
    outputs = collapse_output_attempts(read_jsonl(Path(args.outputs)))
    adjudications = read_csv(Path(args.adjudication)) if args.adjudication else []
    matches = build_matches(case_key, truths, outputs, adjudications)
    summary = metrics(case_key, truths, matches, outputs)
    write_csv(Path(args.matches_output), matches)
    write_csv(Path(args.metrics_output), summary)
    ambiguous = sum(
        row["match_status"] == "ambiguous_semantic_candidate" for row in matches
    )
    print(
        json.dumps(
            {
                "matches": len(matches),
                "metric_rows": len(summary),
                "ambiguous": ambiguous,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
