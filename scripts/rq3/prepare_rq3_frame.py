#!/usr/bin/env python3
# RQ3 review experiment entry point.
"""Build the frozen RQ3 PR pool and actionable CodeQL reference-alert frame."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import compare_sarif


ROOT = Path(__file__).resolve().parents[2]
GROUPS = ("ai", "human")
PATCH_VISIBILITY_GATE_VERSION = "new_side_hunk_v1"
HUNK_HEADER_PATTERN = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?:.*)$"
)
VALID_PATCH_STATUSES = {"added", "modified", "removed", "renamed"}


class PatchVisibilityError(ValueError):
    """A fail-closed cached-patch parsing or path error."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class PatchHunk:
    header: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    visible_new_lines: frozenset[int]
    added_new_lines: frozenset[int]

    @property
    def new_end(self) -> int:
        return self.new_start + self.new_count - 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    base = "data/experiments/security-and-quality/study_stars500"
    parser.add_argument(
        "--analysis-pr-level",
        type=Path,
        default=f"{base}/reports/rq_analysis_final_20260727_v3/analysis_pr_level.csv",
    )
    parser.add_argument(
        "--snapshot-manifest",
        type=Path,
        default=f"{base}/reports/rq_analysis_final_20260727_v3/snapshot_manifest.json",
    )
    parser.add_argument(
        "--frozen-model-specification",
        type=Path,
        default=(
            "data/releases/study_stars500_replication_20260727_v8/"
            "payload/config/study/model_specification.yaml"
        ),
        help=(
            "snapshot 中哈希锁定的 RQ1/RQ2 protocol 副本；当前工作区 protocol "
            "可在不重建 RQ1/RQ2 数据的情况下追加 RQ3 amendments"
        ),
    )
    parser.add_argument(
        "--ai-alerts",
        type=Path,
        default=f"{base}/reports/ai_quality_taxonomy_drill/results/introduced_alerts.csv",
    )
    parser.add_argument(
        "--human-alerts",
        type=Path,
        default=f"{base}/human/results/introduced_alerts.csv",
    )
    parser.add_argument(
        "--pr-enrichment",
        type=Path,
        default=f"{base}/reports/pr_enrichment/pr_enrichment.csv",
    )
    parser.add_argument(
        "--file-enrichment",
        type=Path,
        default=f"{base}/reports/pr_enrichment/file_enrichment.csv",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=f"{base}/metadata/pr_enrichment_cache",
    )
    parser.add_argument(
        "--actionability-config",
        type=Path,
        default="config/study/llm_review_actionability.json",
    )
    parser.add_argument(
        "--location-rules",
        type=Path,
        default="config/study/pr_enrichment_rules.json",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def maximize_csv_field_limit() -> None:
    limit = sys.maxsize
    while limit:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


def clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.casefold() in {"nan", "none", "null", "<na>"} else text


def truthy(value: Any) -> bool:
    return clean(value).casefold() in {"1", "true", "yes", "y"}


def normalize_pr_number(value: Any) -> str:
    text = clean(value)
    try:
        return str(int(float(text)))
    except (TypeError, ValueError):
        return text


def key(group: Any, repo: Any, pr_number: Any) -> tuple[str, str, str]:
    return (
        clean(group).casefold(),
        clean(repo).casefold(),
        normalize_pr_number(pr_number),
    )


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    maximize_csv_field_limit()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), [
            {name: clean(value) for name, value in row.items()} for row in reader
        ]


def write_csv(
    path: Path,
    fields: Sequence[str],
    rows: Iterable[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_snapshot_hashes(
    snapshot: dict[str, Any],
    manifest_path: Path,
    frozen_input_overrides: dict[Path, Path] | None = None,
) -> None:
    """Refuse a stale or partially modified frozen snapshot."""
    failures: list[str] = []
    for section in ("inputs", "outputs"):
        records = snapshot.get(section)
        if not isinstance(records, list):
            failures.append(f"{section}: manifest entry is not a list")
            continue
        for record in records:
            if not isinstance(record, dict):
                failures.append(f"{section}: invalid record")
                continue
            raw_path = clean(record.get("path"))
            expected = clean(record.get("sha256"))
            if not raw_path or not expected:
                failures.append(f"{section}: missing path/sha256")
                continue
            path = Path(raw_path)
            if not path.is_absolute():
                path = (
                    manifest_path.parent / path
                    if section == "outputs"
                    else ROOT / path
                )
            frozen_path = (
                (frozen_input_overrides or {}).get(path.resolve(), path)
                if section == "inputs"
                else path
            )
            if not frozen_path.is_file():
                failures.append(f"{section}: missing {path}")
                continue
            observed = sha256_file(frozen_path)
            if observed != expected:
                failures.append(
                    f"{section}: hash mismatch {frozen_path} "
                    f"(expected {expected}, observed {observed})"
                )
    if failures:
        preview = "\n".join(f"- {item}" for item in failures[:10])
        raise RuntimeError(
            "snapshot manifest hash validation failed; regenerate the final "
            f"snapshot before preparing RQ3:\n{preview}"
        )


def integer(value: Any) -> int:
    try:
        return int(float(clean(value)))
    except (TypeError, ValueError):
        return 0


def finite_number(value: Any) -> bool:
    try:
        return math.isfinite(float(clean(value)))
    except (TypeError, ValueError):
        return False


def normalized_path(value: Any) -> str:
    return compare_sarif.normalize_path(clean(value)).strip("/").casefold()


def patch_lines(patch: str) -> list[str]:
    """Split only on LF so code containing Unicode line separators stays intact."""
    lines = patch.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line.removesuffix("\r") for line in lines]


def patch_line_counts(patch: str) -> tuple[int, int]:
    additions = deletions = 0
    for line in patch_lines(patch):
        if line.startswith("+++ ") or line.startswith("--- "):
            continue
        if line.startswith("+"):
            additions += 1
        elif line.startswith("-"):
            deletions += 1
    return additions, deletions


def parse_patch_hunks(patch: str) -> list[PatchHunk]:
    """Parse and validate every unified-diff hunk in a cached GitHub patch."""
    lines = patch_lines(patch)
    if not lines:
        raise PatchVisibilityError("empty_patch")
    hunks: list[PatchHunk] = []
    index = 0
    previous_old_end: int | None = None
    previous_new_end: int | None = None
    while index < len(lines):
        header = lines[index]
        match = HUNK_HEADER_PATTERN.fullmatch(header)
        if match is None:
            raise PatchVisibilityError(
                "invalid_patch_hunk_header",
                f"line {index + 1}",
            )
        old_start = int(match.group("old_start"))
        old_count = int(match.group("old_count") or 1)
        new_start = int(match.group("new_start"))
        new_count = int(match.group("new_count") or 1)
        if (old_start == 0) != (old_count == 0):
            raise PatchVisibilityError(
                "invalid_patch_hunk_range",
                f"old={old_start},{old_count}",
            )
        if (new_start == 0) != (new_count == 0):
            raise PatchVisibilityError(
                "invalid_patch_hunk_range",
                f"new={new_start},{new_count}",
            )
        if (
            old_count
            and previous_old_end is not None
            and old_start <= previous_old_end
        ):
            raise PatchVisibilityError("overlapping_patch_hunks")
        if (
            new_count
            and previous_new_end is not None
            and new_start <= previous_new_end
        ):
            raise PatchVisibilityError("overlapping_patch_hunks")

        old_line = old_start
        new_line = new_start
        visible_new_lines: set[int] = set()
        added_new_lines: set[int] = set()
        index += 1
        while index < len(lines) and not lines[index].startswith("@@ "):
            line = lines[index]
            if line.startswith(" "):
                visible_new_lines.add(new_line)
                old_line += 1
                new_line += 1
            elif line.startswith("+"):
                visible_new_lines.add(new_line)
                added_new_lines.add(new_line)
                new_line += 1
            elif line.startswith("-"):
                old_line += 1
            elif line == r"\ No newline at end of file":
                pass
            else:
                raise PatchVisibilityError(
                    "invalid_patch_hunk_body",
                    f"line {index + 1}",
                )
            index += 1

        observed_old_count = old_line - old_start
        observed_new_count = new_line - new_start
        if (observed_old_count, observed_new_count) != (
            old_count,
            new_count,
        ):
            raise PatchVisibilityError(
                "invalid_patch_hunk_line_count",
                (
                    f"expected={old_count},{new_count} "
                    f"observed={observed_old_count},{observed_new_count}"
                ),
            )
        expected_visible = (
            set(range(new_start, new_start + new_count))
            if new_count
            else set()
        )
        if visible_new_lines != expected_visible:
            raise PatchVisibilityError("noncontiguous_patch_hunk_new_lines")
        hunk = PatchHunk(
            header=header,
            old_start=old_start,
            old_count=old_count,
            new_start=new_start,
            new_count=new_count,
            visible_new_lines=frozenset(visible_new_lines),
            added_new_lines=frozenset(added_new_lines),
        )
        hunks.append(hunk)
        if old_count:
            previous_old_end = old_start + old_count - 1
        if new_count:
            previous_new_end = hunk.new_end
    return hunks


def patch_visibility_index(
    files: list[dict[str, Any]],
) -> dict[str, list[PatchHunk]]:
    """Index validated hunks by the head-side filename, including renames."""
    if not files:
        raise PatchVisibilityError("empty_patch_file_list")
    result: dict[str, list[PatchHunk]] = {}
    for item in files:
        status = clean(item.get("status")).casefold()
        if status not in VALID_PATCH_STATUSES:
            raise PatchVisibilityError("invalid_patch_status", status)
        filename = normalized_path(item.get("filename"))
        if not filename:
            raise PatchVisibilityError("invalid_patch_filename")
        previous_filename = normalized_path(item.get("previous_filename"))
        if status == "renamed":
            if not previous_filename or previous_filename == filename:
                raise PatchVisibilityError("invalid_renamed_patch_path")
        elif previous_filename and previous_filename != filename:
            raise PatchVisibilityError("unexpected_previous_patch_path")
        if filename in result:
            raise PatchVisibilityError("duplicate_patch_filename", filename)
        patch = item.get("patch")
        if not isinstance(patch, str) or not patch.strip():
            raise PatchVisibilityError("missing_file_patch", filename)
        result[filename] = parse_patch_hunks(patch)
    return result


def read_patch_visibility(cache_path: Path) -> dict[str, list[PatchHunk]]:
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PatchVisibilityError("invalid_cache_json") from exc
    files = payload.get("files")
    if not isinstance(files, list) or not all(
        isinstance(item, dict) for item in files
    ):
        raise PatchVisibilityError("cache_files_not_list")
    return patch_visibility_index(files)


def positive_line_number(value: Any) -> int | None:
    try:
        numeric = float(clean(value))
    except (TypeError, ValueError):
        return None
    if not math.isfinite(numeric) or numeric < 1 or not numeric.is_integer():
        return None
    return int(numeric)


def reference_visibility(
    visibility: dict[str, list[PatchHunk]],
    file_path: str,
    start_line: Any,
) -> tuple[dict[str, Any] | None, str]:
    line = positive_line_number(start_line)
    if line is None:
        return None, "reference_location_invalid"
    hunks = visibility.get(normalized_path(file_path))
    if hunks is None:
        return None, "reference_path_not_in_patch"
    matches = [hunk for hunk in hunks if line in hunk.visible_new_lines]
    if not matches:
        return None, "reference_not_visible_in_diff"
    if len(matches) != 1:
        return None, "reference_visibility_ambiguous"
    hunk = matches[0]
    return (
        {
            "reference_visible_in_diff": True,
            "reference_on_added_line": line in hunk.added_new_lines,
            "hunk_header": hunk.header,
            "hunk_new_start": hunk.new_start,
            "hunk_new_end": hunk.new_end,
            "reference_visibility_gate_version": (
                PATCH_VISIBILITY_GATE_VERSION
            ),
        },
        "",
    )


def validate_cached_patch(
    enrichment: dict[str, str],
    cache_dir: Path,
) -> tuple[bool, str, Path | None]:
    cache_key = clean(enrichment.get("cache_key"))
    if not cache_key:
        return False, "missing_cache_key", None
    cache_path = cache_dir / f"{cache_key}.json"
    if not cache_path.exists():
        return False, "missing_cache_file", cache_path
    expected_hash = clean(enrichment.get("cache_sha256"))
    if expected_hash and sha256_file(cache_path) != expected_hash:
        return False, "cache_hash_mismatch", cache_path
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, "invalid_cache_json", cache_path
    files = payload.get("files")
    if not isinstance(files, list):
        return False, "cache_files_not_list", cache_path
    expected_files = integer(enrichment.get("changed_files"))
    if expected_files != len(files):
        return False, "incomplete_file_list", cache_path
    for item in files:
        if not isinstance(item, dict):
            return False, "invalid_file_entry", cache_path
        patch = item.get("patch")
        if not isinstance(patch, str) or not patch.strip():
            return False, "missing_file_patch", cache_path
        additions, deletions = patch_line_counts(patch)
        if additions != integer(item.get("additions")):
            return False, "patch_additions_mismatch", cache_path
        if deletions != integer(item.get("deletions")):
            return False, "patch_deletions_mismatch", cache_path
    try:
        patch_visibility_index(files)
    except PatchVisibilityError as exc:
        return False, exc.reason, cache_path
    return True, "", cache_path


def alert_family(row: dict[str, str]) -> str:
    family = clean(row.get("alert_category")).casefold()
    if family in {"quality", "security"}:
        return family
    if truthy(row.get("is_quality_alert")):
        return "quality"
    if truthy(row.get("is_security_alert")):
        return "security"
    return ""


def normalized_rule_tags(value: Any) -> set[str]:
    return {
        clean(item).casefold()
        for item in clean(value).split("|")
        if clean(item)
    }


def quality_reference_tiers(
    row: dict[str, str],
    quality_config: dict[str, Any],
) -> dict[str, bool]:
    """Classify one broad-eligible Quality alert into frozen tiers.

    ``broad`` is the frame-level Quality gate.  ``primary`` removes only
    explicitly configured rule tags, and ``strict`` inherits primary before
    additionally applying its severity gate.  This keeps all tiers available
    for post-review sensitivity analysis without additional model calls.
    """

    tiers = quality_config.get("reference_tiers")
    if not isinstance(tiers, dict):
        # Backward-compatible behavior for historical fixtures/configs.
        return {"primary": True, "strict": True, "broad": True}
    for name in ("primary", "strict", "broad"):
        if not isinstance(tiers.get(name), dict):
            raise ValueError(f"quality.reference_tiers.{name} must be an object")

    tags = normalized_rule_tags(row.get("rule_tags"))
    severity = clean(row.get("problem_severity")).casefold()

    def passes(spec: dict[str, Any]) -> bool:
        excluded = {
            clean(value).casefold()
            for value in spec.get("exclude_rule_tags", [])
            if clean(value)
        }
        if tags & excluded:
            return False
        allowed_severity = spec.get("problem_severity")
        if allowed_severity is not None:
            if severity not in {
                clean(value).casefold() for value in allowed_severity
            }:
                return False
        return True

    broad = passes(tiers["broad"])
    primary = broad and passes(tiers["primary"])
    strict_spec = tiers["strict"]
    inherited = clean(strict_spec.get("inherit"))
    if inherited and inherited != "primary":
        raise ValueError("quality strict tier may only inherit primary")
    strict = primary and passes(strict_spec)
    return {"primary": primary, "strict": strict, "broad": broad}


def actionable(
    row: dict[str, str],
    family: str,
    location: str,
    changed_file: bool,
    config: dict[str, Any],
) -> bool:
    common = config["common_alert_filters"]
    lifecycle = clean(row.get("lifecycle")).casefold()
    if lifecycle != clean(common["lifecycle"]).casefold():
        return False
    if location not in set(common["location_classes"]):
        return False
    if common.get("require_changed_file") and not changed_file:
        return False
    precision = clean(row.get("precision")).casefold()
    family_config = config[family]
    if precision not in {
        clean(value).casefold() for value in family_config.get("precision", [])
    }:
        return False
    if family == "quality":
        if clean(row.get("quality_category")) not in set(
            family_config["quality_categories"]
        ):
            return False
        return quality_reference_tiers(row, family_config)["broad"]
    if family_config.get("require_numeric_security_severity"):
        return finite_number(row.get("security_severity"))
    return True


def main() -> None:
    args = parse_args()
    paths = {
        name: resolve(value)
        for name, value in {
            "analysis_pr_level": args.analysis_pr_level,
            "snapshot_manifest": args.snapshot_manifest,
            "frozen_model_specification": args.frozen_model_specification,
            "ai_alerts": args.ai_alerts,
            "human_alerts": args.human_alerts,
            "pr_enrichment": args.pr_enrichment,
            "file_enrichment": args.file_enrichment,
            "cache_dir": args.cache_dir,
            "actionability_config": args.actionability_config,
            "location_rules": args.location_rules,
            "output_dir": args.output_dir,
        }.items()
    }
    snapshot = json.loads(paths["snapshot_manifest"].read_text(encoding="utf-8"))
    if not snapshot.get("rq3_frame_ready"):
        raise RuntimeError("final snapshot 未声明 rq3_frame_ready=true")
    current_model_specification = (
        ROOT / "config/study/model_specification.yaml"
    ).resolve()
    validate_snapshot_hashes(
        snapshot,
        paths["snapshot_manifest"],
        {
            current_model_specification: paths[
                "frozen_model_specification"
            ].resolve()
        },
    )
    config = json.loads(paths["actionability_config"].read_text(encoding="utf-8"))
    location_rules = compare_sarif.load_location_rules(paths["location_rules"])
    _, analysis_rows = read_csv(paths["analysis_pr_level"])
    _, enrichment_rows = read_csv(paths["pr_enrichment"])
    _, file_rows = read_csv(paths["file_enrichment"])

    enrichment_by_key = {
        key(row.get("group"), row.get("repo_name"), row.get("pr_number")): row
        for row in enrichment_rows
    }
    changed_files: dict[tuple[str, str, str], set[str]] = {}
    for row in file_rows:
        identifier = key(
            row.get("group"), row.get("repo_name"), row.get("pr_number")
        )
        changed_files.setdefault(identifier, set()).add(
            normalized_path(row.get("filename"))
        )

    pool_rows: list[dict[str, Any]] = []
    eligible_keys: set[tuple[str, str, str]] = set()
    patch_visibility_by_key: dict[
        tuple[str, str, str],
        dict[str, list[PatchHunk]],
    ] = {}
    patch_exclusions: Counter[str] = Counter()
    for row in analysis_rows:
        if not truthy(row.get("quality_gate_pass")):
            continue
        identifier = key(
            row.get("group"), row.get("repo_name"), row.get("pr_number")
        )
        enrichment = enrichment_by_key.get(identifier)
        if enrichment is None:
            patch_exclusions["missing_enrichment"] += 1
            continue
        if not truthy(enrichment.get("file_list_complete")):
            patch_exclusions["incomplete_file_list"] += 1
            continue
        patch_complete, reason, cache_path = validate_cached_patch(
            enrichment, paths["cache_dir"]
        )
        if not patch_complete:
            patch_exclusions[reason] += 1
            continue
        if cache_path is None:
            patch_exclusions["missing_cache_file"] += 1
            continue
        try:
            visibility = read_patch_visibility(cache_path)
        except PatchVisibilityError as exc:
            patch_exclusions[exc.reason] += 1
            continue
        eligible_keys.add(identifier)
        patch_visibility_by_key[identifier] = visibility
        pool_rows.append(
            {
                "group": identifier[0],
                "repo_name": clean(row.get("repo_name")),
                "pr_number": identifier[2],
                "pr_id": clean(row.get("pr_id")),
                "language": clean(row.get("repo_language")),
                "task_type": clean(row.get("task_type")),
                "changed_kloc": clean(row.get("changed_kloc")),
                "merged_at": clean(row.get("merged_at")),
                "merge_calendar_quarter": "",
                "introduced_quality_alerts": integer(
                    row.get("introduced_quality_alerts")
                ),
                "introduced_security_alerts": integer(
                    row.get("introduced_security_alerts")
                ),
                "analysis_eligible": True,
                "cache_path": str(cache_path),
                "cache_sha256": clean(enrichment.get("cache_sha256")),
                "patch_complete": True,
            }
        )

    alert_rows: list[dict[str, Any]] = []
    alert_audit: Counter[tuple[str, str, str]] = Counter()
    for group, alert_path in (
        ("ai", paths["ai_alerts"]),
        ("human", paths["human_alerts"]),
    ):
        _, alerts = read_csv(alert_path)
        for row in alerts:
            identifier = key(group, row.get("repo_name"), row.get("pr_number"))
            family = alert_family(row)
            if family not in {"quality", "security"}:
                alert_audit[(group, "unknown_family", "excluded")] += 1
                continue
            if identifier not in eligible_keys:
                alert_audit[(group, family, "ineligible_pr")] += 1
                continue
            path = normalized_path(row.get("file_path"))
            location = (
                clean(row.get("location_class"))
                or compare_sarif.location_class(path, location_rules)
            )
            in_changed_file = path in changed_files.get(identifier, set())
            if not actionable(
                row, family, location, in_changed_file, config
            ):
                alert_audit[(group, family, "non_actionable")] += 1
                continue
            visibility_fields, visibility_reason = reference_visibility(
                patch_visibility_by_key[identifier],
                path,
                row.get("start_line"),
            )
            if visibility_fields is None:
                alert_audit[
                    (group, family, visibility_reason)
                ] += 1
                continue
            alert_audit[(group, family, "included")] += 1
            tier_fields: dict[str, Any]
            if family == "quality":
                tiers = quality_reference_tiers(row, config["quality"])
                tier_fields = {
                    "quality_primary_reference": tiers["primary"],
                    "quality_strict_reference": tiers["strict"],
                    "quality_broad_reference": tiers["broad"],
                    "reference_tiers": "|".join(
                        name
                        for name in ("primary", "strict", "broad")
                        if tiers[name]
                    ),
                }
                for tier, included in tiers.items():
                    alert_audit[
                        (group, f"quality_{tier}", "included" if included else "excluded")
                    ] += 1
            else:
                tier_fields = {
                    "quality_primary_reference": False,
                    "quality_strict_reference": False,
                    "quality_broad_reference": False,
                    "reference_tiers": "security",
                }
            alert_rows.append(
                {
                    **row,
                    **visibility_fields,
                    **tier_fields,
                    "group": group,
                    "target_family": family,
                    "location_class": location,
                    "changed_file": True,
                    "actionability_version": config["schema_version"],
                }
            )

    output = paths["output_dir"]
    pool_fields = [
        "group",
        "repo_name",
        "pr_number",
        "pr_id",
        "language",
        "task_type",
        "changed_kloc",
        "merged_at",
        "merge_calendar_quarter",
        "introduced_quality_alerts",
        "introduced_security_alerts",
        "analysis_eligible",
        "cache_path",
        "cache_sha256",
        "patch_complete",
    ]
    write_csv(output / "pr_pool.csv", pool_fields, pool_rows)
    alert_fields = sorted({field for row in alert_rows for field in row})
    write_csv(output / "reference_alerts.csv", alert_fields, alert_rows)
    quality_broad_rows = [
        row
        for row in alert_rows
        if row["target_family"] == "quality"
        and truthy(row.get("quality_broad_reference"))
    ]
    quality_primary_rows = [
        row
        for row in quality_broad_rows
        if truthy(row.get("quality_primary_reference"))
    ]
    quality_strict_rows = [
        row
        for row in quality_primary_rows
        if truthy(row.get("quality_strict_reference"))
    ]
    security_rows = [
        row for row in alert_rows if row["target_family"] == "security"
    ]
    for filename, rows in (
        ("quality_broad_reference_alerts.csv", quality_broad_rows),
        ("quality_primary_reference_alerts.csv", quality_primary_rows),
        ("quality_strict_reference_alerts.csv", quality_strict_rows),
        ("security_reference_alerts.csv", security_rows),
    ):
        write_csv(output / filename, alert_fields, rows)
    audit_rows = [
        {
            "audit_type": "patch_exclusion",
            "group": "",
            "family": "",
            "status": reason,
            "row_n": count,
        }
        for reason, count in sorted(patch_exclusions.items())
    ]
    audit_rows.extend(
        {
            "audit_type": "alert",
            "group": group,
            "family": family,
            "status": status,
            "row_n": count,
        }
        for (group, family, status), count in sorted(alert_audit.items())
    )
    positive_keys = {
        (
            row["group"],
            clean(row.get("target_family")),
            row["repo_name"].casefold(),
            row["pr_number"],
        )
        for row in alert_rows
    }
    tier_positive_keys = {
        tier: {
            (row["group"], row["repo_name"].casefold(), row["pr_number"])
            for row in rows
        }
        for tier, rows in (
            ("quality_broad", quality_broad_rows),
            ("quality_primary", quality_primary_rows),
            ("quality_strict", quality_strict_rows),
            ("security", security_rows),
        )
    }
    for group in GROUPS:
        for family in ("quality", "security"):
            audit_rows.append(
                {
                    "audit_type": "positive_pr",
                    "group": group,
                    "family": family,
                    "status": "included",
                    "row_n": sum(
                        candidate[0] == group and candidate[1] == family
                        for candidate in positive_keys
                    ),
                }
            )
    write_csv(
        output / "frame_audit.csv",
        ["audit_type", "group", "family", "status", "row_n"],
        audit_rows,
    )
    manifest = {
        "schema_version": "1.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "formal_frame_ready",
        "source_snapshot_id": snapshot.get("snapshot_id", ""),
        "rq3_frame_ready": True,
        "frame_builder_sha256": sha256_file(Path(__file__)),
        "reference_visibility_gate": {
            "version": PATCH_VISIBILITY_GATE_VERSION,
            "require_new_side_hunk_visibility": True,
            "head_side_path_for_renames": True,
        },
        "actionability_config": config,
        "counts": {
            "analysis_quality_gated_pr_n": sum(
                truthy(row.get("quality_gate_pass")) for row in analysis_rows
            ),
            "patch_complete_pr_n": len(pool_rows),
            "reference_alert_n": len(alert_rows),
            "positive_pr_n": len(positive_keys),
            "quality_tiers": {
                tier: {
                    "alert_n": len(rows),
                    "positive_pr_n": len(tier_positive_keys[tier]),
                    "positive_pr_by_group": {
                        group: sum(
                            identifier[0] == group
                            for identifier in tier_positive_keys[tier]
                        )
                        for group in GROUPS
                    },
                }
                for tier, rows in (
                    ("quality_broad", quality_broad_rows),
                    ("quality_primary", quality_primary_rows),
                    ("quality_strict", quality_strict_rows),
                    ("security", security_rows),
                )
            },
        },
        "inputs": {
            str(path): sha256_file(path)
            for name, path in paths.items()
            if name not in {"cache_dir", "output_dir"} and path.is_file()
        },
        "outputs": {
            str(path): sha256_file(path)
            for path in (
                output / "pr_pool.csv",
                output / "reference_alerts.csv",
                output / "quality_broad_reference_alerts.csv",
                output / "quality_primary_reference_alerts.csv",
                output / "quality_strict_reference_alerts.csv",
                output / "security_reference_alerts.csv",
                output / "frame_audit.csv",
            )
        },
    }
    (output / "frame_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"已生成 RQ3 frame: pool={len(pool_rows)} "
        f"alerts={len(alert_rows)} positive_pr={len(positive_keys)} -> {output}"
    )


if __name__ == "__main__":
    main()
