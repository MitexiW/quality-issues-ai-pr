#!/usr/bin/env python3
"""Build the frozen RQ3 mechanism mapping for all 187 Quality references.

The strict 114-reference mapping is read from its frozen, author-confirmed
artifact.  The additional 13 AI references inherit the existing RQ1
root-cause clusters.  The additional 60 human references use explicit
reference-level decisions that an author reviewed and accepted under the same
five-category codebook.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORTS = (
    ROOT
    / "data"
    / "experiments"
    / "security-and-quality"
    / "study_stars500"
    / "reports"
)

CATEGORY_LABELS = {
    "incomplete_change_coordination": "Incomplete change coordination",
    "redundant_or_locally_inconsistent_construction": (
        "Redundant or locally inconsistent construction"
    ),
    "control_state_or_dataflow_miscomposition": (
        "Control-, state-, or data-flow miscomposition"
    ),
    "dependency_error_or_resource_mismanagement": (
        "Dependency, error, or resource mismanagement"
    ),
    "interface_or_contract_mismatch": "Interface or contract mismatch",
}


@dataclass(frozen=True)
class Decision:
    category: str
    rationale: str
    confidence: str = "high"


# The author-confirmed transfer is only at the five-category level.  We
# therefore do not invent finer subcategories for these 60 references.
HUMAN_EXTRA_DECISION_GROUPS: tuple[tuple[Decision, tuple[str, ...]], ...] = (
    (
        Decision(
            "incomplete_change_coordination",
            "The PR introduced or retained an import, binding, or computed value without an active consumer. Under the frozen codebook boundary, a merely unused element is incomplete change coordination unless duplication is the central mechanism.",
        ),
        (
            "sf-19c58094c5014824ced4",
            "sf-afa4245d46a5c13ad5ea",
            "sf-634667cf130d5adfb5c8",
            "sf-e01165365bd8631dab4a",
            "sf-ea2190d5e89abdfe0013",
            "sf-31691eb9d307bd01136f",
            "sf-ab9efb5c8d96da9af18f",
            "sf-807473e2ea683c060958",
            "sf-a7dcf851d93ab379dc86",
            "sf-9d17233fc137b1a1c35a",
            "sf-4d185bf6fb706ae6f9dc",
            "sf-4243ee55afb45da0a78d",
            "sf-364ba7b8f7bcd4ec5074",
            "sf-b0f9ec1f679244dfba5b",
            "sf-ddfaa0d5c981fb14731d",
            "sf-4247e6db2953942d4e06",
            "sf-a143d0d95718850d6ea4",
            "sf-c6bc44d55cfd14197b64",
            "sf-8cffd89d7bca7928849c",
            "sf-7f2f46f0c76392d1b5c3",
            "sf-700db2d8573af4374c5d",
            "sf-78421aafb42ce6fee552",
            "sf-308d2ac069b9e853ac0c",
            "sf-47c712411f134f1a67d1",
            "sf-193b98eb590cb584fd17",
            "sf-c5f8853c06f19dd145b6",
            "sf-2726915a65653d1c83f1",
            "sf-d085044c71d30642b204",
            "sf-764bcbb8ceb62ea7c9a1",
            "sf-5b96eff662afd663dc50",
            "sf-de1345accabe5d89dc7c",
            "sf-e20a6ffdd92c301cb30e",
            "sf-912f3ae11b09cb8532ba",
            "sf-09dd349c73d41addb393",
            "sf-b1dcce14a4cbd37910ad",
            "sf-8ddf4c9fbad2a6b55933",
            "sf-079750cf933803000205",
            "sf-c7f930df45b3acf13293",
            "sf-6156b1e48e4b33f77e7d",
            "sf-be63795e543ddb27c31c",
            "sf-b8d8cb2d5fbc86d536ca",
            "sf-e20047eeb42efe170acd",
            "sf-e0dcffa863696f35ed1d",
            "sf-cc7f93c388c787304d3b",
            "sf-ece798738e0079c3b99e",
            "sf-c6d6f4c44edee3477cb7",
            "sf-d227cab195b8becc7e25",
            "sf-82afd1b63992913052c2",
            "sf-8b1567ff123c2a628957",
            "sf-55684ed0f67e014c4cbc",
            "sf-b3a98a201f434eb4384e",
            "sf-5a6799be58721c940899",
        ),
    ),
    (
        Decision(
            "redundant_or_locally_inconsistent_construction",
            "The assignment writes a value that is overwritten before any read, or writes terminal state after its final read. The central anomaly is therefore an effect-free or redundant operation rather than an unintegrated definition.",
        ),
        (
            "sf-f213c0c7f7e42983170e",
            "sf-7c90d856fdd4ae1be025",
            "sf-cad2473cc8a3c26738d6",
            "sf-075790b3eed54c41032a",
            "sf-6810c80978ec17f58c70",
            "sf-b267f2b87dc347207738",
            "sf-199f9345fa0760904951",
        ),
    ),
    (
        Decision(
            "control_state_or_dataflow_miscomposition",
            "An unconditional early return introduced immediately before the validation block makes that block unreachable; the central anomaly is invalid control-flow composition.",
        ),
        ("sf-b9f257b196fb325642b0",),
    ),
)


def parse_bool(value: str) -> bool:
    return value.strip().casefold() in {"1", "true", "yes"}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def wilson_interval(successes: int, total: int) -> tuple[float, float]:
    if total == 0:
        return math.nan, math.nan
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(
        p * (1 - p) / total + z * z / (4 * total * total)
    ) / denominator
    return centre - half, centre + half


def human_extra_decisions() -> dict[str, Decision]:
    result: dict[str, Decision] = {}
    for item, reference_ids in HUMAN_EXTRA_DECISION_GROUPS:
        for reference_id in reference_ids:
            if reference_id in result:
                raise ValueError(f"duplicate human-extra decision: {reference_id}")
            result[reference_id] = item
    if len(result) != 60:
        raise ValueError(f"expected 60 human-extra decisions, found {len(result)}")
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--references",
        type=Path,
        default=REPORTS
        / "final_human_confirmed_rq3_20260817_v1"
        / "reference_adjudication_join.csv",
    )
    parser.add_argument(
        "--strict-mapping",
        type=Path,
        default=REPORTS
        / "rq3_reference_mechanism_mapping_20260901_v1"
        / "reference_mechanism_mapping.csv",
    )
    parser.add_argument(
        "--strict-manifest",
        type=Path,
        default=REPORTS
        / "rq3_reference_mechanism_mapping_20260901_v1"
        / "manifest.json",
    )
    parser.add_argument(
        "--alert-links",
        type=Path,
        default=REPORTS
        / "ai_quality_root_cause_review_20260831_v1"
        / "full_compiled_v1"
        / "alert_cluster_links.csv",
    )
    parser.add_argument(
        "--clusters",
        type=Path,
        default=REPORTS
        / "ai_quality_root_cause_review_20260831_v1"
        / "full_compiled_v1"
        / "root_cause_clusters.csv",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPORTS / "rq3_all_reference_mechanism_mapping_20260901_v1",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    strict_manifest = json.loads(args.strict_manifest.read_text(encoding="utf-8"))
    if strict_manifest.get("status") != "frozen_author_confirmed":
        raise ValueError("strict mapping is not frozen_author_confirmed")

    references = [
        row
        for row in read_csv(args.references)
        if row["target_family"] == "quality"
        and parse_bool(row["validated_issue_reference"])
    ]
    if len(references) != 187:
        raise ValueError(f"expected 187 confirmed Quality references, found {len(references)}")
    if Counter(row["group"] for row in references) != {"human": 117, "ai": 70}:
        raise ValueError("all-reference frame must contain 70 AI and 117 human rows")
    if len({row["reference_id"] for row in references}) != 187:
        raise ValueError("reference_id is not unique in the all-reference frame")

    strict_rows = read_csv(args.strict_mapping)
    strict_by_id = {row["reference_id"]: row for row in strict_rows}
    if len(strict_by_id) != 114:
        raise ValueError("strict mapping must contain 114 unique references")
    links = {row["alert_id"]: row for row in read_csv(args.alert_links)}
    clusters = {row["root_cause_cluster_id"]: row for row in read_csv(args.clusters)}
    proposals = human_extra_decisions()

    observed_human_extra = {
        row["reference_id"]
        for row in references
        if row["group"] == "human"
        and not parse_bool(row["quality_primary_reference"])
    }
    if observed_human_extra != set(proposals):
        missing = sorted(observed_human_extra - set(proposals))
        extra = sorted(set(proposals) - observed_human_extra)
        raise ValueError(f"human-extra proposal mismatch: missing={missing}, extra={extra}")

    mapped: list[dict[str, object]] = []
    for row in references:
        reference_id = row["reference_id"]
        if reference_id in strict_by_id:
            frozen = strict_by_id[reference_id]
            category = frozen["rq1_mechanism_category"]
            subcategory = frozen["mechanism_subcategory"]
            cluster_id = frozen["root_cause_cluster_id"]
            mapping_source = frozen["mapping_source"]
            mapping_status = frozen["mapping_status"]
            confidence = frozen["mapping_confidence"]
            rationale = frozen["mapping_rationale"]
            analysis_tier = "strict_primary_114"
        elif row["group"] == "ai":
            alert_id = row["adjudication_alert_id"]
            if alert_id not in links:
                raise ValueError(f"AI extra alert lacks RQ1 link: {alert_id}")
            link = links[alert_id]
            cluster = clusters[link["root_cause_cluster_id"]]
            category = cluster["root_cause_category"]
            subcategory = cluster["mechanism_subcategory"]
            cluster_id = cluster["root_cause_cluster_id"]
            mapping_source = "frozen_rq1_root_cause_cluster"
            mapping_status = "frozen_existing_rq1_decision"
            confidence = cluster["confidence"]
            rationale = cluster["cause_statement"]
            analysis_tier = "extended_additional_73"
        else:
            item = proposals[reference_id]
            category = item.category
            subcategory = ""
            cluster_id = ""
            mapping_source = "explicit_author_confirmed_codebook_transfer"
            mapping_status = "author_confirmed_transferred_codebook"
            confidence = item.confidence
            rationale = item.rationale
            analysis_tier = "extended_additional_73"

        if category not in CATEGORY_LABELS:
            raise ValueError(f"unexpected category: {category}")
        mapped_row: dict[str, object] = {
            "case_id": row["case_id"],
            "group": row["group"],
            "repo_name": row["repo_name"],
            "pr_number": row["pr_number"],
            "language": row["language"],
            "task_type": row["task_type"],
            "reference_id": reference_id,
            "alert_id": row["adjudication_alert_id"],
            "rule_id": row["rule_id"],
            "rule_name": row["rule_name"],
            "quality_category": row["quality_category"],
            "semantic_recovered": int(parse_bool(row["semantic_recovered"])),
            "analysis_tier": analysis_tier,
            "rq1_mechanism_category": category,
            "rq1_mechanism_label": CATEGORY_LABELS[category],
            "mechanism_subcategory": subcategory,
            "root_cause_cluster_id": cluster_id,
            "mapping_source": mapping_source,
            "mapping_status": mapping_status,
            "mapping_confidence": confidence,
            "mapping_rationale": rationale,
        }
        mapped.append(mapped_row)

    mapped.sort(key=lambda item: (str(item["group"]), str(item["case_id"]), str(item["reference_id"])))
    write_csv(args.output_dir / "reference_mechanism_mapping.csv", mapped, list(mapped[0]))

    summary_rows: list[dict[str, object]] = []
    for group in ("ai", "human", "all"):
        group_rows = mapped if group == "all" else [r for r in mapped if r["group"] == group]
        for category, label in CATEGORY_LABELS.items():
            category_rows = [r for r in group_rows if r["rq1_mechanism_category"] == category]
            recovered = sum(int(r["semantic_recovered"]) for r in category_rows)
            total = len(category_rows)
            low, high = wilson_interval(recovered, total)
            summary_rows.append(
                {
                    "group": group,
                    "rq1_mechanism_category": category,
                    "rq1_mechanism_label": label,
                    "reference_n": total,
                    "recovered_n": recovered,
                    "recall": recovered / total if total else "",
                    "wilson_95_ci_low": low if total else "",
                    "wilson_95_ci_high": high if total else "",
                    "case_n": len({r["case_id"] for r in category_rows}),
                }
            )
    write_csv(
        args.output_dir / "recovery_by_rq1_mechanism.csv",
        summary_rows,
        list(summary_rows[0]),
    )

    manifest = {
        "schema_version": "1.0.0",
        "status": "frozen_author_confirmed",
        "reference_n": len(mapped),
        "strict_author_confirmed_reference_n": 114,
        "additional_ai_frozen_rq1_reference_n": 13,
        "additional_human_author_confirmed_reference_n": 60,
        "group_n": dict(Counter(str(r["group"]) for r in mapped)),
        "recovered_n": sum(int(r["semantic_recovered"]) for r in mapped),
        "category_n": dict(
            Counter(str(r["rq1_mechanism_category"]) for r in mapped)
        ),
        "per_item_review_timestamps_recorded": False,
        "human_extra_author_confirmation": {
            "confirmed": True,
            "reference_n": 60,
            "accepted_category_change_n": 0,
        },
        "inputs": {
            "references": str(args.references.resolve()),
            "strict_mapping": str(args.strict_mapping.resolve()),
            "strict_manifest": str(args.strict_manifest.resolve()),
            "alert_links": str(args.alert_links.resolve()),
            "clusters": str(args.clusters.resolve()),
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        "All-reference RQ3 mechanism mapping prepared: "
        f"references={len(mapped)} recovered={manifest['recovered_n']} "
        f"human_extra_author_confirmed=60 output={args.output_dir.resolve()}"
    )


if __name__ == "__main__":
    main()
