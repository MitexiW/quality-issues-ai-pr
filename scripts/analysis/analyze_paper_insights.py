#!/usr/bin/env python3
# Statistical analysis entry point.
"""Derive the cross-RQ insight analyses used by the paper.

The command is deliberately downstream of the frozen RQ1--RQ3 artifacts.  It
does not rescan repositories, resample PRs, or rerun the LLM reviewer.  It
quantifies four claims:

1. introduced Quality-alert burden is concentrated in a small PR tail;
2. AI provenance adds limited out-of-repository predictive information beyond
   the covariates in the formal RQ2 model;
3. AI and human PRs have comparable broad Quality-category and within-language
   rule profiles; and
4. the LLM reviewer recovers different CodeQL categories at different rates.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
import pandas as pd
import patsy
import statsmodels.api as sm
from scipy.stats import rankdata
from statsmodels.stats.proportion import proportion_confint


ROOT = Path(__file__).resolve().parents[2]
GROUPS = ("ai", "human")
CONTEXT_FORMULA = (
    "1 + C(task_type) + log1p_changed_kloc"
    " + C(repo_language)"
)
PROVENANCE_FORMULA = CONTEXT_FORMULA + " + ai"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-pr-level", type=Path, required=True)
    parser.add_argument("--ai-alerts", type=Path, required=True)
    parser.add_argument("--human-alerts", type=Path, required=True)
    parser.add_argument("--rq3-reference-recovery", type=Path, required=True)
    parser.add_argument("--rq3-finding-relations", type=Path, required=True)
    parser.add_argument("--rq3-summary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--folds", type=int, default=10)
    parser.add_argument("--bootstrap-draws", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20260623)
    parser.add_argument("--min-language-prs-per-group", type=int, default=20)
    return parser.parse_args()


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.casefold() in {"nan", "none", "null", "<na>"} else text


def truthy(value: Any) -> bool:
    text = clean(value).casefold()
    if text in {"true", "yes", "y"}:
        return True
    if text in {"false", "no", "n", ""}:
        return False
    try:
        numeric = float(text)
    except ValueError:
        return False
    return math.isfinite(numeric) and numeric == 1.0


def normalize_pr_number(value: Any) -> str:
    text = clean(value)
    try:
        return str(int(float(text)))
    except (TypeError, ValueError):
        return text


def pr_key(group: Any, repository: Any, pr_number: Any) -> str:
    return "|".join(
        (
            clean(group).casefold(),
            clean(repository).casefold(),
            normalize_pr_number(pr_number),
        )
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    materialized = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not materialized:
        raise ValueError(f"拒绝写入空 CSV: {path}")
    fields: list[str] = []
    for row in materialized:
        for field in row:
            if field not in fields:
                fields.append(field)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(materialized)
    temporary.replace(path)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def gini(values: Sequence[float]) -> float:
    array = np.asarray(values, dtype=float)
    if array.size == 0 or np.any(array < 0):
        raise ValueError("Gini 输入必须是非空非负序列")
    total = float(array.sum())
    if total == 0:
        return 0.0
    ordered = np.sort(array)
    n = len(ordered)
    weighted = float(np.dot(np.arange(1, n + 1), ordered))
    return (2 * weighted) / (n * total) - (n + 1) / n


def top_share(values: Sequence[float], fraction: float) -> tuple[int, float]:
    if not 0 < fraction <= 1:
        raise ValueError("fraction 必须位于 (0, 1]")
    array = np.sort(np.asarray(values, dtype=float))[::-1]
    count = max(1, int(math.floor(len(array) * fraction + 0.5)))
    total = float(array.sum())
    share = float(array[:count].sum() / total) if total else 0.0
    return count, share


def load_analysis(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, low_memory=False)
    required = {
        "group",
        "repo_name",
        "pr_number",
        "task_type",
        "repo_language",
        "changed_kloc",
        "introduced_quality_alerts",
        "introduced_quality_any",
        "quality_gate_pass",
    }
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"analysis PR table 缺少字段: {missing}")
    frame = frame[frame["quality_gate_pass"].map(truthy)].copy()
    frame["group"] = frame["group"].map(lambda value: clean(value).casefold())
    if set(frame["group"]) != set(GROUPS):
        raise ValueError("quality-gated analysis 必须同时包含 ai 和 human")
    frame["pr_key"] = [
        pr_key(group, repo, number)
        for group, repo, number in zip(
            frame["group"],
            frame["repo_name"],
            frame["pr_number"],
            strict=True,
        )
    ]
    if frame["pr_key"].duplicated().any():
        raise ValueError("analysis PR table 存在重复 PR key")
    frame["introduced_quality_alerts"] = pd.to_numeric(
        frame["introduced_quality_alerts"], errors="raise"
    ).astype(int)
    frame["introduced_quality_any"] = frame["introduced_quality_any"].map(truthy)
    if (
        frame["introduced_quality_any"]
        != frame["introduced_quality_alerts"].gt(0)
    ).any():
        raise ValueError("introduced_quality_any/count 不守恒")
    changed_kloc = pd.to_numeric(frame["changed_kloc"], errors="raise")
    if (~np.isfinite(changed_kloc) | (changed_kloc < 0)).any():
        raise ValueError("changed_kloc 必须是有限非负数")
    frame["log1p_changed_kloc"] = np.log1p(changed_kloc)
    for column in ("repo_name", "task_type", "repo_language"):
        if frame[column].map(clean).eq("").any():
            raise ValueError(f"analysis PR table 的 {column} 存在空值")
        frame[column] = frame[column].map(clean)
    frame["ai"] = frame["group"].eq("ai").astype(int)
    return frame.reset_index(drop=True)


def concentration_analysis(
    frame: pd.DataFrame,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    metrics: list[dict[str, Any]] = []
    curves: list[dict[str, Any]] = []
    grid = np.concatenate(
        (
            np.array([0.0, 0.001, 0.0025, 0.005]),
            np.arange(0.01, 0.201, 0.01),
        )
    )
    for group in GROUPS:
        target = frame[frame["group"] == group]
        values = target["introduced_quality_alerts"].to_numpy(dtype=float)
        total = int(values.sum())
        affected = int(np.count_nonzero(values))
        row: dict[str, Any] = {
            "group": group,
            "pr_n": len(target),
            "introduced_quality_alert_n": total,
            "affected_pr_n": affected,
            "affected_pr_percent": 100 * affected / len(target),
            "zero_alert_pr_percent": 100 * (len(target) - affected) / len(target),
            "maximum_alerts_per_pr": int(values.max()),
            "gini": gini(values),
        }
        for label, fraction in (("top_1_percent", 0.01), ("top_5_percent", 0.05), ("top_10_percent", 0.10)):
            count, share = top_share(values, fraction)
            row[f"{label}_pr_n"] = count
            row[f"{label}_alert_share_percent"] = 100 * share
        top_five = min(5, len(values))
        row["top_5_pr_alert_share_percent"] = (
            100 * float(np.sort(values)[::-1][:top_five].sum()) / total
            if total
            else 0.0
        )
        metrics.append(row)

        descending = np.sort(values)[::-1]
        cumulative = np.concatenate(([0.0], np.cumsum(descending)))
        for fraction in grid:
            count = min(
                len(descending),
                max(0, int(math.floor(len(descending) * fraction + 0.5))),
            )
            share = float(cumulative[count] / total) if total else 0.0
            curves.append(
                {
                    "group": group,
                    "top_pr_percent": 100 * fraction,
                    "cumulative_alert_share_percent": 100 * share,
                    "top_pr_n": count,
                }
            )
    return metrics, curves


def stable_fold(repository: str, folds: int, seed: int) -> int:
    digest = hashlib.sha256(f"{seed}|{repository.casefold()}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % folds


def auc_score(y_true: np.ndarray, probabilities: np.ndarray) -> float:
    positive = y_true == 1
    negative = y_true == 0
    n_positive = int(positive.sum())
    n_negative = int(negative.sum())
    if not n_positive or not n_negative:
        return math.nan
    ranks = rankdata(probabilities, method="average")
    positive_rank_sum = float(ranks[positive].sum())
    return (
        positive_rank_sum - n_positive * (n_positive + 1) / 2
    ) / (n_positive * n_negative)


def prediction_metrics(
    y_true: np.ndarray, probabilities: np.ndarray
) -> dict[str, float]:
    clipped = np.clip(probabilities, 1e-12, 1 - 1e-12)
    return {
        "brier_score": float(np.mean((probabilities - y_true) ** 2)),
        "log_loss": float(
            -np.mean(y_true * np.log(clipped) + (1 - y_true) * np.log(1 - clipped))
        ),
        "auroc": auc_score(y_true, probabilities),
        "observed_prevalence": float(np.mean(y_true)),
        "mean_predicted_probability": float(np.mean(probabilities)),
        "calibration_in_the_large": float(
            np.mean(probabilities) - np.mean(y_true)
        ),
    }


def grouped_cross_validated_predictions(
    frame: pd.DataFrame,
    folds: int,
    seed: int,
) -> tuple[pd.DataFrame, list[dict[str, Any]]]:
    if folds < 3:
        raise ValueError("--folds 必须至少为 3")
    fold = frame["repo_name"].map(
        lambda repository: stable_fold(repository, folds, seed)
    )
    if fold.nunique() != folds:
        raise ValueError("repository hash 未覆盖全部 CV folds")
    context = patsy.dmatrix(
        CONTEXT_FORMULA, frame, return_type="dataframe"
    )
    provenance = patsy.dmatrix(
        PROVENANCE_FORMULA, frame, return_type="dataframe"
    )
    y = frame["introduced_quality_any"].astype(int).to_numpy()
    predictions = {
        "context_only": np.full(len(frame), np.nan),
        "context_plus_provenance": np.full(len(frame), np.nan),
    }
    diagnostics: list[dict[str, Any]] = []
    for held_out in range(folds):
        test = fold.eq(held_out).to_numpy()
        train = ~test
        if len(np.unique(y[train])) != 2 or len(np.unique(y[test])) != 2:
            raise RuntimeError(f"CV fold {held_out} 缺少 outcome class")
        if frame.loc[train, "group"].nunique() != 2 or frame.loc[test, "group"].nunique() != 2:
            raise RuntimeError(f"CV fold {held_out} 缺少 AI/Human group")
        for name, design in (
            ("context_only", context),
            ("context_plus_provenance", provenance),
        ):
            result = sm.GLM(
                y[train],
                np.asarray(design.loc[train], dtype=float),
                family=sm.families.Binomial(),
            ).fit(maxiter=300)
            probabilities = result.predict(
                np.asarray(design.loc[test], dtype=float)
            )
            predictions[name][test] = np.clip(probabilities, 0.0, 1.0)
        diagnostics.append(
            {
                "fold": held_out,
                "test_pr_n": int(test.sum()),
                "test_repository_n": int(frame.loc[test, "repo_name"].nunique()),
                "test_ai_pr_n": int(frame.loc[test, "ai"].sum()),
                "test_human_pr_n": int(test.sum() - frame.loc[test, "ai"].sum()),
                "test_quality_positive_n": int(y[test].sum()),
            }
        )
    for name, values in predictions.items():
        if not np.isfinite(values).all():
            raise RuntimeError(f"{name} 存在缺失 OOF prediction")
    output = frame[
        ["pr_key", "group", "repo_name", "pr_number", "introduced_quality_any"]
    ].copy()
    output["fold"] = fold.to_numpy()
    for name, values in predictions.items():
        output[f"{name}_probability"] = values
    return output, diagnostics


def bootstrap_predictive_deltas(
    predictions: pd.DataFrame,
    draws: int,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if draws < 200:
        raise ValueError("--bootstrap-draws 必须至少为 200")
    y = predictions["introduced_quality_any"].astype(int).to_numpy()
    context = predictions["context_only_probability"].to_numpy(dtype=float)
    provenance = predictions[
        "context_plus_provenance_probability"
    ].to_numpy(dtype=float)
    model_metrics = {
        "context_only": prediction_metrics(y, context),
        "context_plus_provenance": prediction_metrics(y, provenance),
    }
    metric_rows = [
        {"model": model, **metrics}
        for model, metrics in model_metrics.items()
    ]

    repositories = sorted(predictions["repo_name"].unique())
    index_by_repository = {
        repository: np.flatnonzero(
            predictions["repo_name"].to_numpy() == repository
        )
        for repository in repositories
    }
    rng = np.random.default_rng(seed)
    delta_draws: dict[str, list[float]] = {
        "brier_score": [],
        "log_loss": [],
        "auroc": [],
    }
    for _ in range(draws):
        sampled = rng.choice(repositories, size=len(repositories), replace=True)
        indexes = np.concatenate([index_by_repository[item] for item in sampled])
        sampled_y = y[indexes]
        context_metrics = prediction_metrics(sampled_y, context[indexes])
        provenance_metrics = prediction_metrics(sampled_y, provenance[indexes])
        for metric in delta_draws:
            delta_draws[metric].append(
                provenance_metrics[metric] - context_metrics[metric]
            )
    delta_rows: list[dict[str, Any]] = []
    for metric, values in delta_draws.items():
        array = np.asarray(values, dtype=float)
        point = (
            model_metrics["context_plus_provenance"][metric]
            - model_metrics["context_only"][metric]
        )
        delta_rows.append(
            {
                "metric": metric,
                "delta_provenance_minus_context": point,
                "cluster_bootstrap_ci_low": float(np.nanpercentile(array, 2.5)),
                "cluster_bootstrap_ci_high": float(np.nanpercentile(array, 97.5)),
                "bootstrap_draws": draws,
                "improvement_direction": (
                    "negative" if metric in {"brier_score", "log_loss"} else "positive"
                ),
            }
        )
    return metric_rows, delta_rows


def calibration_table(
    predictions: pd.DataFrame, bins: int = 10
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for model in ("context_only", "context_plus_provenance"):
        probability = predictions[f"{model}_probability"]
        quantiles = pd.qcut(
            probability.rank(method="first"), bins, labels=False
        )
        for bin_index in range(bins):
            selected = quantiles.eq(bin_index)
            rows.append(
                {
                    "model": model,
                    "probability_decile": bin_index + 1,
                    "pr_n": int(selected.sum()),
                    "mean_predicted_probability": float(
                        probability[selected].mean()
                    ),
                    "observed_prevalence": float(
                        predictions.loc[selected, "introduced_quality_any"].mean()
                    ),
                }
            )
    return rows


def load_quality_alerts(
    path: Path,
    group: str,
    roster: pd.DataFrame,
) -> pd.DataFrame:
    alerts = pd.read_csv(path, low_memory=False)
    required = {
        "repo_name",
        "pr_number",
        "rule_id",
        "is_quality_alert",
        "quality_category",
    }
    missing = sorted(required - set(alerts.columns))
    if missing:
        raise ValueError(f"{group} alerts 缺少字段: {missing}")
    if "group" in alerts.columns:
        source_group = alerts["group"].map(lambda value: clean(value).casefold())
        alerts = alerts[source_group.eq(group.casefold())].copy()
    alerts = alerts[alerts["is_quality_alert"].map(truthy)].copy()
    alerts["group"] = group
    alerts["pr_key"] = [
        pr_key(group, repo, number)
        for repo, number in zip(
            alerts["repo_name"], alerts["pr_number"], strict=True
        )
    ]
    roster_keys = set(roster.loc[roster["group"] == group, "pr_key"])
    alerts = alerts[alerts["pr_key"].isin(roster_keys)].copy()
    language_by_key = roster.set_index("pr_key")["repo_language"].to_dict()
    alerts["repo_language"] = alerts["pr_key"].map(language_by_key)
    alerts["rule_id"] = alerts["rule_id"].map(clean)
    alerts["quality_category"] = alerts["quality_category"].map(clean)
    if alerts[["repo_language", "rule_id", "quality_category"]].eq("").any().any():
        raise ValueError(f"{group} quality alerts 存在空 taxonomy 字段")
    expected = int(
        roster.loc[
            roster["group"] == group, "introduced_quality_alerts"
        ].sum()
    )
    if len(alerts) != expected:
        raise ValueError(
            f"{group} quality alert 守恒失败: alerts={len(alerts)} expected={expected}"
        )
    return alerts


def js_divergence_bits(left: np.ndarray, right: np.ndarray) -> float:
    left = np.asarray(left, dtype=float)
    right = np.asarray(right, dtype=float)
    if left.sum() <= 0 or right.sum() <= 0:
        return math.nan
    left = left / left.sum()
    right = right / right.sum()
    middle = (left + right) / 2

    def kl(values: np.ndarray) -> float:
        selected = values > 0
        return float(
            np.sum(values[selected] * np.log2(values[selected] / middle[selected]))
        )

    return 0.5 * kl(left) + 0.5 * kl(right)


def issue_profile_analysis(
    roster: pd.DataFrame,
    alerts: pd.DataFrame,
    minimum_language_prs: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    category_occurrence = alerts[
        ["group", "pr_key", "quality_category"]
    ].drop_duplicates()
    categories = sorted(category_occurrence["quality_category"].unique())
    category_rows: list[dict[str, Any]] = []
    category_vectors: dict[str, np.ndarray] = {}
    for group in GROUPS:
        denominator = int((roster["group"] == group).sum())
        counts = (
            category_occurrence[category_occurrence["group"] == group][
                "quality_category"
            ]
            .value_counts()
            .reindex(categories, fill_value=0)
        )
        category_vectors[group] = counts.to_numpy(dtype=float)
        for category, count in counts.items():
            category_rows.append(
                {
                    "group": group,
                    "quality_category": category,
                    "pr_with_category_n": int(count),
                    "all_pr_n": denominator,
                    "pr_prevalence_percent": 100 * int(count) / denominator,
                    "share_of_pr_category_occurrences_percent": (
                        100 * int(count) / int(counts.sum())
                    ),
                }
            )
    left = category_vectors["ai"]
    right = category_vectors["human"]
    left_distribution = left / left.sum()
    right_distribution = right / right.sum()
    category_metrics = [
        {
            "scope": "broad_quality_categories",
            "ai_pr_category_occurrence_n": int(left.sum()),
            "human_pr_category_occurrence_n": int(right.sum()),
            "jensen_shannon_divergence_bits": js_divergence_bits(left, right),
            "total_variation_distance": float(
                0.5 * np.abs(left_distribution - right_distribution).sum()
            ),
            "maximum_absolute_share_difference_percentage_points": float(
                100 * np.max(np.abs(left_distribution - right_distribution))
            ),
        }
    ]

    rule_occurrence = alerts[
        ["group", "pr_key", "repo_language", "rule_id"]
    ].drop_duplicates()
    roster_counts = (
        roster.groupby(["repo_language", "group"]).size().unstack(fill_value=0)
    )
    language_rows: list[dict[str, Any]] = []
    for language, counts in roster_counts.iterrows():
        if (
            counts.get("ai", 0) < minimum_language_prs
            or counts.get("human", 0) < minimum_language_prs
        ):
            continue
        target = rule_occurrence[rule_occurrence["repo_language"] == language]
        rules = sorted(target["rule_id"].unique())
        if not rules:
            continue
        vectors: dict[str, np.ndarray] = {}
        top_rules: dict[str, set[str]] = {}
        for group in GROUPS:
            occurrences = (
                target[target["group"] == group]["rule_id"]
                .value_counts()
                .reindex(rules, fill_value=0)
            )
            vectors[group] = occurrences.to_numpy(dtype=float)
            top_rules[group] = set(
                occurrences.sort_values(ascending=False).head(10).index
            )
        if vectors["ai"].sum() == 0 or vectors["human"].sum() == 0:
            continue
        ai_distribution = vectors["ai"] / vectors["ai"].sum()
        human_distribution = vectors["human"] / vectors["human"].sum()
        language_rows.append(
            {
                "repo_language": language,
                "ai_pr_n": int(counts["ai"]),
                "human_pr_n": int(counts["human"]),
                "ai_pr_rule_occurrence_n": int(vectors["ai"].sum()),
                "human_pr_rule_occurrence_n": int(vectors["human"].sum()),
                "union_rule_n": len(rules),
                "jensen_shannon_divergence_bits": js_divergence_bits(
                    vectors["ai"], vectors["human"]
                ),
                "distribution_overlap": float(
                    np.minimum(ai_distribution, human_distribution).sum()
                ),
                "top_10_rule_overlap_n": len(
                    top_rules["ai"] & top_rules["human"]
                ),
            }
        )
    if not language_rows:
        raise RuntimeError("没有语言满足 within-language rule-profile 门槛")
    weights = np.asarray(
        [row["ai_pr_n"] + row["human_pr_n"] for row in language_rows],
        dtype=float,
    )
    category_metrics.append(
        {
            "scope": "within_language_rule_profiles_weighted_mean",
            "eligible_language_n": len(language_rows),
            "minimum_prs_per_group": minimum_language_prs,
            "jensen_shannon_divergence_bits": float(
                np.average(
                    [
                        row["jensen_shannon_divergence_bits"]
                        for row in language_rows
                    ],
                    weights=weights,
                )
            ),
            "distribution_overlap": float(
                np.average(
                    [row["distribution_overlap"] for row in language_rows],
                    weights=weights,
                )
            ),
            "top_10_rule_overlap_n_mean": float(
                np.average(
                    [row["top_10_rule_overlap_n"] for row in language_rows],
                    weights=weights,
                )
            ),
        }
    )
    return category_rows, category_metrics, language_rows


def rq3_coverage_analysis(
    references_path: Path,
    findings_path: Path,
    summary_path: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    references = pd.read_csv(references_path, low_memory=False)
    findings = pd.read_csv(findings_path, low_memory=False)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    required_references = {
        "group",
        "reference_family",
        "quality_primary_reference",
        "quality_category",
        "semantic_recovered",
    }
    required_findings = {"group", "codeql_relation"}
    if required_references - set(references.columns):
        raise ValueError("RQ3 reference recovery 缺少必要字段")
    if required_findings - set(findings.columns):
        raise ValueError("RQ3 finding relations 缺少必要字段")
    primary_mask = (
        references["reference_family"].map(clean).eq("quality")
        & references["quality_primary_reference"].map(truthy)
    )
    if "validated_issue_reference" in references.columns:
        primary_mask &= references["validated_issue_reference"].map(truthy)
    primary = references[primary_mask].copy()
    primary["semantic_recovered"] = pd.to_numeric(
        primary["semantic_recovered"], errors="raise"
    ).astype(int)
    if not set(primary["semantic_recovered"].unique()).issubset({0, 1}):
        raise ValueError("semantic_recovered 必须是二元字段")
    rows: list[dict[str, Any]] = []
    for group in (*GROUPS, "pooled"):
        target = primary if group == "pooled" else primary[primary["group"] == group]
        for category, category_frame in target.groupby("quality_category"):
            recovered = int(category_frame["semantic_recovered"].sum())
            total = len(category_frame)
            low, high = proportion_confint(
                recovered, total, alpha=0.05, method="wilson"
            )
            rows.append(
                {
                    "group": group,
                    "quality_category": clean(category),
                    "primary_reference_n": total,
                    "semantic_recovered_n": recovered,
                    "semantic_recovery_percent": 100 * recovered / total,
                    "wilson_ci_low_percent": 100 * float(low),
                    "wilson_ci_high_percent": 100 * float(high),
                }
            )

    relation_rows: list[dict[str, Any]] = []
    findings["group"] = findings["group"].map(lambda value: clean(value).casefold())
    findings["codeql_relation"] = findings["codeql_relation"].map(clean)
    for group in (*GROUPS, "pooled"):
        target = findings if group == "pooled" else findings[findings["group"] == group]
        counts = target["codeql_relation"].value_counts()
        for relation, count in counts.items():
            relation_rows.append(
                {
                    "group": group,
                    "codeql_relation": relation,
                    "finding_n": int(count),
                    "finding_percent": 100 * int(count) / len(target),
                }
            )
    audit = summary.get("automatic_matcher_audit", {})
    matcher_audit = {
        "semantic_same_issue_finding_n": int(
            summary["semantic_relation_counts"]["same_issue"]
        ),
        "automatic_true_semantic_alignment_n": int(
            audit["true_semantic_alignment_n"]
        ),
        "automatic_missed_semantic_alignment_n": int(
            audit["missed_semantic_alignment_n"]
        ),
        "automatic_false_alignment_n": int(audit["false_alignment_n"]),
        "automatic_sensitivity_to_semantic_recoveries": float(
            audit["sensitivity_to_semantic_recoveries"]
        ),
        "automatic_positive_predictive_value": float(
            audit["positive_predictive_value"]
        ),
    }
    return rows, relation_rows, matcher_audit


def insight_report(
    concentration: list[dict[str, Any]],
    predictive_metrics: list[dict[str, Any]],
    predictive_deltas: list[dict[str, Any]],
    profile_metrics: list[dict[str, Any]],
    rq3_categories: list[dict[str, Any]],
    matcher_audit: dict[str, Any],
) -> str:
    concentration_by_group = {row["group"]: row for row in concentration}
    model_by_name = {row["model"]: row for row in predictive_metrics}
    delta_by_name = {row["metric"]: row for row in predictive_deltas}
    broad = next(
        row for row in profile_metrics if row["scope"] == "broad_quality_categories"
    )
    within_language = next(
        row
        for row in profile_metrics
        if row["scope"] == "within_language_rule_profiles_weighted_mean"
    )
    pooled_rq3 = [
        row for row in rq3_categories if row["group"] == "pooled"
    ]
    pooled_lines = "\n".join(
        f"- {row['quality_category']}: "
        f"{row['semantic_recovered_n']}/{row['primary_reference_n']} "
        f"({row['semantic_recovery_percent']:.2f}%)."
        for row in sorted(
            pooled_rq3, key=lambda item: item["quality_category"]
        )
    )
    return f"""# Cross-RQ insight analysis

## 1. Sparse, heavy-tailed Quality risk

- AI: {concentration_by_group['ai']['affected_pr_percent']:.2f}% of PRs were
  Quality-positive, while the top 1% of PRs contributed
  {concentration_by_group['ai']['top_1_percent_alert_share_percent']:.2f}% of
  introduced Quality alerts (Gini
  {concentration_by_group['ai']['gini']:.3f}).
- Human: {concentration_by_group['human']['affected_pr_percent']:.2f}% were
  Quality-positive, while the top 1% contributed
  {concentration_by_group['human']['top_1_percent_alert_share_percent']:.2f}%
  (Gini {concentration_by_group['human']['gini']:.3f}).

This supports a tail-risk interpretation. It does not imply that alerts are
runtime defects or that the largest PRs are caused by authorship.

## 2. Incremental predictive value of provenance

Repository-grouped {int(next(iter(predictive_deltas))['bootstrap_draws']) if predictive_deltas else 0}-draw
cluster bootstrap intervals were computed from out-of-fold predictions.

- Context-only Brier score:
  {model_by_name['context_only']['brier_score']:.5f}; context plus provenance:
  {model_by_name['context_plus_provenance']['brier_score']:.5f}; difference
  {delta_by_name['brier_score']['delta_provenance_minus_context']:+.5f}
  [{delta_by_name['brier_score']['cluster_bootstrap_ci_low']:+.5f},
  {delta_by_name['brier_score']['cluster_bootstrap_ci_high']:+.5f}].
- Context-only AUROC: {model_by_name['context_only']['auroc']:.5f}; context
  plus provenance: {model_by_name['context_plus_provenance']['auroc']:.5f};
  difference {delta_by_name['auroc']['delta_provenance_minus_context']:+.5f}
  [{delta_by_name['auroc']['cluster_bootstrap_ci_low']:+.5f},
  {delta_by_name['auroc']['cluster_bootstrap_ci_high']:+.5f}].

This is a predictive, not causal, analysis. Its role is to quantify whether
the recorded AI/Human label improves out-of-repository risk ranking beyond the
same observable covariates used by the formal RQ2 model.

## 3. Issue-profile similarity

- Broad category Jensen--Shannon divergence:
  {broad['jensen_shannon_divergence_bits']:.4f} bits; total-variation
  distance: {broad['total_variation_distance']:.4f}.
- Within-language rule-profile weighted mean Jensen--Shannon divergence:
  {within_language['jensen_shannon_divergence_bits']:.4f} bits; distribution
  overlap: {within_language['distribution_overlap']:.4f}, across
  {int(within_language['eligible_language_n'])} eligible languages.

The rule comparison is stratified by CodeQL database language and counts each
PR at most once per rule. It therefore avoids treating repeated alerts from
one PR or language-specific query packs as a distinct authorship signature.

## 4. LLM--CodeQL coverage

Pooled primary-Quality semantic recovery by category:

{pooled_lines}

The deterministic location matcher recovered
{matcher_audit['automatic_true_semantic_alignment_n']} of
{matcher_audit['semantic_same_issue_finding_n']} manually accepted same-issue
relations and missed
{matcher_audit['automatic_missed_semantic_alignment_n']}; it also made
{matcher_audit['automatic_false_alignment_n']} false alignments. Exact
location matching is therefore not an adequate substitute for the frozen
same-root-cause review.

## Paper-level synthesis

The evidence supports one bounded argument: CodeQL-detectable Quality risk is
sparse and heavy-tailed rather than uniformly elevated in AI-authored PRs; the
recorded authorship label contributes little standalone predictive information
after observable context is included; and the tested LLM reviewer recovers
only a small, category-dependent subset of the static-analysis references.
Repository policy should therefore use layered, PR-level gates rather than AI
provenance alone.
"""


def main() -> None:
    args = parse_args()
    inputs = {
        "analysis_pr_level": resolve(args.analysis_pr_level),
        "ai_alerts": resolve(args.ai_alerts),
        "human_alerts": resolve(args.human_alerts),
        "rq3_reference_recovery": resolve(args.rq3_reference_recovery),
        "rq3_finding_relations": resolve(args.rq3_finding_relations),
        "rq3_summary": resolve(args.rq3_summary),
    }
    for name, path in inputs.items():
        if not path.is_file():
            raise FileNotFoundError(f"{name} 不存在: {path}")
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    analysis = load_analysis(inputs["analysis_pr_level"])
    concentration_metrics, concentration_curves = concentration_analysis(analysis)
    predictions, fold_diagnostics = grouped_cross_validated_predictions(
        analysis, args.folds, args.seed
    )
    predictive_metrics, predictive_deltas = bootstrap_predictive_deltas(
        predictions, args.bootstrap_draws, args.seed
    )
    calibration = calibration_table(predictions)

    alert_frames = [
        load_quality_alerts(inputs["ai_alerts"], "ai", analysis),
        load_quality_alerts(inputs["human_alerts"], "human", analysis),
    ]
    alerts = pd.concat(alert_frames, ignore_index=True)
    category_profile, profile_metrics, language_profiles = issue_profile_analysis(
        analysis, alerts, args.min_language_prs_per_group
    )
    rq3_categories, rq3_relations, matcher_audit = rq3_coverage_analysis(
        inputs["rq3_reference_recovery"],
        inputs["rq3_finding_relations"],
        inputs["rq3_summary"],
    )

    output_files = {
        "concentration_metrics.csv": concentration_metrics,
        "concentration_curve.csv": concentration_curves,
        "predictive_model_metrics.csv": predictive_metrics,
        "predictive_incremental_value.csv": predictive_deltas,
        "predictive_fold_diagnostics.csv": fold_diagnostics,
        "predictive_calibration.csv": calibration,
        "quality_category_pr_profile.csv": category_profile,
        "issue_profile_similarity.csv": profile_metrics,
        "within_language_rule_similarity.csv": language_profiles,
        "rq3_recovery_by_category.csv": rq3_categories,
        "rq3_finding_relation_profile.csv": rq3_relations,
    }
    for filename, rows in output_files.items():
        write_csv(output_dir / filename, rows)
    predictions.to_csv(
        output_dir / "predictive_out_of_fold_predictions.csv", index=False
    )

    write_text(
        output_dir / "report.md",
        insight_report(
            concentration_metrics,
            predictive_metrics,
            predictive_deltas,
            profile_metrics,
            rq3_categories,
            matcher_audit,
        ),
    )

    manifest = {
        "status": "completed",
        "analysis_name": "cross_rq_paper_insights",
        "scope": {
            "pr_n": len(analysis),
            "repository_n": int(analysis["repo_name"].nunique()),
            "ai_pr_n": int((analysis["group"] == "ai").sum()),
            "human_pr_n": int((analysis["group"] == "human").sum()),
            "quality_alert_n": int(analysis["introduced_quality_alerts"].sum()),
            "rq3_primary_quality_reference_n": int(
                sum(
                    row["primary_reference_n"]
                    for row in rq3_categories
                    if row["group"] == "pooled"
                )
            ),
        },
        "parameters": {
            "folds": args.folds,
            "bootstrap_draws": args.bootstrap_draws,
            "seed": args.seed,
            "min_language_prs_per_group": args.min_language_prs_per_group,
            "context_formula": CONTEXT_FORMULA,
            "provenance_formula": PROVENANCE_FORMULA,
            "cv_group": "repo_name",
        },
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in inputs.items()
        },
        "outputs": sorted(
            path.name for path in output_dir.iterdir() if path.is_file()
        ),
        "interpretation_limits": [
            "predictive comparison is not a causal effect estimate",
            "CodeQL alerts are tool-defined outcomes rather than runtime defects",
            "within-language rule similarity is descriptive",
            "RQ3 recovery uses manually reviewed same-root-cause relations",
        ],
    }
    write_text(
        output_dir / "manifest.json",
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
    )
    print(
        "Cross-RQ insight analysis completed: "
        f"PRs={len(analysis)}, output={output_dir}"
    )


if __name__ == "__main__":
    main()
