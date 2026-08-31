#!/usr/bin/env python3
# Statistical analysis entry point.
"""Fit the frozen introduced-only RQ2 outcome models.

The command requires both a final RQ2-ready analysis snapshot and a final,
outcome-blind full-sample roster produced by ``prepare_rq2_design.py``.  The
formal study roster contains every analyzable PR with unit weight.  It fits
repository-clustered GEE models, standardizes predictions over that same full
population, and keeps Quality (primary) and Security (secondary) separate.
The formal comparison adjusts for task type, CodeQL database language, and
change size; calendar time is not part of the estimand or model.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
import pandas as pd
import patsy
import statsmodels.api as sm
from scipy.stats import chi2
from statsmodels.genmod.cov_struct import Exchangeable


ROOT = Path(__file__).resolve().parents[2]
FAMILIES = ("quality", "security")
OUTCOMES = {
    "quality": {
        "binary": "introduced_quality_any",
        "count": "introduced_quality_alerts",
        "role": "primary",
    },
    "security": {
        "binary": "introduced_security_any",
        "count": "introduced_security_alerts",
        "role": "secondary",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-pr-level", type=Path, required=True)
    parser.add_argument("--snapshot-manifest", type=Path, required=True)
    parser.add_argument("--design-weights", type=Path, required=True)
    parser.add_argument("--design-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--draws", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20260623)
    parser.add_argument("--min-family-events", type=int, default=20)
    parser.add_argument("--min-repositories", type=int, default=20)
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


def strict_boolean(value: Any, field: str) -> bool:
    text = clean(value).casefold()
    if text in {"1", "true", "yes", "y"}:
        return True
    if text in {"0", "false", "no", "n"}:
        return False
    raise ValueError(f"{field} 不是有效布尔值: {value!r}")


def normalize_pr_number(value: Any) -> str:
    text = clean(value)
    try:
        return str(int(float(text)))
    except (TypeError, ValueError):
        return text


def strict_nonnegative_integer(value: Any, field: str) -> int:
    try:
        parsed = float(clean(value))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} 不是有效整数: {value!r}") from error
    if not math.isfinite(parsed) or parsed < 0 or not parsed.is_integer():
        raise ValueError(f"{field} 不是非负整数: {value!r}")
    return int(parsed)


def strict_finite_float(value: Any, field: str) -> float:
    try:
        parsed = float(clean(value))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} 不是有效数值: {value!r}") from error
    if not math.isfinite(parsed):
        raise ValueError(f"{field} 不是有限数值: {value!r}")
    return parsed


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    maximize_csv_field_limit()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), [
            {key: clean(value) for key, value in row.items()} for row in reader
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


def validate_manifests(
    snapshot: dict[str, Any], design: dict[str, Any]
) -> None:
    if not snapshot.get("rq2_ready"):
        raise RuntimeError("snapshot manifest 未声明 rq2_ready=true")
    if design.get("status") != "final_design":
        raise RuntimeError("design manifest 不是 final_design")
    if not design.get("source_rq2_ready"):
        raise RuntimeError("design 并非来自 RQ2-ready snapshot")
    if not design.get("outcome_blind"):
        raise RuntimeError("design manifest 未声明 outcome_blind=true")
    if clean(design.get("design_name")) != "unweighted_full_sample":
        raise RuntimeError(
            "正式 RQ2 只接受 design_name=unweighted_full_sample；"
            "拒绝匹配、倾向加权或删减样本的 design"
        )
    snapshot_id = clean(snapshot.get("snapshot_id"))
    source_id = clean(design.get("source_snapshot_id"))
    if snapshot_id and source_id and snapshot_id != source_id:
        raise RuntimeError(
            f"snapshot/design ID 不一致: {snapshot_id!r} != {source_id!r}"
        )


def join_inputs(
    analysis_rows: list[dict[str, str]],
    design_rows: list[dict[str, str]],
) -> pd.DataFrame:
    analysis: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in analysis_rows:
        if not strict_boolean(row.get("quality_gate_pass"), "quality_gate_pass"):
            continue
        key = (
            clean(row.get("group")).casefold(),
            clean(row.get("repo_name")).casefold(),
            normalize_pr_number(row.get("pr_number")),
        )
        if key[0] not in {"ai", "human"} or not key[1] or not key[2]:
            raise ValueError(f"analysis 中存在无效 PR key: {key}")
        if key in analysis:
            raise ValueError(f"analysis 中存在重复 PR: {key}")
        analysis[key] = row
    joined: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for design in design_rows:
        key = (
            clean(design.get("group")).casefold(),
            clean(design.get("repo_name")).casefold(),
            normalize_pr_number(design.get("pr_number")),
        )
        if key in seen:
            raise ValueError(f"design 中存在重复 PR: {key}")
        seen.add(key)
        if key[0] not in {"ai", "human"} or not key[1] or not key[2]:
            raise ValueError(f"design 中存在无效 PR key: {key}")
        if clean(design.get("design_name")) != "unweighted_full_sample":
            raise ValueError(f"design row 不是 unweighted_full_sample: {key}")
        if not strict_boolean(design.get("common_support"), "common_support"):
            raise ValueError(
                f"full-sample roster 不允许排除 PR: {key}"
            )
        if clean(design.get("support_exclusion_reason")):
            raise ValueError(f"full-sample roster 不允许 exclusion reason: {key}")
        source = analysis.get(key)
        if source is None:
            raise ValueError(f"full-sample roster PR 在 analysis 中不存在: {key}")
        weight = strict_finite_float(
            design.get("overlap_weight"), "overlap_weight"
        )
        if not math.isclose(
            weight, 1.0, rel_tol=0.0, abs_tol=1e-12
        ):
            raise ValueError(
                f"full-sample roster 要求每个 PR 权重为 1: {key} -> {weight}"
            )
        task_type = clean(design.get("task_type"))
        repo_language = clean(design.get("repo_language"))
        log1p_changed_kloc = strict_finite_float(
            design.get("log1p_changed_kloc"), "log1p_changed_kloc"
        )
        if (
            not task_type
            or not repo_language
            or log1p_changed_kloc < 0
        ):
            raise ValueError(f"full-sample roster 协变量无效: {key}")
        if task_type != clean(source.get("task_type")):
            raise ValueError(f"{key} 的 task_type 在 analysis/design 中不一致")
        source_language = (
            clean(source.get("repo_language")) or clean(source.get("language"))
        )
        if repo_language != source_language:
            raise ValueError(f"{key} 的 repo_language 在 analysis/design 中不一致")

        outcomes: dict[str, int] = {}
        for family in FAMILIES:
            any_field = f"introduced_{family}_any"
            count_field = f"introduced_{family}_alerts"
            count = strict_nonnegative_integer(source.get(count_field), count_field)
            observed_any = strict_boolean(source.get(any_field), any_field)
            if observed_any != (count > 0):
                raise ValueError(
                    f"{key} 的 {any_field} 与 {count_field} 不守恒"
                )
            outcomes[any_field] = int(observed_any)
            outcomes[count_field] = count
        joined.append(
            {
                "repo_name": clean(source.get("repo_name")),
                "pr_number": normalize_pr_number(source.get("pr_number")),
                "group": key[0],
                "ai": int(key[0] == "ai"),
                "task_type": task_type,
                "repo_language": repo_language,
                "log1p_changed_kloc": log1p_changed_kloc,
                "overlap_weight": weight,
                **outcomes,
            }
        )
    frame = pd.DataFrame(joined)
    if frame.empty or set(frame["group"]) != {"ai", "human"}:
        raise RuntimeError("最终 design join 后必须同时包含 AI 和 Human")
    if set(frame["overlap_weight"]) != {1.0}:
        raise RuntimeError("正式 RQ2 分析权重必须全部为 1")
    if len(frame) != len(analysis):
        missing = sorted(set(analysis) - seen)
        raise RuntimeError(
            "full-sample roster 未覆盖全部 quality-gated PR："
            f"analysis={len(analysis)} roster={len(frame)} "
            f"missing_examples={missing[:5]}"
        )
    return frame


def formula(outcome: str) -> str:
    return (
        f"{outcome} ~ ai * C(task_type, Treatment(reference='fix'))"
        " + log1p_changed_kloc + C(repo_language)"
    )


def weighted_mean_variance(
    values: np.ndarray, weights: np.ndarray
) -> tuple[float, float]:
    mean = float(np.average(values, weights=weights))
    variance = float(np.average((values - mean) ** 2, weights=weights))
    return mean, variance


def nb_alpha(values: np.ndarray, weights: np.ndarray) -> tuple[float, float]:
    mean, variance = weighted_mean_variance(values, weights)
    ratio = variance / mean if mean > 0 else 0.0
    alpha = max((variance - mean) / (mean * mean), 1e-6) if mean > 0 else 1e-6
    return alpha, ratio


def covariance_draws(
    parameters: np.ndarray,
    covariance: np.ndarray,
    draws: int,
    rng: np.random.Generator,
) -> np.ndarray:
    covariance = (covariance + covariance.T) / 2
    eigenvalues, eigenvectors = np.linalg.eigh(covariance)
    scale = max(float(np.max(np.abs(eigenvalues))), 1.0)
    tolerance = scale * 1e-8
    if float(np.min(eigenvalues)) < -tolerance:
        raise RuntimeError(
            "robust covariance 非正半定，拒绝通过特征值裁剪隐藏无效不确定性"
        )
    clipped = np.maximum(eigenvalues, scale * 1e-12)
    stable = (eigenvectors * clipped) @ eigenvectors.T
    return rng.multivariate_normal(parameters, stable, size=draws)


def design_for_prediction(result: Any, frame: pd.DataFrame) -> np.ndarray:
    matrix = patsy.build_design_matrices(
        [result.model.data.design_info],
        frame,
        return_type="dataframe",
    )[0]
    return np.asarray(matrix, dtype=float)


def inverse_link(kind: str, linear: np.ndarray) -> np.ndarray:
    if kind == "binary":
        clipped = np.clip(linear, -35, 35)
        return 1 / (1 + np.exp(-clipped))
    return np.exp(np.clip(linear, -35, 35))


def interval(values: np.ndarray) -> tuple[float, float]:
    return float(np.percentile(values, 2.5)), float(np.percentile(values, 97.5))


def standardized_effects(
    result: Any,
    frame: pd.DataFrame,
    kind: str,
    family: str,
    role: str,
    draws: int,
    rng: np.random.Generator,
) -> list[dict[str, Any]]:
    parameter_draws = covariance_draws(
        np.asarray(result.params, dtype=float),
        np.asarray(result.cov_params(), dtype=float),
        draws,
        rng,
    )
    records: list[dict[str, Any]] = []
    tasks = ["all", *sorted(frame["task_type"].unique())]
    for task in tasks:
        target = frame if task == "all" else frame[frame["task_type"] == task]
        if target.empty:
            continue
        weights = np.asarray(target["overlap_weight"], dtype=float)
        standardized: dict[str, tuple[float, np.ndarray]] = {}
        for group, ai_value in (("ai", 1), ("human", 0)):
            counterfactual = target.copy()
            counterfactual["ai"] = ai_value
            matrix = design_for_prediction(result, counterfactual)
            point_values = inverse_link(
                kind, matrix @ np.asarray(result.params, dtype=float)
            )
            point = float(np.average(point_values, weights=weights))
            draw_values = inverse_link(kind, matrix @ parameter_draws.T)
            draw_means = np.average(draw_values, axis=0, weights=weights)
            standardized[group] = (point, draw_means)
            low, high = interval(draw_means)
            records.append(
                {
                    "family": family,
                    "role": role,
                    "model": kind,
                    "task_type": task,
                    "metric": (
                        f"marginal_probability_{group}"
                        if kind == "binary"
                        else f"marginal_mean_count_{group}"
                    ),
                    "estimate": point,
                    "ci_low": low,
                    "ci_high": high,
                }
            )
        ai_point, ai_draws = standardized["ai"]
        human_point, human_draws = standardized["human"]
        difference = ai_point - human_point
        difference_draws = ai_draws - human_draws
        ratio = ai_point / human_point if human_point > 0 else math.nan
        ratio_draws = np.divide(
            ai_draws,
            human_draws,
            out=np.full_like(ai_draws, np.nan),
            where=human_draws > 0,
        )
        metrics = [
            (
                "risk_difference" if kind == "binary" else "mean_difference",
                difference,
                difference_draws,
            ),
            (
                "risk_ratio" if kind == "binary" else "incidence_rate_ratio",
                ratio,
                ratio_draws,
            ),
        ]
        if kind == "binary":
            ai_odds = ai_point / max(1 - ai_point, 1e-12)
            human_odds = human_point / max(1 - human_point, 1e-12)
            odds_ratio = ai_odds / human_odds if human_odds > 0 else math.nan
            ai_draw_odds = ai_draws / np.maximum(1 - ai_draws, 1e-12)
            human_draw_odds = human_draws / np.maximum(1 - human_draws, 1e-12)
            metrics.append(
                (
                    "marginal_odds_ratio",
                    odds_ratio,
                    ai_draw_odds / np.maximum(human_draw_odds, 1e-12),
                )
            )
        for metric, point, metric_draws in metrics:
            finite = metric_draws[np.isfinite(metric_draws)]
            low, high = interval(finite)
            records.append(
                {
                    "family": family,
                    "role": role,
                    "model": kind,
                    "task_type": task,
                    "metric": metric,
                    "estimate": point,
                    "ci_low": low,
                    "ci_high": high,
                }
            )
    return records


def interaction_test(result: Any) -> tuple[int, float, float]:
    names = list(result.params.index)
    indexes = [
        index
        for index, name in enumerate(names)
        if name.startswith("ai:C(task_type")
    ]
    if not indexes:
        return 0, math.nan, math.nan
    coefficients = np.asarray(result.params, dtype=float)[indexes]
    covariance = np.asarray(result.cov_params(), dtype=float)[np.ix_(indexes, indexes)]
    statistic = float(coefficients.T @ np.linalg.pinv(covariance) @ coefficients)
    degrees = len(indexes)
    return degrees, statistic, float(chi2.sf(statistic, degrees))


def fit_family(
    frame: pd.DataFrame,
    family: str,
    draws: int,
    rng: np.random.Generator,
    min_events: int,
    min_repositories: int,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    specification = OUTCOMES[family]
    role = specification["role"]
    events = int(frame[specification["binary"]].sum())
    group_events = {
        group: int(
            frame.loc[frame["group"] == group, specification["binary"]].sum()
        )
        for group in ("ai", "human")
    }
    repositories = int(frame["repo_name"].nunique())
    diagnostics: list[dict[str, Any]] = [
        {
            "family": family,
            "role": role,
            "pr_n": len(frame),
            "repository_n": repositories,
            "binary_event_n": events,
            "ai_binary_event_n": group_events["ai"],
            "human_binary_event_n": group_events["human"],
            "count_sum": int(frame[specification["count"]].sum()),
            "model_status": "pending",
            "skip_reason": "",
        }
    ]
    if (
        events < min_events
        or min(group_events.values()) == 0
        or repositories < min_repositories
    ):
        reasons = []
        if events < min_events:
            reasons.append(f"events<{min_events}")
        if min(group_events.values()) == 0:
            reasons.append("zero_events_in_group")
        if repositories < min_repositories:
            reasons.append(f"repositories<{min_repositories}")
        diagnostics[0]["model_status"] = "skipped_sparse"
        diagnostics[0]["skip_reason"] = "|".join(reasons)
        return [], [], diagnostics, []

    effects: list[dict[str, Any]] = []
    coefficients: list[dict[str, Any]] = []
    interactions: list[dict[str, Any]] = []
    weights = np.asarray(frame["overlap_weight"], dtype=float)
    for kind in ("binary", "count"):
        outcome = specification[kind]
        if kind == "binary":
            model_family = sm.families.Binomial()
            dispersion_alpha = ""
            variance_mean_ratio = ""
        else:
            dispersion_alpha, variance_mean_ratio = nb_alpha(
                np.asarray(frame[outcome], dtype=float), weights
            )
            model_family = sm.families.NegativeBinomial(alpha=dispersion_alpha)
        model_arguments: dict[str, Any] = {
            "groups": "repo_name",
            "data": frame,
            "family": model_family,
            "cov_struct": Exchangeable(),
        }
        if not np.allclose(weights, 1.0):
            model_arguments["weights"] = frame["overlap_weight"]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            model = sm.GEE.from_formula(
                formula(outcome),
                **model_arguments,
            )
            result = model.fit(maxiter=500)
        dependence = getattr(result.cov_struct, "dep_params", None)
        dependence_valid = (
            dependence is None
            or bool(np.all(np.isfinite(np.asarray(dependence, dtype=float))))
        )
        if not getattr(result, "converged", True) or not dependence_valid:
            diagnostics[0][f"{kind}_converged"] = False
            diagnostics[0][f"{kind}_inference_status"] = (
                "suppressed_nonconvergence"
            )
            diagnostics[0][f"{kind}_inference_reason"] = (
                f"{family} {kind} exchangeable GEE did not converge"
            )
            diagnostics[0][f"{kind}_working_correlation"] = "exchangeable"
            diagnostics[0][f"{kind}_scale"] = clean(getattr(result, "scale", ""))
            diagnostics[0][f"{kind}_dependence_parameter"] = clean(dependence)
            if kind == "count":
                diagnostics[0]["count_effects_reportable"] = False
                diagnostics[0]["count_suppression_rule"] = "nonconvergence"
                diagnostics[0]["count_variance_mean_ratio"] = variance_mean_ratio
                diagnostics[0]["negative_binomial_alpha"] = dispersion_alpha
            continue
        try:
            model_effects = standardized_effects(
                result, frame, kind, family, role, draws, rng
            )
        except RuntimeError as error:
            if "robust covariance 非正半定" not in str(error):
                raise
            diagnostics[0][f"{kind}_converged"] = True
            diagnostics[0][f"{kind}_inference_status"] = (
                "suppressed_invalid_robust_covariance"
            )
            diagnostics[0][f"{kind}_inference_reason"] = str(error)
            diagnostics[0][f"{kind}_working_correlation"] = "exchangeable"
            diagnostics[0][f"{kind}_scale"] = float(result.scale)
            diagnostics[0][f"{kind}_dependence_parameter"] = clean(
                getattr(result.cov_struct, "dep_params", "")
            )
            continue
        if kind == "count":
            observed_mean = float(
                np.average(np.asarray(frame[outcome], dtype=float), weights=weights)
            )
            overall_standardized_means = [
                float(row["estimate"])
                for row in model_effects
                if row["task_type"] == "all"
                and row["metric"].startswith("marginal_mean_count_")
            ]
            maximum_standardized_mean = max(
                overall_standardized_means, default=math.nan
            )
            prediction_to_observed_ratio = (
                maximum_standardized_mean / observed_mean
                if observed_mean > 0
                else math.inf
            )
            count_effects_stable = (
                math.isfinite(prediction_to_observed_ratio)
                and prediction_to_observed_ratio <= 10
            )
            diagnostics[0]["count_observed_mean"] = observed_mean
            diagnostics[0][
                "count_maximum_standardized_mean"
            ] = maximum_standardized_mean
            diagnostics[0][
                "count_prediction_to_observed_ratio"
            ] = prediction_to_observed_ratio
            diagnostics[0]["count_effects_reportable"] = count_effects_stable
            diagnostics[0]["count_suppression_rule"] = (
                ""
                if count_effects_stable
                else "standardized_mean_gt_10x_observed_mean"
            )
            if count_effects_stable:
                effects.extend(model_effects)
        else:
            effects.extend(model_effects)
        for name, estimate, standard_error, p_value in zip(
            result.params.index,
            result.params,
            result.bse,
            result.pvalues,
            strict=True,
        ):
            coefficients.append(
                {
                    "family": family,
                    "role": role,
                    "model": kind,
                    "term": name,
                    "estimate": estimate,
                    "standard_error": standard_error,
                    "p_value": p_value,
                }
            )
        degrees, statistic, p_value = interaction_test(result)
        interactions.append(
            {
                "family": family,
                "role": role,
                "model": kind,
                "degrees_of_freedom": degrees,
                "wald_chi_square": statistic,
                "p_value": p_value,
            }
        )
        diagnostics[0][f"{kind}_converged"] = True
        diagnostics[0][f"{kind}_inference_status"] = "completed"
        diagnostics[0][f"{kind}_working_correlation"] = "exchangeable"
        diagnostics[0][f"{kind}_scale"] = float(result.scale)
        diagnostics[0][f"{kind}_dependence_parameter"] = clean(
            getattr(result.cov_struct, "dep_params", "")
        )
        if kind == "count":
            diagnostics[0]["count_variance_mean_ratio"] = variance_mean_ratio
            diagnostics[0]["negative_binomial_alpha"] = dispersion_alpha
    suppressed_models = [
        kind
        for kind in ("binary", "count")
        if str(diagnostics[0].get(f"{kind}_inference_status", "")).startswith(
            "suppressed_"
        )
    ]
    if suppressed_models:
        diagnostics[0]["model_status"] = "completed_with_suppressed_inference"
        diagnostics[0]["suppressed_inference_models"] = "|".join(
            suppressed_models
        )
    else:
        diagnostics[0]["model_status"] = (
            "completed"
            if diagnostics[0].get("count_effects_reportable", True)
            else "completed_count_effects_suppressed_unstable"
        )
    return effects, coefficients, diagnostics, interactions


def main() -> None:
    args = parse_args()
    if args.draws < 1:
        raise ValueError("--draws 必须大于 0")
    if args.min_family_events < 1 or args.min_repositories < 1:
        raise ValueError("最小 event/repository 门槛必须大于 0")
    paths = {
        "analysis": resolve(args.analysis_pr_level),
        "snapshot": resolve(args.snapshot_manifest),
        "weights": resolve(args.design_weights),
        "design": resolve(args.design_manifest),
        "output": resolve(args.output_dir),
    }
    snapshot_manifest = json.loads(paths["snapshot"].read_text(encoding="utf-8"))
    design_manifest = json.loads(paths["design"].read_text(encoding="utf-8"))
    validate_manifests(snapshot_manifest, design_manifest)
    analysis_fields, analysis_rows = read_csv(paths["analysis"])
    _, design_rows = read_csv(paths["weights"])
    weight_design_names = {
        clean(row.get("design_name")) for row in design_rows
        if clean(row.get("design_name"))
    }
    if len(weight_design_names) > 1:
        raise ValueError(
            f"design weights 包含多个 design_name: {sorted(weight_design_names)}"
        )
    weight_design_name = (
        next(iter(weight_design_names))
        if weight_design_names
        else clean(design_manifest.get("design_name")) or "unspecified"
    )
    required_outcomes = {
        specification[kind]
        for specification in OUTCOMES.values()
        for kind in ("binary", "count")
    }
    missing = required_outcomes - set(analysis_fields)
    if missing:
        raise ValueError(f"analysis_pr_level 缺少 RQ2 outcomes: {sorted(missing)}")
    frame = join_inputs(analysis_rows, design_rows)
    weighted_analysis = not bool(
        np.allclose(np.asarray(frame["overlap_weight"], dtype=float), 1.0)
    )
    rng = np.random.default_rng(args.seed)

    effects: list[dict[str, Any]] = []
    coefficients: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    interactions: list[dict[str, Any]] = []
    for family in FAMILIES:
        family_results = fit_family(
            frame,
            family,
            args.draws,
            rng,
            args.min_family_events,
            args.min_repositories,
        )
        effects.extend(family_results[0])
        coefficients.extend(family_results[1])
        diagnostics.extend(family_results[2])
        interactions.extend(family_results[3])

    output_dir = paths["output"]
    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(
        output_dir / "standardized_effects.csv",
        [
            "family",
            "role",
            "model",
            "task_type",
            "metric",
            "estimate",
            "ci_low",
            "ci_high",
        ],
        effects,
    )
    write_csv(
        output_dir / "model_coefficients.csv",
        [
            "family",
            "role",
            "model",
            "term",
            "estimate",
            "standard_error",
            "p_value",
        ],
        coefficients,
    )
    write_csv(
        output_dir / "model_diagnostics.csv",
        sorted({key for row in diagnostics for key in row}),
        diagnostics,
    )
    write_csv(
        output_dir / "task_interaction_tests.csv",
        [
            "family",
            "role",
            "model",
            "degrees_of_freedom",
            "wald_chi_square",
            "p_value",
        ],
        interactions,
    )
    output_manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "final_models",
        "source_snapshot_id": snapshot_manifest.get("snapshot_id", ""),
        "source_design_status": design_manifest.get("status", ""),
        "source_weight_design_name": weight_design_name,
        "source_design_balance": (
            design_manifest.get("balance", {})
            if weight_design_name == design_manifest.get("design_name")
            else design_manifest.get("secondary_design", {}).get("balance", {})
        ),
        "pr_n": len(frame),
        "repository_n": int(frame["repo_name"].nunique()),
        "ai_pr_n": int((frame["group"] == "ai").sum()),
        "human_pr_n": int((frame["group"] == "human").sum()),
        "draws": args.draws,
        "seed": args.seed,
        "quality_role": "primary",
        "security_role": "secondary",
        "weighted_analysis": weighted_analysis,
        "model_covariates": [
            "authorship_group",
            "task_type",
            "authorship_group_by_task_type",
            "log1p_changed_kloc",
            "repo_language",
        ],
        "calendar_time_in_model": False,
        "models": {
            "binary": "logistic GEE; exchangeable; repository clusters",
            "count": (
                "negative-binomial GEE; exchangeable; repository clusters; "
                "moment dispersion"
            ),
        },
        "count_effect_reporting_rule": (
            "Suppress standardized count effects when the largest overall "
            "counterfactual marginal mean exceeds 10 times the observed mean; "
            "retain raw distributions and model diagnostics."
        ),
        "count_effects_suppressed_families": [
            row["family"]
            for row in diagnostics
            if not row.get("count_effects_reportable", True)
        ],
        "inputs": {key: str(value) for key, value in paths.items() if key != "output"},
    }
    (output_dir / "model_manifest.json").write_text(
        json.dumps(output_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    report = [
        "# RQ2 adjusted introduced-alert models",
        "",
        f"- PR：{len(frame):,}",
        f"- repositories：{frame['repo_name'].nunique():,}",
        f"- AI：{(frame['group'] == 'ai').sum():,}",
        f"- Human：{(frame['group'] == 'human').sum():,}",
        f"- design：{weight_design_name}",
        f"- all PR weights equal 1：{not weighted_analysis}",
        "- suppressed count-effect families："
        + (
            ", ".join(output_manifest["count_effects_suppressed_families"])
            or "none"
        ),
        f"- parameter draws for standardized intervals：{args.draws:,}",
        "",
        "Quality 是唯一 confirmatory family；Security 保持 secondary，两个 family "
        "从未合并。主要解释文件为 `standardized_effects.csv`，回归系数仅用于审计。",
        "",
    ]
    (output_dir / "report.md").write_text("\n".join(report), encoding="utf-8")
    print(f"已生成 RQ2 models: {output_dir}")
    print(
        f"prs={len(frame)} repositories={frame['repo_name'].nunique()} "
        f"effects={len(effects)}"
    )


if __name__ == "__main__":
    main()
