#!/usr/bin/env python3
"""Render the manuscript's statistical figures from frozen result artifacts.

The script writes vector PDFs directly into the flat LaTeX submission folder.
It deliberately keeps captions and figure placement in ``main.tex`` while
making every plotted value reproducible from the formal CSV outputs.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Iterable

import matplotlib as mpl

mpl.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORT_ROOT = (
    REPOSITORY_ROOT
    / "data/experiments/security-and-quality/study_stars500/reports"
)
DEFAULT_OUTPUT_DIR = REPOSITORY_ROOT / "paper/overleaf"

BLUE = "#0072B2"
GREEN = "#009E73"
ORANGE = "#D55E00"
EDGE = "#3F4145"


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise FileNotFoundError(f"Missing frozen input: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def require_equal(actual: object, expected: object, message: str) -> None:
    if actual != expected:
        raise ValueError(f"{message}: expected {expected!r}, found {actual!r}")


def configure_style() -> None:
    mpl.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Nimbus Roman", "Times New Roman", "Times", "DejaVu Serif"],
            "font.size": 8.0,
            "axes.labelsize": 8.0,
            "axes.titlesize": 8.0,
            "xtick.labelsize": 7.5,
            "ytick.labelsize": 7.5,
            "legend.fontsize": 7.1,
            "axes.linewidth": 0.65,
            "lines.linewidth": 1.2,
            "patch.linewidth": 0.65,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.02,
        }
    )


def finish_axes(axes: Iterable[plt.Axes], *, grid_axis: str = "y") -> None:
    for axis in axes:
        axis.grid(axis=grid_axis, color="#D9D9D9", linewidth=0.55, zorder=0)
        axis.spines["top"].set_visible(False)
        axis.spines["right"].set_visible(False)
        axis.tick_params(width=0.6, length=2.5)


def save_pdf(
    fig: plt.Figure,
    path: Path,
    title: str,
    *,
    pad_inches: float = 0.02,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(
        path,
        format="pdf",
        bbox_inches="tight",
        pad_inches=pad_inches,
        metadata={"Title": title, "Author": "Qihang Wan", "Creator": "Matplotlib"},
    )
    plt.close(fig)


def plot_ai_quality_profile(report_root: Path, output_dir: Path) -> None:
    profile_root = report_root / "final_human_confirmed_rq1_ai_profile_20260820_v2"
    task_rows = read_rows(profile_root / "introduced_by_task.csv")
    category_rows = read_rows(profile_root / "quality_category_profile.csv")
    location_rows = read_rows(profile_root / "introduced_by_location.csv")
    bootstrap_rows = read_rows(profile_root / "repository_cluster_bootstrap_intervals.csv")

    tasks = {
        row["stratum"]: float(row["affected_pr_percent"])
        for row in task_rows
        if row["family"] == "quality" and row["stratum"] != "all"
    }
    categories = {
        row["value"]: float(row["alert_percent_within_family"])
        for row in category_rows
        if row["family"] == "quality"
    }
    locations = {
        row["value"]: float(row["alert_percent_within_family"])
        for row in location_rows
        if row["family"] == "quality"
    }
    task_intervals = {
        row["task_type"]: (float(row["ci_low"]), float(row["ci_high"]))
        for row in bootstrap_rows
        if row["family"] == "quality"
        and row["metric"] == "affected_pr_percent"
        and row["task_type"] != "all"
    }

    task_values = [tasks[key] for key in ("feat", "fix", "refactor")]
    require_equal(
        set(task_intervals), {"feat", "fix", "refactor"}, "task confidence intervals changed"
    )
    task_low = np.array([task_intervals[key][0] for key in ("feat", "fix", "refactor")])
    task_high = np.array([task_intervals[key][1] for key in ("feat", "fix", "refactor")])
    category_values = [
        categories[key]
        for key in ("maintainability", "correctness_reliability", "performance_efficiency")
    ]
    location_values = [
        locations["production"],
        locations["test"],
        sum(locations[key] for key in ("example", "docs", "build")),
    ]

    require_equal(round(sum(category_values), 8), 100.0, "Quality category shares changed")
    require_equal(round(sum(location_values), 8), 100.0, "Quality location shares changed")

    with mpl.rc_context(
        {
            "font.size": 8.5,
            "axes.labelsize": 8.5,
            "xtick.labelsize": 8.0,
            "ytick.labelsize": 8.0,
        }
    ):
        fig, axes = plt.subplots(1, 3, figsize=(5.15, 2.25), gridspec_kw={"wspace": 0.48})
        specifications = [
            (axes[0], ["Feature", "Fix", "Refactor"], task_values, BLUE, 17),
            (
                axes[1],
                ["Maintainability", "Correctness", "Performance"],
                category_values,
                GREEN,
                100,
            ),
            (axes[2], ["Production", "Test", "Other"], location_values, ORANGE, 100),
        ]
        for panel, (axis, labels, values, color, maximum) in enumerate(specifications):
            error = None
            if panel == 0:
                estimates = np.asarray(values)
                error = np.vstack((estimates - task_low, task_high - estimates))
            bars = axis.bar(
                np.arange(3),
                values,
                width=0.62,
                color=color,
                edgecolor=EDGE,
                yerr=error,
                capsize=2.2 if error is not None else 0,
                error_kw={"elinewidth": 0.9, "capthick": 0.9},
                zorder=3,
            )
            axis.bar_label(bars, fmt="%.2f", padding=2, fontsize=8.0)
            axis.set_xticks(np.arange(3), labels=labels, rotation=20, ha="right")
            axis.set_ylim(0, maximum)
            axis.text(
                -0.13,
                1.08,
                f"({chr(97 + panel)})",
                transform=axis.transAxes,
                fontweight="bold",
            )
        axes[0].set_ylabel("Affected PRs (%)")
        axes[1].set_ylabel("Issue share (%)")
        axes[2].set_ylabel("Issue share (%)")
        finish_axes(axes)
        fig.subplots_adjust(bottom=0.28, top=0.86, left=0.10, right=0.99)
        save_pdf(
            fig,
            output_dir / "Fig3.pdf",
            "AI-authored PR task, category, and location profiles",
            pad_inches=0.03,
        )


def plot_ai_quality_burden(report_root: Path, output_dir: Path) -> None:
    """Plot the descriptive size gradient and positive-PR issue concentration."""

    profile_root = report_root / "final_human_confirmed_rq1_ai_profile_20260820_v2"
    change_rows = [
        row
        for row in read_rows(profile_root / "introduced_by_change_size.csv")
        if row["family"] == "quality" and row["stratum"] != "all"
    ]
    distribution_rows = [
        row
        for row in read_rows(profile_root / "pr_issue_count_distribution.csv")
        if row["family"] == "quality" and row["issue_count_bin"] != "0"
    ]

    change_by_band = {row["stratum"]: row for row in change_rows}
    distribution_by_bin = {row["issue_count_bin"]: row for row in distribution_rows}
    change_order = ["le_100", "101_1000", "gt_1000"]
    count_order = ["1", "2_3", "4_10", "gt_10"]
    require_equal(set(change_by_band), set(change_order), "changed-code bands changed")
    require_equal(set(distribution_by_bin), set(count_order), "issue-count bins changed")

    require_equal(
        sum(int(change_by_band[key]["pr_n"]) for key in change_order),
        3087,
        "changed-code bands no longer partition the AI cohort",
    )
    require_equal(
        sum(int(change_by_band[key]["introduced_alert_n"]) for key in change_order),
        775,
        "changed-code bands no longer conserve Quality issues",
    )
    require_equal(
        sum(int(change_by_band[key]["affected_pr_n"]) for key in change_order),
        251,
        "changed-code bands no longer conserve Quality-positive PRs",
    )
    positive_pr_n = sum(int(distribution_by_bin[key]["pr_n"]) for key in count_order)
    require_equal(positive_pr_n, 251, "positive-PR count distribution changed")
    require_equal(
        sum(int(distribution_by_bin[key]["introduced_alert_n"]) for key in count_order),
        775,
        "positive-PR count bins no longer conserve Quality issues",
    )

    changed_positive = np.array(
        [float(change_by_band[key]["affected_pr_percent"]) for key in change_order]
    )
    changed_low = np.array(
        [float(change_by_band[key]["affected_pr_wilson_low_percent"]) for key in change_order]
    )
    changed_high = np.array(
        [float(change_by_band[key]["affected_pr_wilson_high_percent"]) for key in change_order]
    )
    positive_pr_share = np.array(
        [100.0 * int(distribution_by_bin[key]["pr_n"]) / positive_pr_n for key in count_order]
    )
    issue_share = np.array(
        [float(distribution_by_bin[key]["alert_percent_within_family"]) for key in count_order]
    )
    require_equal(
        [round(value, 1) for value in positive_pr_share],
        [51.4, 25.1, 19.9, 3.6],
        "rounded positive-PR shares changed",
    )
    require_equal(
        [round(value, 1) for value in issue_share],
        [16.6, 19.2, 37.9, 26.2],
        "rounded Quality-issue shares changed",
    )

    # The paper reports the concentration curve from the rounded bin shares,
    # ordered from the highest to the lowest issue burden.  Keep these plotted
    # values explicit so that the displayed cumulative labels cannot silently
    # drift when the source CSV is regenerated at greater precision.
    concentration_pr_share = np.array([0.0, 3.6, 23.5, 48.6, 100.0])
    concentration_issue_share = np.array([0.0, 26.2, 64.1, 83.3, 100.0])

    with mpl.rc_context(
        {
            "font.size": 8.6,
            "axes.labelsize": 8.6,
            "xtick.labelsize": 8.0,
            "ytick.labelsize": 8.0,
            "legend.fontsize": 8.0,
        }
    ):
        fig, (left_ax, right_ax) = plt.subplots(
            1,
            2,
            figsize=(5.15, 2.30),
            gridspec_kw={"width_ratios": [1.04, 1.0], "wspace": 0.44},
        )

        y_left = np.arange(3)
        left_ax.errorbar(
            changed_positive,
            y_left,
            xerr=np.vstack((changed_positive - changed_low, changed_high - changed_positive)),
            fmt="o",
            markersize=5.2,
            color=BLUE,
            ecolor=BLUE,
            elinewidth=1.1,
            capsize=2.8,
            markeredgecolor=EDGE,
            markeredgewidth=0.55,
            zorder=3,
        )
        left_ax.set_yticks(
            y_left,
            labels=["≤100\n(54/1,964)", "101–1,000\n(135/952)", ">1,000\n(62/171)"],
        )
        left_ax.invert_yaxis()
        left_ax.set_xlim(0, 50)
        left_ax.set_xticks([0, 10, 20, 30, 40, 50])
        left_ax.set_xlabel("Affected PRs (%)")
        left_ax.set_ylabel("Changed code lines")
        left_ax.text(-0.31, 1.07, "(a)", transform=left_ax.transAxes, fontweight="bold")
        for position, estimate, upper in zip(y_left, changed_positive, changed_high):
            left_ax.text(
                upper + 0.7,
                position,
                f"{estimate:.2f}%",
                va="center",
                ha="left",
                fontsize=8.0,
            )

        right_ax.plot(
            [0.0, 100.0],
            [0.0, 100.0],
            color="#B8B8B8",
            linewidth=0.9,
            linestyle=(0, (3, 2)),
            zorder=1,
        )
        right_ax.plot(
            concentration_pr_share,
            concentration_issue_share,
            color=BLUE,
            linewidth=1.45,
            marker="o",
            markersize=4.5,
            markerfacecolor=BLUE,
            markeredgecolor=EDGE,
            markeredgewidth=0.45,
            zorder=3,
        )
        right_ax.set_xlim(0, 102)
        right_ax.set_ylim(0, 102)
        right_ax.set_xticks([0, 25, 50, 75, 100])
        right_ax.set_yticks([0, 25, 50, 75, 100])
        right_ax.set_xlabel("Cumulative share of\npositive PRs (%)")
        right_ax.set_ylabel("Cumulative share of\nconfirmed Quality issues (%)")
        right_ax.set_aspect("equal", adjustable="box")
        right_ax.text(-0.25, 1.07, "(b)", transform=right_ax.transAxes, fontweight="bold")
        right_ax.text(
            70,
            73,
            "Equality",
            color="#777777",
            fontsize=7.8,
            rotation=45,
            ha="center",
            va="bottom",
        )
        right_ax.annotate(
            "Top 3.6% PRs\n→ 26.2% of issues",
            xy=(3.6, 26.2),
            xytext=(8.0, 22.0),
            textcoords="data",
            fontsize=8.0,
            ha="left",
            va="top",
            bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.6},
            arrowprops={"arrowstyle": "-", "color": EDGE, "linewidth": 0.65},
        )
        right_ax.annotate(
            "Top 23.5% PRs\n→ 64.1% of issues",
            xy=(23.5, 64.1),
            xytext=(28.0, 94.0),
            textcoords="data",
            fontsize=8.0,
            ha="left",
            va="top",
            bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.6},
            arrowprops={"arrowstyle": "-", "color": EDGE, "linewidth": 0.65},
        )

        finish_axes((left_ax,), grid_axis="x")
        finish_axes((right_ax,), grid_axis="both")
        fig.subplots_adjust(bottom=0.25, top=0.88, left=0.16, right=0.99)
        save_pdf(
            fig,
            output_dir / "Fig2.pdf",
            "AI-authored PR change-size gradient and issue concentration",
            pad_inches=0.03,
        )


def plot_adjusted_effects(
    report_root: Path,
    output_dir: Path,
    *,
    layout: str,
) -> None:
    rows = read_rows(
        report_root / "final_human_confirmed_rq2_models_20260817_v1/standardized_effects.csv"
    )
    effects = {
        row["task_type"]: row
        for row in rows
        if row["family"] == "quality"
        and row["role"] == "primary"
        and row["model"] == "binary"
        and row["metric"] == "risk_difference"
    }
    task_order = ["all", "feat", "fix", "refactor"]
    labels = ["All PRs", "Feature", "Fix", "Refactor"]
    estimate = np.array([100.0 * float(effects[key]["estimate"]) for key in task_order])
    low = np.array([100.0 * float(effects[key]["ci_low"]) for key in task_order])
    high = np.array([100.0 * float(effects[key]["ci_high"]) for key in task_order])

    wrapped = layout == "wrapped"
    wrapped_style = {
        # The wrapped PDF is enlarged slightly when placed at 0.42\textwidth.
        # Keep its final type below the 10 pt body text while preserving an
        # approximately 8 pt minimum after LaTeX scaling.
        "font.size": 7.7,
        "axes.labelsize": 7.7,
        "xtick.labelsize": 7.2,
        "ytick.labelsize": 7.2,
    }
    with mpl.rc_context(wrapped_style if wrapped else {}):
        fig, axis = plt.subplots(figsize=(2.35, 1.72) if wrapped else (3.45, 2.40))
        y = np.arange(len(labels))
        axis.axvline(0, color="#666666", linewidth=0.8, linestyle="--", zorder=1)
        axis.errorbar(
            estimate,
            y,
            xerr=np.vstack((estimate - low, high - estimate)),
            fmt="o",
            markersize=5.0,
            color=BLUE,
            ecolor=BLUE,
            elinewidth=1.1,
            capsize=2.5,
            markeredgecolor=EDGE,
            markeredgewidth=0.5,
            zorder=3,
        )
        axis.set_yticks(y, labels=labels)
        axis.invert_yaxis()
        axis.set_xlim(-7, 8)
        if wrapped:
            axis.set_xticks([-5, 0, 5])
            axis.set_xlabel("Adjusted risk difference\n(AI minus Human, pp)")
            fig.subplots_adjust(bottom=0.30, top=0.98, left=0.31, right=0.98)
        else:
            axis.set_xlabel("Adjusted AI-minus-human risk difference (pp)")
            fig.subplots_adjust(bottom=0.22, top=0.96, left=0.27, right=0.98)
        finish_axes((axis,), grid_axis="x")
        save_pdf(
            fig,
            output_dir / "Fig4.pdf",
            "Adjusted AI-human Quality risk differences",
            pad_inches=0.03 if wrapped else 0.02,
        )


def plot_review_recovery(
    report_root: Path,
    output_dir: Path,
    *,
    layout: str,
) -> None:
    rows = read_rows(report_root / "final_human_confirmed_rq3_20260817_v1/group_metrics.csv")
    metrics = {
        row["group"]: row for row in rows if row["layer"] == "human_confirmed_primary"
    }
    groups = ["ai", "human"]
    labels = ["AI PRs", "Human PRs"]
    x = np.arange(2)
    offset = 0.10

    recall = np.array([100.0 * float(metrics[key]["micro_recall"]) for key in groups])
    recall_low = np.array([100.0 * float(metrics[key]["micro_ci_low"]) for key in groups])
    recall_high = np.array([100.0 * float(metrics[key]["micro_ci_high"]) for key in groups])
    hit = np.array([100.0 * float(metrics[key]["pr_hit_rate"]) for key in groups])
    hit_low = np.array([100.0 * float(metrics[key]["hit_ci_low"]) for key in groups])
    hit_high = np.array([100.0 * float(metrics[key]["hit_ci_high"]) for key in groups])

    wrapped = layout == "wrapped"
    wrapped_style = {
        "font.size": 9.2,
        "axes.labelsize": 9.2,
        "xtick.labelsize": 8.5,
        "ytick.labelsize": 8.5,
        "legend.fontsize": 8.5,
    }
    with mpl.rc_context(wrapped_style if wrapped else {}):
        fig, axis = plt.subplots(figsize=(2.50, 2.20) if wrapped else (3.45, 2.55))
        axis.errorbar(
            x - offset,
            recall,
            yerr=np.vstack((recall - recall_low, recall_high - recall)),
            fmt="o",
            markersize=5.0,
            color=BLUE,
            ecolor=BLUE,
            elinewidth=1.1,
            capsize=2.5,
            markeredgecolor=EDGE,
            markeredgewidth=0.5,
            label="Reference recall" if wrapped else "Alert-level recall",
            zorder=3,
        )
        axis.errorbar(
            x + offset,
            hit,
            yerr=np.vstack((hit - hit_low, hit_high - hit)),
            fmt="s",
            markersize=4.8,
            color=ORANGE,
            ecolor=ORANGE,
            elinewidth=1.1,
            capsize=2.5,
            markeredgecolor=EDGE,
            markeredgewidth=0.5,
            label="PR hit" if wrapped else "Positive-PR hit rate",
            zorder=3,
        )
        axis.set_xticks(x, labels=labels)
        axis.set_xlim(-0.45, 1.45)
        axis.set_ylim(0, 50)
        axis.set_ylabel("Recovery (%)")
        axis.legend(
            loc="upper center",
            bbox_to_anchor=(0.5, 1.22 if wrapped else 1.18),
            ncol=2,
            frameon=False,
        )
        finish_axes((axis,))
        fig.subplots_adjust(
            bottom=0.20 if wrapped else 0.18,
            top=0.77 if wrapped else 0.80,
            left=0.22 if wrapped else 0.18,
            right=0.98,
        )
        save_pdf(
            fig,
            output_dir / "Fig5.pdf",
            "LLM review recovery",
            pad_inches=0.03 if wrapped else 0.02,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-root", type=Path, default=DEFAULT_REPORT_ROOT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--layout",
        choices=("standard", "wrapped"),
        default="standard",
        help="Layout for Fig4/Fig5; wrapped uses a small canvas and larger type.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_style()
    plot_ai_quality_burden(args.report_root.resolve(), args.output_dir.resolve())
    plot_ai_quality_profile(args.report_root.resolve(), args.output_dir.resolve())
    plot_adjusted_effects(
        args.report_root.resolve(),
        args.output_dir.resolve(),
        layout=args.layout,
    )
    plot_review_recovery(
        args.report_root.resolve(),
        args.output_dir.resolve(),
        layout=args.layout,
    )
    print(
        f"Rendered Fig2.pdf--Fig5.pdf in {args.output_dir.resolve()} "
        f"(result layout={args.layout})"
    )


if __name__ == "__main__":
    main()
