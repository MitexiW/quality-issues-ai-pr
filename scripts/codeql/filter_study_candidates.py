#!/usr/bin/env python3
# CodeQL pipeline entry point.
"""Filter AI or human PR candidates for the AI-vs-human CodeQL study.

Unlike ``filter_fix_candidates.py`` this filter:

- supports both the AI tables (``pull_request`` / ``pr_task_type``) and the
  human control tables (``human_pull_request`` / ``human_pr_task_type``);
- applies NO change-size filter and does NOT depend on ``pr_commit_details``
  (the human tables have no file-level diff), so both sides share identical
  inclusion criteria;
- emits a ``candidate_prs.csv`` whose schema is compatible with
  ``prepare_codeql_jobs.py`` and the rest of the existing pipeline.

Study inclusion criteria (defaults): repository ``stars`` strictly greater than
``--min-stars``; repository language in the eight-language set (Kotlin
excluded); ``pr_task_type.type`` in {fix, feat, refactor}; PR ``state=closed``
and ``merged_at`` not null; repository has at least ``--min-prs-per-repo``
qualifying PRs.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import duckdb

# Output schema mirrors filter_fix_candidates.PR_FIELDS so downstream scripts
# (prepare_codeql_jobs.py, summarize_results.py, run_scale_codeql_experiment.py)
# consume it unchanged. Change-size columns are emitted empty.
PR_FIELDS = [
    "repo_id",
    "repo_name",
    "repo_url",
    "language",
    "stars",
    "pr_id",
    "pr_number",
    "pr_title",
    "pr_body",
    "agent",
    "merged_at",
    "closed_at",
    "keyword_hit",
    "task_type",
    "task_confidence",
    "task_reason",
    "forks",
    "pr_url",
    "created_at",
    "total_changed_files",
    "total_changed_lines",
    "code_changed_files",
    "code_changed_lines",
    "noise_changed_files",
]

DEFAULT_LANGUAGES = (
    "Java",
    "JavaScript",
    "TypeScript",
    "Python",
    "Go",
    "Ruby",
    "C",
    "C++",
)
DEFAULT_TASK_TYPES = ("fix", "feat", "refactor")

SOURCE_TABLES = {
    "ai": ("pull_request", "pr_task_type", "AI_agent"),
    "human": ("human_pull_request", "human_pr_task_type", "Human"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("ai", "human"), required=True)
    parser.add_argument("--cache-dir", default="data/aidev_parquet")
    parser.add_argument("--output", required=True, help="candidate_prs.csv 输出路径")
    parser.add_argument("--min-stars", type=int, default=500)
    parser.add_argument("--min-prs-per-repo", type=int, default=1)
    parser.add_argument("--languages", nargs="+", default=list(DEFAULT_LANGUAGES))
    parser.add_argument("--task-types", nargs="+", default=list(DEFAULT_TASK_TYPES))
    return parser.parse_args()


def parquet_glob(base_dir: Path, table: str) -> str:
    path = base_dir / table / "train" / "*.parquet"
    if not list(path.parent.glob(path.name)):
        raise FileNotFoundError(f"缺少 parquet 表: {path}")
    return str(path).replace("'", "''")


def sql_str(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_query(args: argparse.Namespace, base_dir: Path) -> str:
    pr_table, task_table, human_agent = SOURCE_TABLES[args.source]
    pr_glob = parquet_glob(base_dir, pr_table)
    task_glob = parquet_glob(base_dir, task_table)
    repo_glob = parquet_glob(base_dir, "repository")
    languages = ", ".join(sql_str(lang) for lang in args.languages)
    tasks = ", ".join(sql_str(t.strip().lower()) for t in args.task_types)
    # Human table has no `agent`; AI keeps its recorded agent.
    agent_expr = "p.agent" if args.source == "ai" else sql_str(human_agent)

    return f"""
    WITH eligible_repos AS (
      SELECT id, url, full_name, language, stars, forks
      FROM read_parquet('{repo_glob}')
      WHERE stars > {args.min_stars}
        AND language IN ({languages})
    ),
    selected_tasks AS (
      SELECT id, LOWER(TRIM(type)) AS task_type, confidence, reason
      FROM read_parquet('{task_glob}')
      WHERE LOWER(TRIM(type)) IN ({tasks})
      QUALIFY ROW_NUMBER() OVER (
        PARTITION BY id ORDER BY confidence DESC NULLS LAST
      ) = 1
    ),
    qualified AS (
      SELECT
        r.id AS repo_id,
        r.full_name AS repo_name,
        REPLACE(r.url, 'api.github.com/repos/', 'github.com/') AS repo_url,
        r.language AS language,
        r.stars AS stars,
        p.id AS pr_id,
        p.number AS pr_number,
        p.title AS pr_title,
        p.body AS pr_body,
        {agent_expr} AS agent,
        p.merged_at AS merged_at,
        p.closed_at AS closed_at,
        t.task_type AS keyword_hit,
        t.task_type AS task_type,
        t.confidence AS task_confidence,
        t.reason AS task_reason,
        r.forks AS forks,
        p.html_url AS pr_url,
        p.created_at AS created_at,
        '' AS total_changed_files,
        '' AS total_changed_lines,
        '' AS code_changed_files,
        '' AS code_changed_lines,
        '' AS noise_changed_files
      FROM read_parquet('{pr_glob}') p
      JOIN selected_tasks t ON p.id = t.id
      JOIN eligible_repos r ON p.repo_url = r.url
      WHERE p.state = 'closed' AND p.merged_at IS NOT NULL
    ),
    repo_counts AS (
      SELECT repo_id FROM qualified
      GROUP BY repo_id
      HAVING COUNT(DISTINCT pr_id) >= {args.min_prs_per_repo}
    )
    SELECT q.* FROM qualified q
    JOIN repo_counts c USING (repo_id)
    ORDER BY stars DESC, repo_name, created_at
    """


def main() -> None:
    args = parse_args()
    base_dir = Path(args.cache_dir)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    con = duckdb.connect()
    try:
        frame = con.execute(build_query(args, base_dir)).fetchdf()
    finally:
        con.close()

    frame = frame[PR_FIELDS]
    frame.to_csv(output, index=False)
    repo_count = frame["repo_id"].nunique()
    print(
        f"[{args.source}] 候选筛选完成：{len(frame)} 个 PR，{repo_count} 个仓库 -> {output}"
    )
    lang_counts = frame["language"].value_counts().to_dict()
    print("语言分布:", lang_counts)


if __name__ == "__main__":
    main()
