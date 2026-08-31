#!/usr/bin/env python3
# CodeQL pipeline entry point.
"""Filter task-type based PRs suitable for before/after CodeQL analysis."""

from __future__ import annotations

import argparse
from pathlib import Path

import duckdb
from huggingface_hub import snapshot_download

from prepare_codeql_jobs import CODEQL_LANGUAGE_MAP
from utils import setup_logging

REPO_ID = "hao-li/AIDev"
REVISION = "refs/convert/parquet"
TABLES = ("pull_request", "repository", "pr_task_type", "pr_commit_details")
DEFAULT_LANGUAGES = (
    "Java",
    "Kotlin",
    "JavaScript",
    "TypeScript",
    "Python",
    "Go",
    "Ruby",
)
DEFAULT_TASK_TYPES = ("fix",)

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
REPO_FIELDS = [
    "repo_id",
    "repo_name",
    "repo_url",
    "language",
    "stars",
    "ai_pr_count",
    "fix_pr_count",
    "forks",
    "agent_count",
    "avg_code_changed_files",
    "avg_code_changed_lines",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="使用 AIDev task type 和变更规模筛选 CodeQL PR"
    )
    parser.add_argument("--cache-dir", default="data/aidev_parquet")
    parser.add_argument("--output-dir", default="data/candidates")
    parser.add_argument("--skip-download", action="store_true")
    parser.add_argument("--min-stars", type=int, default=500)
    parser.add_argument("--min-prs-per-repo", type=int, default=3)
    parser.add_argument("--min-files", type=int, default=1)
    parser.add_argument("--max-files", type=int, default=20)
    parser.add_argument("--min-lines", type=int, default=1)
    parser.add_argument("--max-lines", type=int, default=1000)
    parser.add_argument("--languages", nargs="+", default=list(DEFAULT_LANGUAGES))
    parser.add_argument(
        "--task-types",
        nargs="+",
        default=list(DEFAULT_TASK_TYPES),
        help="允许的 AIDev task type；默认只保留 fix",
    )
    parser.add_argument(
        "--all-task-types",
        action="store_true",
        help="保留所有 AIDev task type，忽略 --task-types",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def download_tables(cache_dir: Path) -> Path:
    return Path(
        snapshot_download(
            repo_id=REPO_ID,
            repo_type="dataset",
            revision=REVISION,
            local_dir=str(cache_dir),
            allow_patterns=[
                f"{table}/train/*.parquet"
                for table in TABLES
            ],
            max_workers=1,
        )
    )


def parquet_glob(base_dir: Path, table: str) -> str:
    path = base_dir / table / "train" / "*.parquet"
    if not list(path.parent.glob(path.name)):
        raise FileNotFoundError(f"缺少 parquet 表: {path}")
    return str(path).replace("'", "''")


def sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def validate_args(args: argparse.Namespace) -> None:
    bounds = (
        ("min-stars", args.min_stars),
        ("min-prs-per-repo", args.min_prs_per_repo),
        ("min-files", args.min_files),
        ("max-files", args.max_files),
        ("min-lines", args.min_lines),
        ("max-lines", args.max_lines),
    )
    for name, value in bounds:
        if value < 0:
            raise ValueError(f"--{name} 不能为负数")
    if args.min_files > args.max_files:
        raise ValueError("--min-files 不能大于 --max-files")
    if args.min_lines > args.max_lines:
        raise ValueError("--min-lines 不能大于 --max-lines")
    unsupported = sorted(set(args.languages) - set(CODEQL_LANGUAGE_MAP))
    if unsupported:
        raise ValueError(f"CodeQL 不支持这些语言: {', '.join(unsupported)}")
    args.task_types = [item.strip().lower() for item in args.task_types if item.strip()]
    if not args.all_task_types and not args.task_types:
        raise ValueError("--task-types 不能为空，除非使用 --all-task-types")


def create_qualified_table(
    connection: duckdb.DuckDBPyConnection,
    args: argparse.Namespace,
    base_dir: Path,
) -> None:
    languages = ", ".join(sql_string(language) for language in args.languages)
    task_filter = ""
    if not args.all_task_types:
        task_types = ", ".join(sql_string(task_type) for task_type in args.task_types)
        task_filter = f"WHERE task_type IN ({task_types})"
    paths = {
        table: parquet_glob(base_dir, table)
        for table in TABLES
    }
    connection.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE qualified_pr AS
        WITH eligible_repos AS (
          SELECT id, url, full_name, language, stars, forks
          FROM read_parquet('{paths["repository"]}')
          WHERE stars > {args.min_stars}
            AND language IN ({languages})
        ),
        selected_tasks AS (
          SELECT
            id,
            LOWER(TRIM(type)) AS task_type,
            confidence,
            reason
          FROM read_parquet('{paths["pr_task_type"]}')
          {task_filter}
          QUALIFY ROW_NUMBER() OVER (
            PARTITION BY id ORDER BY confidence DESC NULLS LAST
          ) = 1
        ),
        selected_merged_pr AS (
          SELECT
            p.id AS pr_id,
            p.number,
            p.repo_id,
            p.title,
            p.body,
            p.agent,
            p.created_at,
            p.closed_at,
            p.merged_at,
            p.html_url,
            t.task_type AS type,
            t.confidence,
            t.reason
          FROM read_parquet('{paths["pull_request"]}') p
          JOIN selected_tasks t ON p.id = t.id
          WHERE p.state = 'closed'
            AND p.merged_at IS NOT NULL
        ),
        changed_files AS (
          SELECT
            pr_id,
            filename,
            COALESCE(
              changes,
              COALESCE(additions, 0) + COALESCE(deletions, 0)
            ) AS changes,
            CASE
              WHEN filename IS NULL THEN 1
              WHEN LOWER(filename) LIKE 'docs/%' THEN 1
              WHEN LOWER(filename) LIKE 'doc/%' THEN 1
              WHEN LOWER(filename) LIKE 'documentation/%' THEN 1
              WHEN LOWER(filename) LIKE 'examples/%' THEN 1
              WHEN LOWER(filename) LIKE 'example/%' THEN 1
              WHEN LOWER(filename) LIKE 'samples/%' THEN 1
              WHEN LOWER(filename) LIKE 'sample/%' THEN 1
              WHEN LOWER(filename) LIKE '%.md' THEN 1
              WHEN LOWER(filename) LIKE '%.txt' THEN 1
              WHEN LOWER(filename) LIKE '%.rst' THEN 1
              WHEN LOWER(filename) LIKE '%.adoc' THEN 1
              WHEN LOWER(filename) LIKE '%/test/%' THEN 1
              WHEN LOWER(filename) LIKE '%/tests/%' THEN 1
              WHEN LOWER(filename) LIKE 'test/%' THEN 1
              WHEN LOWER(filename) LIKE 'tests/%' THEN 1
              WHEN LOWER(filename) LIKE '%test.%' THEN 1
              WHEN LOWER(filename) LIKE '%tests.%' THEN 1
              WHEN LOWER(filename) LIKE '%_test.%' THEN 1
              WHEN LOWER(filename) LIKE '%.spec.%' THEN 1
              WHEN LOWER(filename) LIKE '%.json' THEN 1
              WHEN LOWER(filename) LIKE '%.yml' THEN 1
              WHEN LOWER(filename) LIKE '%.yaml' THEN 1
              WHEN LOWER(filename) LIKE '%.toml' THEN 1
              WHEN LOWER(filename) LIKE '%.ini' THEN 1
              WHEN LOWER(filename) LIKE '%.lock' THEN 1
              WHEN LOWER(filename) LIKE '%package-lock.json' THEN 1
              WHEN LOWER(filename) LIKE '%yarn.lock' THEN 1
              WHEN LOWER(filename) LIKE '%pnpm-lock.yaml' THEN 1
              WHEN LOWER(filename) LIKE '%poetry.lock' THEN 1
              WHEN LOWER(filename) LIKE '%cargo.lock' THEN 1
              WHEN LOWER(filename) LIKE '%go.sum' THEN 1
              ELSE 0
            END AS is_noise_file
          FROM read_parquet('{paths["pr_commit_details"]}')
        ),
        pr_change_stats AS (
          SELECT
            pr_id,
            COUNT(*) AS total_changed_files,
            SUM(changes) AS total_changed_lines,
            SUM(CASE WHEN is_noise_file = 0 THEN 1 ELSE 0 END)
              AS code_changed_files,
            SUM(CASE WHEN is_noise_file = 0 THEN changes ELSE 0 END)
              AS code_changed_lines,
            SUM(CASE WHEN is_noise_file = 1 THEN 1 ELSE 0 END)
              AS noise_changed_files
          FROM changed_files
          GROUP BY pr_id
        ),
        size_qualified_pr AS (
          SELECT
            p.*,
            r.full_name,
            r.url AS repo_url,
            r.language,
            r.stars,
            r.forks,
            c.total_changed_files,
            c.total_changed_lines,
            c.code_changed_files,
            c.code_changed_lines,
            c.noise_changed_files
          FROM selected_merged_pr p
          JOIN eligible_repos r ON p.repo_id = r.id
          JOIN pr_change_stats c ON p.pr_id = c.pr_id
          WHERE c.code_changed_files BETWEEN {args.min_files} AND {args.max_files}
            AND c.code_changed_lines BETWEEN {args.min_lines} AND {args.max_lines}
        ),
        qualified_repo_ids AS (
          SELECT repo_id
          FROM size_qualified_pr
          GROUP BY repo_id
          HAVING COUNT(DISTINCT pr_id) >= {args.min_prs_per_repo}
        )
        SELECT p.*
        FROM size_qualified_pr p
        JOIN qualified_repo_ids r USING (repo_id)
        """
    )


def write_outputs(
    connection: duckdb.DuckDBPyConnection,
    output_dir: Path,
) -> tuple[int, int]:
    prs = connection.execute(
        """
        SELECT
          repo_id,
          full_name AS repo_name,
          REPLACE(repo_url, 'api.github.com/repos/', 'github.com/') AS repo_url,
          language,
          stars,
          pr_id,
          number AS pr_number,
          title AS pr_title,
          body AS pr_body,
          agent,
          merged_at,
          closed_at,
          LOWER(TRIM(type)) AS keyword_hit,
          LOWER(TRIM(type)) AS task_type,
          confidence AS task_confidence,
          reason AS task_reason,
          forks,
          html_url AS pr_url,
          created_at,
          total_changed_files,
          total_changed_lines,
          code_changed_files,
          code_changed_lines,
          noise_changed_files
        FROM qualified_pr
        ORDER BY stars DESC, repo_name, created_at
        """
    ).fetchdf()
    repos = connection.execute(
        """
        SELECT
          repo_id,
          full_name AS repo_name,
          REPLACE(repo_url, 'api.github.com/repos/', 'github.com/') AS repo_url,
          language,
          stars,
          COUNT(DISTINCT pr_id) AS ai_pr_count,
          COUNT(DISTINCT pr_id) AS fix_pr_count,
          forks,
          COUNT(DISTINCT agent) AS agent_count,
          AVG(code_changed_files) AS avg_code_changed_files,
          AVG(code_changed_lines) AS avg_code_changed_lines
        FROM qualified_pr
        GROUP BY repo_id, full_name, repo_url, language, stars, forks
        ORDER BY fix_pr_count DESC, stars DESC
        """
    ).fetchdf()

    output_dir.mkdir(parents=True, exist_ok=True)
    prs[PR_FIELDS].to_csv(output_dir / "candidate_prs.csv", index=False)
    repos[REPO_FIELDS].to_csv(output_dir / "candidate_repos.csv", index=False)
    return len(repos), len(prs)


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)
    validate_args(args)
    cache_dir = Path(args.cache_dir)
    base_dir = cache_dir if args.skip_download else download_tables(cache_dir)

    connection = duckdb.connect()
    try:
        create_qualified_table(connection, args, base_dir)
        repo_count, pr_count = write_outputs(connection, Path(args.output_dir))
    finally:
        connection.close()

    print(f"筛选完成：{repo_count} 个仓库，{pr_count} 个 PR")


if __name__ == "__main__":
    main()
