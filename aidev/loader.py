from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pandas as pd

from .tables import HF_DATASET, TABLES

_CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "cache"


def list_tables() -> dict[str, str]:
    return dict(TABLES)


def _hf_uri(table: str) -> str:
    if table not in TABLES:
        known = ", ".join(sorted(TABLES))
        raise ValueError(f"未知表 '{table}'，可选: {known}")
    return f"hf://datasets/{HF_DATASET}/{table}.parquet"


def load_table(
    table: str,
    *,
    columns: Iterable[str] | None = None,
    cache: bool = False,
) -> pd.DataFrame:
    """从 Hugging Face 加载 AIDev 表。

    Args:
        table: 表名（不含 .parquet 后缀）
        columns: 只读取指定列，可显著减少下载量
        cache: 是否缓存到本地 data/cache/
    """
    cache_path = _CACHE_DIR / f"{table}.parquet"
    if cache and cache_path.exists():
        return pd.read_parquet(cache_path, columns=list(columns) if columns else None)

    df = pd.read_parquet(_hf_uri(table), columns=list(columns) if columns else None)

    if cache:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_parquet(cache_path, index=False)

    return df


def load_pr_with_patches(
    *,
    agents: Iterable[str] | None = None,
    languages: Iterable[str] | None = None,
    min_stars: int | None = None,
    limit: int | None = None,
) -> pd.DataFrame:
    """加载 AIDev-pop PR 及其文件级 patch，适合代码分析 / CodeQL 研究。"""
    pr_cols = ["id", "title", "body", "agent", "state", "repo_id", "html_url", "merged_at"]
    pr = load_table("pull_request", columns=pr_cols)
    repo = load_table("repository", columns=["id", "full_name", "language", "stars"])

    if agents:
        pr = pr[pr["agent"].isin(list(agents))]
    if min_stars is not None:
        hot_repos = set(repo.loc[repo["stars"] >= min_stars, "id"])
        pr = pr[pr["repo_id"].isin(hot_repos)]
    if languages:
        lang_repos = set(repo.loc[repo["language"].isin(list(languages)), "id"])
        pr = pr[pr["repo_id"].isin(lang_repos)]

    pr = pr.merge(repo, left_on="repo_id", right_on="id", how="left", suffixes=("", "_repo"))
    if limit:
        pr = pr.head(limit)

    pr_ids = pr["id"].tolist()
    patches = load_table(
        "pr_commit_details",
        columns=["pr_id", "filename", "patch", "status"],
    )
    patches = patches[patches["pr_id"].isin(pr_ids)]

    return pr.merge(patches, left_on="id", right_on="pr_id", how="inner")
