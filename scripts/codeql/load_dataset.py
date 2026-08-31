#!/usr/bin/env python3
# CodeQL pipeline entry point.
"""Stream AIDev tables or local CSV/Parquet files in bounded batches."""

from __future__ import annotations

import argparse
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pandas as pd

DEFAULT_DATASET = "hao-li/AIDev"


def iter_local_batches(
    path: str | Path,
    *,
    batch_size: int = 10_000,
    columns: list[str] | None = None,
) -> Iterator[pd.DataFrame]:
    source = Path(path)
    suffix = source.suffix.lower()
    if suffix in {".csv", ".csv.gz"} or source.name.lower().endswith(".csv.gz"):
        yield from pd.read_csv(
            source,
            usecols=columns,
            chunksize=batch_size,
            low_memory=False,
        )
        return
    if suffix in {".parquet", ".pq"}:
        import pyarrow.dataset as ds

        dataset = ds.dataset(source, format="parquet")
        scanner = dataset.scanner(columns=columns, batch_size=batch_size)
        for batch in scanner.to_batches():
            yield batch.to_pandas()
        return
    raise ValueError(f"不支持的输入格式: {source}，仅支持 CSV/CSV.GZ/Parquet")


def iter_hf_batches(
    table: str,
    *,
    dataset_name: str = DEFAULT_DATASET,
    batch_size: int = 10_000,
) -> Iterator[pd.DataFrame]:
    """Use datasets streaming so the full remote table is not materialized."""
    from datasets import load_dataset

    stream = load_dataset(
        dataset_name,
        name=table,
        split="train",
        streaming=True,
    )
    rows: list[dict[str, Any]] = []
    for row in stream:
        rows.append(row)
        if len(rows) >= batch_size:
            yield pd.DataFrame.from_records(rows)
            rows.clear()
    if rows:
        yield pd.DataFrame.from_records(rows)


def iter_batches(
    source: str,
    *,
    table: str | None = None,
    dataset_name: str = DEFAULT_DATASET,
    batch_size: int = 10_000,
    columns: list[str] | None = None,
) -> Iterator[pd.DataFrame]:
    if source == "hf":
        if not table:
            raise ValueError("source=hf 时必须提供 table")
        yield from iter_hf_batches(
            table,
            dataset_name=dataset_name,
            batch_size=batch_size,
        )
    else:
        yield from iter_local_batches(source, batch_size=batch_size, columns=columns)


def load_small_table(
    source: str,
    *,
    table: str | None = None,
    dataset_name: str = DEFAULT_DATASET,
    batch_size: int = 10_000,
) -> pd.DataFrame:
    batches = list(
        iter_batches(
            source,
            table=table,
            dataset_name=dataset_name,
            batch_size=batch_size,
        )
    )
    return pd.concat(batches, ignore_index=True) if batches else pd.DataFrame()


def main() -> None:
    parser = argparse.ArgumentParser(description="流式检查 AIDev 或本地表")
    parser.add_argument("--source", default="hf", help="hf 或 CSV/Parquet 路径")
    parser.add_argument("--table", default="pull_request", help="Hugging Face 子集名")
    parser.add_argument("--dataset", default=DEFAULT_DATASET)
    parser.add_argument("--batch-size", type=int, default=10_000)
    parser.add_argument("--limit", type=int, default=5, help="仅显示前 N 行")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    shown = 0
    total = 0
    for batch in iter_batches(
        args.source,
        table=args.table,
        dataset_name=args.dataset,
        batch_size=args.batch_size,
    ):
        total += len(batch)
        if shown < args.limit:
            sample = batch.head(args.limit - shown)
            print(sample.to_string(index=False))
            shown += len(sample)
        if shown >= args.limit:
            break
    logging.info("已读取 %s 行（预览模式）", total)


if __name__ == "__main__":
    main()
