#!/usr/bin/env python3
# CodeQL pipeline entry point.
"""Run `go build ./...` from a module subdirectory for CodeQL tracing."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("module_dir")
    args = parser.parse_args()
    module_dir = Path(args.module_dir)
    subprocess.run(["go", "build", "./..."], cwd=module_dir, check=True)


if __name__ == "__main__":
    main()
