"""Build the lake from bronze: the dated facts, the warehouse, the as-of checks and the lake file.

    python scripts/build_lake.py               # everything, the work database removed after
    python scripts/build_lake.py --keep-work   # keep data/cache/lake/unscheduled.duckdb for a look
    python scripts/build_lake.py --no-checks   # skip the as-of checks on the real facts

Writes data/lake/unscheduled.duckdb, results/lake/*.json and results/parts/lake.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from unscheduled_lake.build import build, default_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--keep-work", action="store_true", help="keep the work database")
    parser.add_argument("--no-checks", action="store_true", help="skip the as-of checks on the real facts")
    parser.add_argument("--memory", default="2GB", help="DuckDB memory limit")
    parser.add_argument("--threads", type=int, default=2, help="DuckDB and dbt threads")
    args = parser.parse_args(argv)
    settings = default_settings(
        keep_work=args.keep_work, run_checks=not args.no_checks, memory=args.memory, threads=args.threads
    )
    summary = build(settings)
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
