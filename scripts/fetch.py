"""Fetch public sources into locks, the ledger and bronze.

    uv run python scripts/fetch.py cvelist kev            the hourly pair
    uv run python scripts/fetch.py all                    every source, in dependency order
    uv run python scripts/fetch.py nvd --nvd-parts history --progress-log data/locks/nvd_progress.log
    uv run python scripts/fetch.py kev --reparse data/raw  parse again from raw files checked against the lock

Runs resume from the ledger unless --no-resume is given. --budget-minutes stops a source cleanly
after the unit in progress, so a scheduled job ends with its ledger and locks written. Raw files are
deleted after parsing unless --keep-raw is given (the workflow keeps them to upload by digest).
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from unscheduled_sources import base, registry


class Log:
    def __init__(self, path: Path | None) -> None:
        self.handle: TextIO | None = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.handle = path.open("a", encoding="utf-8")

    def __call__(self, message: str) -> None:
        line = f"{datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')} {message}"
        print(line, flush=True)
        if self.handle is not None:
            self.handle.write(line + "\n")
            self.handle.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("sources", nargs="+", help="source names, or all")
    parser.add_argument("--keep-raw", action="store_true")
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--budget-minutes", type=float, default=None)
    parser.add_argument("--nvd-parts", default="cves,history", help="cves, history or both")
    parser.add_argument("--progress-log", type=Path, default=None)
    parser.add_argument("--reparse", type=Path, default=None, help="parse raw files under this directory")
    args = parser.parse_args(argv)

    names = list(registry.SOURCES) if args.sources == ["all"] else args.sources
    log = Log(args.progress_log)
    ctx = registry.context(
        keep_raw=args.keep_raw,
        resume=not args.no_resume,
        budget_s=args.budget_minutes * 60 if args.budget_minutes else None,
        log=log,
    )
    failed: list[str] = []
    for name in names:
        cls = registry.fetcher_class(name)
        if name == "nvd":
            from unscheduled_sources.nvd import Nvd

            fetcher: base.Fetcher = Nvd(
                ctx, parts=tuple(p.strip() for p in args.nvd_parts.split(",") if p.strip())
            )
        else:
            fetcher = cls(ctx)
        log(f"{name}: start")
        try:
            if args.reparse is not None:
                summary = base.reparse(fetcher, args.reparse / name)
            else:
                summary = base.run(fetcher)
        except Exception as error:
            log(f"{name}: failed: {type(error).__name__}: {error}")
            failed.append(name)
            continue
        log(
            f"{name}: done, {summary.units} units, {summary.skipped} already in the ledger, "
            f"{summary.rows_in} rows in, {summary.rows_changed} new"
            + (f", refused {summary.refused}" if summary.refused else "")
            + (", stopped at the time budget" if summary.stopped_early else "")
        )
    if failed:
        log(f"failed: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
