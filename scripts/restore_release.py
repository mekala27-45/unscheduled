"""Restore the bronze, the locks and the config of a lake release into this checkout, as lake.yml does.

    python scripts/restore_release.py [--release lake-YYYYMMDD]

The committed numbers are rebuilt from a published release this way, so that the lake a reader can
download is the lake the numbers came from: restore, then scripts/build_lake.py,
scripts/run_analysis.py, scripts/backlog_charts.py and scripts/build_field.py. Each archive is checked
against the release's SHA256SUMS before it is opened. data/bronze is replaced, not merged, so no
table from an earlier local fetch survives.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from scripts.reset_and_rederive import download, extract, newest_lake_release


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--release", default=None)
    args = parser.parse_args(argv)
    tag = args.release or newest_lake_release()
    folder = download(tag)
    for stale in (ROOT / "data" / "bronze", ROOT / "data" / "locks"):
        shutil.rmtree(stale, ignore_errors=True)
    counts = extract(folder, ROOT)
    print(f"restore: {tag}, {counts['bronze_archives']} bronze archives, the locks and the config")
    return 0


if __name__ == "__main__":
    sys.exit(main())
