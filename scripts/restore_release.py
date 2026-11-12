"""Restore the bronze, the locks and the config of a lake release into this checkout, as lake.yml does.

    python scripts/restore_release.py [--release lake-YYYYMMDD]

The committed numbers are rebuilt from a published release this way, so that the lake a reader can
download is the lake the numbers came from: restore, then scripts/build_lake.py,
scripts/run_analysis.py, scripts/backlog_charts.py and scripts/build_field.py. Each archive is checked
against the release's SHA256SUMS before it is opened. data/bronze is replaced, not merged, so no
table from an earlier local fetch survives. results/lake/release.json names the release restored and
the digest of its SHA256SUMS, so the numbers built next say which published lake they came from.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime
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
    record = {
        "tag": tag,
        "restored_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "bronze_archives": counts["bronze_archives"],
        "sha256sums_sha256": hashlib.sha256((folder / "SHA256SUMS").read_bytes()).hexdigest(),
    }
    out = ROOT / "results" / "lake" / "release.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    print(f"restore: {tag}, {counts['bronze_archives']} bronze archives, the locks and the config")
    return 0


if __name__ == "__main__":
    sys.exit(main())
