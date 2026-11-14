"""Restore the bronze, the locks and the config of a lake release into this checkout, as lake.yml does.

    python scripts/restore_release.py [--release lake-YYYYMMDD]

Without --release it restores the newest settled release: the hourly fetch refreshes the newest lake
release in place until the next daily fetch, so the one before it is the newest that no run changes.
The committed numbers are rebuilt from a published release this way, so that the lake a reader can
download is the lake the numbers came from: restore, then scripts/build_lake.py,
scripts/run_analysis.py, scripts/backlog_charts.py and scripts/build_field.py. Each archive is checked
against the release's SHA256SUMS before it is opened, or against the digest GitHub recorded at upload
when the sums leave it out. data/bronze is replaced, not merged, so no table from an earlier local
fetch survives. results/lake/release.json names the release restored and the digest of every archive,
so the numbers built next say which published bronze they came from, and a rederive can tell when a
release changed. With --recorded it restores the release that record names instead, fails when any
archive's digest moved since, and leaves the record as it is: the models workflow starts this way.
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

from scripts.reset_and_rederive import (
    archive_digests,
    download,
    extract,
    recorded_release,
    settled_lake_release,
    unchanged_since_recorded,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--release", default=None)
    parser.add_argument(
        "--recorded",
        action="store_true",
        help="restore the release results/lake/release.json names, fail if an archive changed since, keep the record",
    )
    args = parser.parse_args(argv)
    recorded = recorded_release() if args.recorded else None
    if args.recorded and not recorded:
        raise SystemExit("restore: results/lake/release.json names no release to restore")
    tag = str(recorded["tag"]) if recorded else args.release or settled_lake_release()
    folder = download(tag)
    if recorded:
        problem = unchanged_since_recorded(folder, recorded, tag)
        if problem:
            raise SystemExit(f"restore: {problem}")
    for stale in (ROOT / "data" / "bronze", ROOT / "data" / "locks"):
        shutil.rmtree(stale, ignore_errors=True)
    counts = extract(folder, ROOT)
    if recorded:
        print(
            f"restore: {tag} as recorded, every archive unchanged, {counts['bronze_archives']} bronze archives"
        )
        return 0
    record = {
        "tag": tag,
        "restored_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "bronze_archives": counts["bronze_archives"],
        "sha256sums_sha256": hashlib.sha256((folder / "SHA256SUMS").read_bytes()).hexdigest(),
        "archives": archive_digests(folder),
    }
    out = ROOT / "results" / "lake" / "release.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    print(f"restore: {tag}, {counts['bronze_archives']} bronze archives, the locks and the config")
    return 0


if __name__ == "__main__":
    sys.exit(main())
