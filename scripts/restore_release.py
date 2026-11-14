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

import tarfile

from scripts.reset_and_rederive import (
    archive_digests,
    download,
    download_one,
    extract,
    recorded_release,
    settled_lake_release,
    unchanged_since_recorded,
)


def restore_tables(tag: str | None, tables: list[str]) -> int:
    """Single bronze tables from a named release, each checked by digest and extracted in place of
    any earlier copy of that table, the rest of bronze untouched. Each table gets a note beside it,
    data/bronze/<table>.release.json, naming the release and the archive's digest, which the model
    that reads it copies into its record."""
    if not tag:
        raise SystemExit("restore: --table needs --release, the release the table is read from")
    bronze = ROOT / "data" / "bronze"
    bronze.mkdir(parents=True, exist_ok=True)
    for table in tables:
        archive, digest = download_one(tag, f"bronze-{table}.tar")
        shutil.rmtree(bronze / table, ignore_errors=True)
        with tarfile.open(archive) as tar:
            tar.extractall(bronze, filter="data")
        note = {"tag": tag, "archive": archive.name, "sha256": digest}
        (bronze / f"{table}.release.json").write_text(json.dumps(note, indent=1) + "\n", encoding="utf-8")
        print(f"restore: {table} from {tag}, {archive.name} {digest[:12]}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--release", default=None)
    parser.add_argument(
        "--recorded",
        action="store_true",
        help="restore the release results/lake/release.json names, fail if an archive changed since, keep the record",
    )
    parser.add_argument(
        "--table",
        action="append",
        default=[],
        help="restore only this bronze table from --release, beside the bronze already here (repeatable)",
    )
    args = parser.parse_args(argv)
    if args.table:
        return restore_tables(args.release, args.table)
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
