"""Publish bronze, the locks and the status vocabulary as a lake release, the way fetch.yml does.

    python scripts/publish_lake.py            # lake-YYYYMMDD at the commit main points to on GitHub
    python scripts/publish_lake.py --dry-run  # write the archives and their sums, upload nothing

The scheduled fetch resumes from the newest lake release and never starts the lake from nothing
(fetch.yml), so the first one is published by the build with this script. Each bronze table goes up
as bronze-<table>.tar, the locks with the run ledger as locks.tar.gz, config/labels.yaml and
config/filers.yaml as config.tar.gz, and SHA256SUMS lists every archive. The archives are written
with sorted names, a fixed time and no owner, so the same files always give the same bytes. Only
the GitHub REST API is used, through the gh command line, which reads its own credential.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import subprocess
import sys
import tarfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "mekala27-45/unscheduled"
FIXED_TIME = int(datetime(2026, 1, 1, tzinfo=UTC).timestamp())


def _add_tree(tar: tarfile.TarFile, base: Path, top: str) -> None:
    for path in sorted((base / top).rglob("*")):
        if not path.is_file():
            continue
        info = tarfile.TarInfo(path.relative_to(base).as_posix())
        info.size = path.stat().st_size
        info.mtime = FIXED_TIME
        info.mode = 0o644
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        with path.open("rb") as handle:
            tar.addfile(info, handle)


def _add_file(tar: tarfile.TarFile, path: Path, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.size = path.stat().st_size
    info.mtime = FIXED_TIME
    info.mode = 0o644
    info.uid = info.gid = 0
    with path.open("rb") as handle:
        tar.addfile(info, handle)


def archives(out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    bronze = ROOT / "data" / "bronze"
    for table in sorted(p.name for p in bronze.iterdir() if p.is_dir()):
        target = out / f"bronze-{table}.tar"
        with tarfile.open(target, "w", format=tarfile.PAX_FORMAT) as tar:
            _add_tree(tar, bronze, table)
        written.append(target)
    for name, build in (("locks.tar.gz", "locks"), ("config.tar.gz", "config")):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
            if build == "locks":
                _add_tree(tar, ROOT / "data", "locks")
            else:
                for f in ("labels.yaml", "filers.yaml"):
                    _add_file(tar, ROOT / "config" / f, f)
        target = out / name
        with target.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=FIXED_TIME) as gz:
            gz.write(buffer.getvalue())
        written.append(target)
    sums = out / "SHA256SUMS"
    sums.write_text(
        "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  ./{p.name}\n" for p in written),
        encoding="utf-8",
    )
    return [*written, sums]


def gh(*args: str) -> str:
    result = subprocess.run(["gh", *args], capture_output=True, check=False)
    if result.returncode != 0:
        raise SystemExit(f"publish: gh {' '.join(args[:3])} failed: {result.stderr.decode()[:400]}")
    return result.stdout.decode()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "cache" / "lake-release")
    args = parser.parse_args(argv)
    files = archives(args.out)
    total = sum(p.stat().st_size for p in files)
    tag = f"lake-{datetime.now(UTC):%Y%m%d}"
    print(f"publish: {len(files)} files, {total / 1e6:.1f} MB, tag {tag}")
    if args.dry_run:
        return 0
    main_sha = json.loads(gh("api", f"repos/{REPO}/git/ref/heads/main"))["object"]["sha"]
    release = json.loads(
        gh(
            "api",
            "-X",
            "POST",
            f"repos/{REPO}/releases",
            "-f",
            f"tag_name={tag}",
            "-f",
            f"target_commitish={main_sha}",
            "-f",
            f"name=lake {datetime.now(UTC):%Y-%m-%d}",
            "-f",
            "body=Bronze tables, the locks with the run ledger, and the status vocabulary, published by "
            "the build so the scheduled fetch has a lake to resume from. Every archive is listed with its "
            "SHA-256 in SHA256SUMS; every raw file the fetch read is listed with its digest in the locks.",
            "-f",
            "make_latest=false",
        )
    )
    upload = f"https://uploads.github.com/repos/{REPO}/releases/{release['id']}/assets"
    for path in files:
        gh(
            "api",
            "-X",
            "POST",
            f"{upload}?name={path.name}",
            "-H",
            "Content-Type: application/octet-stream",
            "--input",
            str(path),
        )
        print(f"publish: uploaded {path.name}", flush=True)
    print(f"publish: release {tag} is up")
    return 0


if __name__ == "__main__":
    sys.exit(main())
