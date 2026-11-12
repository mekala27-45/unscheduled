"""Publish the serving bundle as a GitHub release the API pulls from (ADR 0007).

    python scripts/publish_serving.py            # data/serving/ to a new serving-<stamp> release
    python scripts/publish_serving.py --dry-run  # check the bundle and print what would be sent
    python scripts/publish_serving.py --lake     # then the lake file it was built from, to that release

Uses only the GitHub REST API through the gh command line, which reads its own credential; this
script never sees a token. The bundle manifest lists every file with its sha256, and the release is
refused when a file on disk does not match the manifest, so the API can trust what it downloads by
digest alone. The release it made is recorded in data/serving/published.json; with --lake the lake
file the bundle was built from goes up to that release as lake-<first twelve of its sha256>.duckdb,
after the API has loaded the bundle, so a slow upload never holds the data back.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "mekala27-45/unscheduled"
BUNDLE = ROOT / "data" / "serving"
PUBLISHED = BUNDLE / "published.json"
LAKE_FILE = ROOT / "data" / "lake" / "unscheduled.duckdb"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(bundle: Path) -> list[Path]:
    manifest_path = bundle / "bundle_manifest.json"
    if not manifest_path.exists():
        raise SystemExit("publish: data/serving/bundle_manifest.json does not exist; build the bundle first")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files: list[Path] = []
    for entry in manifest["files"]:
        path = bundle / entry["file"]
        if not path.exists():
            raise SystemExit(f"publish: {entry['file']} is listed but missing")
        if sha256(path) != entry["sha256"]:
            raise SystemExit(f"publish: {entry['file']} does not match its digest in the manifest")
        files.append(path)
    return [*files, manifest_path]


def gh(*args: str, data: bytes | None = None) -> str:
    result = subprocess.run(["gh", *args], input=data, capture_output=True, check=False)
    if result.returncode != 0:
        raise SystemExit(f"publish: gh {' '.join(args[:3])} failed: {result.stderr.decode()[:400]}")
    return result.stdout.decode()


def upload(release_id: int, path: Path, name: str) -> None:
    gh(
        "api",
        "-X",
        "POST",
        f"https://uploads.github.com/repos/{REPO}/releases/{release_id}/assets?name={name}",
        "-H",
        "Content-Type: application/octet-stream",
        "--input",
        str(path),
    )


def publish_lake() -> int:
    """The lake file beside the bundle it fed, in the release this script made last."""
    if not PUBLISHED.exists():
        raise SystemExit("publish: data/serving/published.json does not exist; publish the bundle first")
    if not LAKE_FILE.exists():
        raise SystemExit("publish: data/lake/unscheduled.duckdb does not exist; build the lake first")
    release = json.loads(PUBLISHED.read_text(encoding="utf-8"))
    name = f"lake-{sha256(LAKE_FILE)[:12]}.duckdb"
    upload(int(release["id"]), LAKE_FILE, name)
    print(f"publish: uploaded {name} to {release['tag']}")
    return 0


def main(dry_run: bool) -> int:
    files = verify(BUNDLE)
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M")
    tag = f"serving-{stamp}"
    total = sum(p.stat().st_size for p in files)
    print(f"publish: {len(files)} files, {total / 1e6:.1f} MB, tag {tag}")
    if dry_run:
        return 0
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True)
    release = json.loads(
        gh(
            "api",
            "-X",
            "POST",
            f"repos/{REPO}/releases",
            "-f",
            f"tag_name={tag}",
            "-f",
            f"target_commitish={head.stdout.strip()}",
            "-f",
            f"name=Serving bundle {stamp}",
            "-f",
            "body=The data the API loads into Neon, checked by digest. Built from the lake; see bundle_manifest.json.",
            "-F",
            "prerelease=true",
        )
    )
    for path in files:
        upload(int(release["id"]), path, path.name)
        print(f"publish: uploaded {path.name}")
    PUBLISHED.write_text(json.dumps({"tag": tag, "id": release["id"]}, indent=1) + "\n", encoding="utf-8")
    print(f"publish: release {tag} is up")
    return 0


if __name__ == "__main__":
    sys.exit(publish_lake() if "--lake" in sys.argv else main("--dry-run" in sys.argv))
