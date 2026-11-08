"""The advisory files both engines read: OSV all.zip per ecosystem, and the GHSA repository.

OSV files land in data/cache/osv/<Ecosystem>/all.zip, the bucket path kept, with a sidecar that
records the URL, size, digest and the object generation and time the bucket reported. osv-scanner
reads the very same files offline (osv-scanner 2.7.0 looks for <dir>/osv-scalibr/<Ecosystem>/all.zip,
which osv_scanner_db_dir builds with links), so the two engines never disagree because they read
different days of data.

The GHSA repository is read from data/cache/ghsa/advisory-database in its own layout
(advisories/github-reviewed/YYYY/MM/GHSA-id/GHSA-id.json). In Actions the whole reviewed tree is
fetched; where only raw file access is available the reviewed records are fetched one by one at the
paths OSV's copies point to, and the sidecar says which of the two was done.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from unscheduled_match.ecosystems import Ecosystem

OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
GHSA_RAW = "https://raw.githubusercontent.com/github/advisory-database/main"


def osv_zip_path(cache_root: Path, eco: Ecosystem) -> Path:
    return cache_root / "osv" / eco.osv / "all.zip"


def sidecar(path: Path) -> Path:
    return path.with_name(path.name + ".json")


def read_sidecar(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(sidecar(path).read_text(encoding="utf-8"))
    return data


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_osv_zip(cache_root: Path, eco: Ecosystem, client: httpx.Client, *, refresh: bool = False) -> Path:
    """Download one ecosystem's all.zip unless the cached copy matches the bucket's generation."""
    target = osv_zip_path(cache_root, eco)
    url = f"{OSV_BUCKET}/{eco.osv}/all.zip"
    head = client.head(url)
    head.raise_for_status()
    generation = head.headers.get("x-goog-generation", "")
    if target.exists() and sidecar(target).exists() and not refresh:
        known = read_sidecar(target)
        if known.get("generation") == generation and target.stat().st_size == known.get("size"):
            return target
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".part")
    digest = hashlib.sha256()
    size = 0
    with client.stream("GET", url) as response, tmp.open("wb") as handle:
        response.raise_for_status()
        last_modified = response.headers.get("last-modified", "")
        generation = response.headers.get("x-goog-generation", generation)
        for block in response.iter_bytes(1 << 20):
            handle.write(block)
            digest.update(block)
            size += len(block)
    os.replace(tmp, target)
    record = {
        "url": url,
        "ecosystem": eco.osv,
        "size": size,
        "sha256": digest.hexdigest(),
        "generation": generation,
        "last_modified": last_modified,
        "fetched_at": _now(),
    }
    sidecar(target).write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    return target


def osv_scanner_db_dir(cache_root: Path, ecosystems: Iterable[Ecosystem], work: Path) -> Path:
    """A directory in osv-scanner's offline layout whose zips are links to the cached files."""
    base = work / "osv-scalibr"
    base.mkdir(parents=True, exist_ok=True)
    for eco in ecosystems:
        source = osv_zip_path(cache_root, eco).resolve()
        if not source.exists():
            raise FileNotFoundError(f"no cached OSV database for {eco.osv}: {source}")
        folder = base / eco.osv
        folder.mkdir(parents=True, exist_ok=True)
        link = folder / "all.zip"
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(source)
    return work


def ghsa_root(cache_root: Path) -> Path:
    return cache_root / "ghsa" / "advisory-database"


def ghsa_path(published: str, ghsa_id: str) -> str:
    """The repository path of a reviewed advisory, filed under the year and month it was published."""
    year, month = published[0:4], published[5:7]
    return f"advisories/github-reviewed/{year}/{month}/{ghsa_id}/{ghsa_id}.json"


def fetch_ghsa_records(
    cache_root: Path, wanted: Iterable[tuple[str, str]], client: httpx.Client
) -> dict[str, Any]:
    """Fetch reviewed GHSA records one by one by raw path, for the ids OSV's copies name.

    Used where the repository cannot be fetched whole. Records already on disk are kept. Returns the
    fetch summary written to the sidecar.
    """
    root = ghsa_root(cache_root)
    fetched = kept = missing = 0
    missing_ids: list[str] = []
    for ghsa_id, published in sorted(set(wanted)):
        rel = ghsa_path(published, ghsa_id)
        target = root / rel
        if target.exists():
            kept += 1
            continue
        response = client.get(f"{GHSA_RAW}/{rel}")
        if response.status_code == 404:
            missing += 1
            missing_ids.append(ghsa_id)
            continue
        response.raise_for_status()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(response.content)
        fetched += 1
    summary: dict[str, Any] = {
        "mode": "raw records located through OSV copies",
        "source": GHSA_RAW,
        "fetched": fetched,
        "kept": kept,
        "not_found": missing,
        "not_found_ids": missing_ids,
        "fetched_at": _now(),
    }
    root.mkdir(parents=True, exist_ok=True)
    (root.parent / "fetch.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    return summary


def mark_full_tree(cache_root: Path, source: str) -> dict[str, Any]:
    """Record that data/cache/ghsa holds the whole reviewed tree, as the exposure workflow fetches it."""
    root = ghsa_root(cache_root)
    reviewed = root / "advisories" / "github-reviewed"
    if not reviewed.exists():
        raise FileNotFoundError(f"no reviewed GHSA tree at {reviewed}")
    summary: dict[str, Any] = {
        "mode": "full reviewed tree",
        "source": source,
        "records": sum(1 for _ in reviewed.rglob("GHSA-*.json")),
        "fetched_at": _now(),
    }
    (root.parent / "fetch.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    return summary
