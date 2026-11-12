"""The CVE List V5: the newest daily baseline from the CVEProject/cvelistV5 releases, and every
hourly delta after it.

The release tags are read with git ls-remote (the tags are cve_YYYY-MM-DD_HHMMZ), so the fetch needs
no API token. The baseline (YYYY-MM-DD_all_CVEs_at_midnight.zip.zip) is a zip holding cves.zip; it
is streamed to disk, the inner zip is taken out and read member by member, never unpacked. Each
hourly delta holds every record changed since that midnight, so each is a dated snapshot of those
records; records are keyed by their digest, so a record unchanged since an earlier snapshot adds
nothing and snapshot_at is the first snapshot that showed that exact record.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import polars as pl
from unscheduled_core.hashing import canonical_json, sha256_text

from unscheduled_sources.base import Fetcher, Output, RawFile, Unit
from unscheduled_sources.contract import frame
from unscheduled_sources.timeutil import parse_ts

TAG = re.compile(r"refs/tags/cve_(\d{4}-\d{2}-\d{2})_(\d{4})Z$")
RECORD = re.compile(r"(CVE-\d{4}-\d{4,})\.json$")
CWE = re.compile(r"\bCWE-\d+\b")
CVSS_KEYS = (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0"))
PLACEHOLDER_VERSIONS = frozenset({"", "n/a", "na", "unspecified", "unknown", "*", "-", "x"})
CHUNK = 20_000


def release_tags(git_url: str, timeout_s: float = 120.0) -> list[tuple[str, str]]:
    """(day, HHMM) for every hourly release tag, oldest first."""
    out = subprocess.run(
        ["git", "ls-remote", "--tags", git_url],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    ).stdout
    tags = sorted({(m[1], m[2]) for line in out.splitlines() if (m := TAG.search(line.split("\t")[-1]))})
    return tags


def english(entries: Iterable[dict[str, Any]] | None) -> str | None:
    items = [e for e in entries or [] if isinstance(e, dict) and e.get("value")]
    for e in items:
        if str(e.get("lang", "")).lower().startswith("en"):
            return str(e["value"])
    return str(items[0]["value"]) if items else None


def cwes(problem_types: Iterable[dict[str, Any]] | None) -> list[str]:
    found: list[str] = []
    for pt in problem_types or []:
        for d in pt.get("descriptions") or []:
            value = d.get("cweId")
            if not value and d.get("type") == "CWE":
                match = CWE.search(str(d.get("description") or ""))
                value = match.group(0) if match else None
            if value and value not in found:
                found.append(str(value))
    return found


def has_versions(affected: Iterable[dict[str, Any]] | None) -> bool:
    """True when some affected entry names a version or a range, not only a placeholder."""
    for a in affected or []:
        for v in a.get("versions") or []:
            if not isinstance(v, dict):
                continue
            if v.get("lessThan") or v.get("lessThanOrEqual") or v.get("changes"):
                return True
            if str(v.get("version") or "").strip().lower() not in PLACEHOLDER_VERSIONS:
                return True
    return False


def _metrics(
    cve_id: str, container: dict[str, Any], source: str | None, kind: str, observed: datetime
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for m in container.get("metrics") or []:
        for key, version in CVSS_KEYS:
            data = m.get(key)
            if not isinstance(data, dict):
                continue
            score = data.get("baseScore")
            rows.append(
                {
                    "cve_id": cve_id,
                    "source": source,
                    "source_type": kind,
                    "version": str(data.get("version") or version),
                    "vector": data.get("vectorString"),
                    "base_score": float(score) if score is not None else None,
                    "base_severity": data.get("baseSeverity"),
                    "origin": "cvelist",
                    "observed_at": observed,
                }
            )
    return rows


def parse_record(
    record: dict[str, Any], snapshot_at: datetime
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    meta = record.get("cveMetadata") or {}
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    adps = [a for a in containers.get("adp") or [] if isinstance(a, dict)]
    cve_id = str(meta["cveId"])
    filer = (cna.get("providerMetadata") or {}).get("shortName") or meta.get("assignerShortName")
    affected = cna.get("affected")
    row = {
        "cve_id": cve_id,
        "state": meta.get("state"),
        "assigner_org_id": meta.get("assignerOrgId"),
        "assigner_short_name": meta.get("assignerShortName"),
        "date_reserved": parse_ts(meta.get("dateReserved")),
        "date_published": parse_ts(meta.get("datePublished")),
        "date_updated": parse_ts(meta.get("dateUpdated")),
        "description": english(cna.get("descriptions")) or english(cna.get("rejectedReasons")),
        "problem_cwes": cwes(cna.get("problemTypes")),
        "affected_json": canonical_json(affected) if affected is not None else None,
        "has_affected_versions": has_versions(affected),
        "references_count": len(cna.get("references") or []),
        "adp_cisa_present": any(
            (a.get("providerMetadata") or {}).get("shortName") == "CISA-ADP" for a in adps
        ),
        "snapshot_at": snapshot_at,
        "record_digest": sha256_text(canonical_json(record)),
    }
    metrics = _metrics(cve_id, cna, filer, "cna", snapshot_at)
    weaknesses = [
        {"cve_id": cve_id, "source": filer, "cwe_id": c, "origin": "cvelist", "observed_at": snapshot_at}
        for c in cwes(cna.get("problemTypes"))
    ]
    for adp in adps:
        provider = (adp.get("providerMetadata") or {}).get("shortName")
        metrics.extend(_metrics(cve_id, adp, provider, "adp", snapshot_at))
        weaknesses.extend(
            {
                "cve_id": cve_id,
                "source": provider,
                "cwe_id": c,
                "origin": "cvelist",
                "observed_at": snapshot_at,
            }
            for c in cwes(adp.get("problemTypes"))
        )
    return row, metrics, weaknesses


def iter_records(archive: zipfile.ZipFile) -> Iterator[tuple[str, bytes]]:
    for info in archive.infolist():
        if info.is_dir() or not RECORD.search(info.filename):
            continue
        yield info.filename, archive.read(info)


def frames_from_zip(
    path: Path, snapshot_at: datetime, chunk: int = CHUNK
) -> Iterator[tuple[str, pl.DataFrame, int, int]]:
    """Frames of the three tables, chunk by chunk, with the records read and those that failed."""
    import json

    records: list[dict[str, Any]] = []
    metrics: list[dict[str, Any]] = []
    weaknesses: list[dict[str, Any]] = []
    unreadable = 0
    with zipfile.ZipFile(path) as archive:
        for _, data in iter_records(archive):
            try:
                rec, met, weak = parse_record(json.loads(data), snapshot_at)
            except (ValueError, KeyError, TypeError):
                unreadable += 1
                continue
            records.append(rec)
            metrics.extend(met)
            weaknesses.extend(weak)
            if len(records) >= chunk:
                yield from _flush(records, metrics, weaknesses, unreadable)
                records, metrics, weaknesses = [], [], []
    yield from _flush(records, metrics, weaknesses, unreadable)


def _flush(
    records: list[dict[str, Any]],
    metrics: list[dict[str, Any]],
    weaknesses: list[dict[str, Any]],
    unreadable: int,
) -> Iterator[tuple[str, pl.DataFrame, int, int]]:
    yield "cve_records", frame("cve_records", records), len(records), unreadable
    yield "cve_metrics", frame("cve_metrics", metrics), 0, 0
    yield "cve_weaknesses", frame("cve_weaknesses", weaknesses), 0, 0


class CveList(Fetcher):
    source = "cvelist"
    tables: ClassVar[tuple[str, ...]] = ("cve_records", "cve_metrics", "cve_weaknesses")

    def units(self) -> Iterator[Unit]:
        tags = release_tags(self.cfg["git"])
        if not tags:
            raise RuntimeError("the cvelistV5 repository lists no release tags")
        day = tags[-1][0]
        hours = sorted(h for d, h in tags if d == day)
        yield Unit(f"baseline-{day}", f"baseline {day}", {"day": day, "hour": "0000", "kind": "baseline"})
        for h in hours:
            if h == "0000":
                continue
            yield Unit(f"delta-{day}-{h}Z", f"delta {day} {h}Z", {"day": day, "hour": h, "kind": "delta"})

    def fetch(self, unit: Unit) -> list[RawFile]:
        day, hour = unit.meta["day"], unit.meta["hour"]
        tag = self.cfg["tag"].format(day=day, hour="0000" if unit.meta["kind"] == "baseline" else hour)
        asset_key = "baseline_asset" if unit.meta["kind"] == "baseline" else "delta_asset"
        asset = self.cfg[asset_key].format(day=day, hour=hour)
        url = f"{self.cfg['release_download']}/{tag}/{asset}"
        dest = self.raw_root / unit.name / asset
        with self.ctx.http_factory(attempts=5) as http:
            got = http.download(url, dest)
        self.ctx.log(f"cvelist {unit.window}: {got.size} bytes")
        return [
            RawFile(
                unit.name,
                asset,
                url,
                dest,
                got.sha256,
                got.size,
                got.fetched_at,
                pinned=True,
                meta={"fetched": True},
            )
        ]

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        for raw in raws:
            snapshot_at = snapshot_time(raw.unit)
            path = raw.path
            inner: Path | None = None
            if raw.file.endswith(".zip.zip"):
                inner = raw.path.with_name("cves.zip")
                with zipfile.ZipFile(raw.path) as outer:
                    member = next(i for i in outer.infolist() if i.filename.endswith(".zip"))
                    with outer.open(member) as src, inner.open("wb") as dst:
                        shutil.copyfileobj(src, dst, 1 << 20)
                if raw.meta.get("fetched") and not self.ctx.keep_raw:
                    # The outer file is locked by its digest already; only the inner zip is read.
                    raw.path.unlink(missing_ok=True)
                path = inner
            read = 0
            unreadable = 0
            try:
                for name, df, n, bad in frames_from_zip(path, snapshot_at):
                    read += n
                    unreadable = max(unreadable, bad)
                    yield name, df
            finally:
                if inner is not None:
                    inner.unlink(missing_ok=True)
            raw.rows = read
            if unreadable:
                raw.meta["note"] = f"unreadable records {unreadable}"
            self.ctx.log(
                f"cvelist {raw.unit}: {read} records" + (f", {unreadable} unreadable" if unreadable else "")
            )


def snapshot_time(unit: str) -> datetime:
    """baseline-YYYY-MM-DD is that midnight; delta-YYYY-MM-DD-HHMMZ is that hour, in UTC."""
    m = re.match(r"^(baseline|delta)-(\d{4}-\d{2}-\d{2})(?:-(\d{2})(\d{2})Z)?$", unit)
    if not m:
        raise ValueError(f"not a cvelist unit: {unit}")
    day = datetime.strptime(m[2], "%Y-%m-%d").replace(tzinfo=UTC)
    if m[1] == "delta" and m[3] is not None:
        return day.replace(hour=int(m[3]), minute=int(m[4]))
    return day
