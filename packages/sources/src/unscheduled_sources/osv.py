"""OSV: the all.zip of each ecosystem from the public OSV bucket.

One unit per ecosystem per day. The zip is read member by member and never unpacked. Each record
keeps its id, aliases, the three dates, the summary, its severity and affected blocks as canonical
JSON, and source_db, the database prefix of the id (GHSA, PYSEC, GO, RUSTSEC, MAL, DSA, DLA and so
on), which the OSV schema defines as the publisher of the record and so names the licence that
applies to it. Advisories are keyed by id, ecosystem and modified, so each new version of an
advisory is a new row and an unchanged one adds nothing.
"""

from __future__ import annotations

import json
import zipfile
from collections import Counter
from collections.abc import Iterator
from typing import Any, ClassVar

from unscheduled_core.hashing import canonical_json

from unscheduled_sources.base import Fetcher, Output, RawFile, Unit
from unscheduled_sources.contract import frame
from unscheduled_sources.timeutil import parse_ts

CHUNK = 50_000


def source_db(advisory_id: str) -> str:
    return advisory_id.split("-", 1)[0] if "-" in advisory_id else advisory_id


def advisory_row(record: dict[str, Any], ecosystem: str) -> dict[str, Any]:
    advisory_id = str(record["id"])
    severity = record.get("severity")
    affected = record.get("affected")
    return {
        "id": advisory_id,
        "ecosystem": ecosystem,
        "aliases": [str(a) for a in record.get("aliases") or []],
        "published": parse_ts(record.get("published")),
        "modified": parse_ts(record.get("modified")),
        "withdrawn": parse_ts(record.get("withdrawn")),
        "summary": record.get("summary"),
        "severity_json": canonical_json(severity) if severity else None,
        "affected_json": canonical_json(affected) if affected is not None else None,
        "source_db": source_db(advisory_id),
    }


class Osv(Fetcher):
    source = "osv"
    tables: ClassVar[tuple[str, ...]] = ("osv_advisories",)

    def units(self) -> Iterator[Unit]:
        day = self.ctx.today.isoformat()
        for eco in self.cfg["ecosystems"]:
            safe = str(eco).replace(".", "-")
            yield Unit(f"{safe}-{day}", f"{eco} {day}", {"ecosystem": eco})

    def fetch(self, unit: Unit) -> list[RawFile]:
        eco = unit.meta["ecosystem"]
        url = f"{self.cfg['bucket']}/{eco}/all.zip"
        with self.ctx.http_factory(attempts=5) as http:
            got = http.download(url, self.raw_root / unit.name / "all.zip")
        generation = got.headers.get("x-goog-generation")
        note = f"object generation {generation}" if generation else None
        self.ctx.log(f"osv {eco}: {got.size} bytes")
        meta = {"ecosystem": eco, **({"note": note} if note else {})}
        return [RawFile(unit.name, "all.zip", url, got.path, got.sha256, got.size, got.fetched_at, meta=meta)]

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        for raw in raws:
            eco = raw.meta.get("ecosystem") or ecosystem_of(raw.unit, self.cfg["ecosystems"])
            rows: list[dict[str, Any]] = []
            prefixes: Counter[str] = Counter()
            read = 0
            unreadable = 0
            with zipfile.ZipFile(raw.path) as archive:
                for info in archive.infolist():
                    if info.is_dir() or not info.filename.endswith(".json"):
                        continue
                    try:
                        row = advisory_row(json.loads(archive.read(info)), eco)
                    except (ValueError, KeyError, TypeError):
                        unreadable += 1
                        continue
                    prefixes[row["source_db"]] += 1
                    rows.append(row)
                    read += 1
                    if len(rows) >= CHUNK:
                        yield "osv_advisories", frame("osv_advisories", rows)
                        rows = []
            yield "osv_advisories", frame("osv_advisories", rows)
            raw.rows = read
            top = ", ".join(f"{k} {v}" for k, v in prefixes.most_common())
            note = f"{eco}: {read} advisories by database: {top}"
            if unreadable:
                note += f"; unreadable {unreadable}"
            raw.meta["note"] = (raw.meta.get("note", "") + "; " if raw.meta.get("note") else "") + note
            self.ctx.log(f"osv {note}")


def ecosystem_of(unit: str, ecosystems: list[str]) -> str:
    for eco in ecosystems:
        if unit.startswith(str(eco).replace(".", "-") + "-"):
            return str(eco)
    raise ValueError(f"no ecosystem for the osv unit {unit}")
