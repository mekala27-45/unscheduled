"""OSV records, read from OSV's all.zip files and from the GHSA repository, which uses the same format.

Only what matching, dating and reporting need is kept: ids and aliases, the three dates, the affected
packages with their ranges and enumerated versions, severity vectors, the summary and, for GHSA, the
reviewed flag and severity. A record that names none of the wanted packages is never built, so an
npm all.zip of a few hundred thousand records costs one JSON parse per record and little memory.
"""

from __future__ import annotations

import json
import zipfile
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from unscheduled_core.model import StrictModel

from unscheduled_match import ecosystems as eco_mod
from unscheduled_match.ranges import EVENT_KINDS, Event, EventKind


class OsvRange(StrictModel):
    type: str
    events: tuple[tuple[str, str], ...]  # (kind, value) in the order the record lists them
    repo: str | None = None

    def as_events(self) -> list[Event]:
        return [Event(cast(EventKind, kind), value) for kind, value in self.events]


class OsvAffected(StrictModel):
    ecosystem: str
    name: str
    purl: str | None = None
    ranges: tuple[OsvRange, ...] = ()
    versions: tuple[str, ...] = ()


class Severity(StrictModel):
    type: str
    score: str


class Advisory(StrictModel):
    id: str
    source: str  # osv (from an all.zip) or ghsa (from the GHSA repository)
    aliases: tuple[str, ...] = ()
    upstream: tuple[str, ...] = ()
    published: datetime | None = None
    modified: datetime
    withdrawn: datetime | None = None
    summary: str = ""
    details_head: str = ""
    severity: tuple[Severity, ...] = ()
    affected: tuple[OsvAffected, ...] = ()
    ghsa_severity: str | None = None
    github_reviewed: bool | None = None

    @property
    def cve_aliases(self) -> tuple[str, ...]:
        ids = [self.id, *self.aliases]
        return tuple(sorted({i for i in ids if i.startswith("CVE-")}))

    @property
    def all_ids(self) -> tuple[str, ...]:
        return tuple(sorted({self.id, *self.aliases}))


def parse_time(text: str | None) -> datetime | None:
    if not text:
        return None
    value = text.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _events(raw: list[dict[str, Any]]) -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    for event in raw:
        for kind in EVENT_KINDS:
            if kind in event:
                out.append((kind, str(event[kind])))
    return tuple(out)


def _affected(raw: dict[str, Any]) -> OsvAffected | None:
    package = raw.get("package") or {}
    ecosystem, name = package.get("ecosystem"), package.get("name")
    if not ecosystem or not name:
        return None
    ranges = tuple(
        OsvRange(type=str(r.get("type", "")), events=_events(r.get("events") or []), repo=r.get("repo"))
        for r in raw.get("ranges") or []
    )
    return OsvAffected(
        ecosystem=str(ecosystem),
        name=str(name),
        purl=package.get("purl"),
        ranges=ranges,
        versions=tuple(str(v) for v in raw.get("versions") or []),
    )


def from_json(record: dict[str, Any], source: str) -> Advisory:
    modified = parse_time(record.get("modified"))
    if modified is None:
        raise ValueError(f"{record.get('id')}: an OSV record must carry modified")
    affected = tuple(a for a in (_affected(raw) for raw in record.get("affected") or []) if a)
    database = record.get("database_specific") or {}
    reviewed = database.get("github_reviewed")
    details = str(record.get("details") or "")
    return Advisory(
        id=str(record["id"]),
        source=source,
        aliases=tuple(str(a) for a in record.get("aliases") or []),
        upstream=tuple(str(a) for a in record.get("upstream") or []),
        published=parse_time(record.get("published")),
        modified=modified,
        withdrawn=parse_time(record.get("withdrawn")),
        summary=str(record.get("summary") or ""),
        details_head=details[:500],
        severity=tuple(
            Severity(type=str(s.get("type", "")), score=str(s.get("score", "")))
            for s in record.get("severity") or []
        ),
        affected=affected,
        ghsa_severity=database.get("severity") if isinstance(database.get("severity"), str) else None,
        github_reviewed=reviewed if isinstance(reviewed, bool) else None,
    )


NameFilter = Callable[[str, str], bool]


def names_in(record: dict[str, Any]) -> Iterator[tuple[str, str]]:
    for raw in record.get("affected") or []:
        package = raw.get("package") or {}
        ecosystem, name = package.get("ecosystem"), package.get("name")
        if ecosystem and name:
            yield str(ecosystem), str(name)


def wanted_filter(keys: Iterable[tuple[str, str]]) -> NameFilter:
    """Accept a record when one of its packages is a wanted (base ecosystem, name)."""
    wanted: set[tuple[str, str]] = set()
    for ecosystem, name in keys:
        eco = eco_mod.lookup_osv(ecosystem)
        if eco is not None:
            wanted.add((eco.osv, eco_mod.normalize_name(eco, name)))

    def accept(ecosystem: str, name: str) -> bool:
        eco = eco_mod.lookup_osv(ecosystem)
        return eco is not None and (eco.osv, eco_mod.normalize_name(eco, name)) in wanted

    return accept


def read_zip(path: Path, accept: NameFilter | None = None) -> Iterator[Advisory]:
    """Every record of one all.zip that names an accepted package."""
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if not info.filename.endswith(".json"):
                continue
            record = json.loads(archive.read(info))
            if accept is not None and not any(accept(e, n) for e, n in names_in(record)):
                continue
            yield from_json(record, "osv")


def read_ghsa_tree(root: Path, accept: NameFilter | None = None) -> Iterator[Advisory]:
    """Every reviewed record under advisories/github-reviewed in a copy of the GHSA repository."""
    base = root / "advisories" / "github-reviewed"
    if not base.exists():
        return
    for path in sorted(base.rglob("GHSA-*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if accept is not None and not any(accept(e, n) for e, n in names_in(record)):
            continue
        yield from_json(record, "ghsa")
