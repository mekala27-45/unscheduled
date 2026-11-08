"""The advisories the matcher knows, by id and by package, and which version of each held at a time T.

One advisory id can arrive more than once: from OSV's all.zip, from the GHSA repository, and, when the
lake has built it, from silver advisory_versions with every version the history shows. At a time T the
version used is the newest one whose `modified` is at or before T (exact). When every copy on hand
was modified after T but the advisory was published before T, the oldest copy on hand stands in for
the version of that day and the finding says so: known_from is the publication time and the rule is
`published`. An advisory withdrawn at or before T matches nothing at T.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from unscheduled_core.model import StrictModel

from unscheduled_match import cache
from unscheduled_match import ecosystems as eco_mod
from unscheduled_match.ecosystems import Ecosystem
from unscheduled_match.osv import Advisory, read_ghsa_tree, read_zip, wanted_filter

# A copy from OSV carries the versions OSV enumerated for ECOSYSTEM ranges, so it wins a tie.
SOURCE_RANK = {"osv": 0, "ghsa": 1}


class KnownVersion(StrictModel):
    advisory: Advisory
    known_from: datetime
    rule: str  # modified: exact at T; published: the copy on hand stands in for the version at T
    sources: tuple[str, ...]  # every source that holds a copy of this id


class LoadStats(StrictModel):
    osv_records: dict[str, int]
    ghsa_records: int
    ghsa_mode: str


class AdvisoryStore:
    def __init__(self) -> None:
        self._copies: dict[str, list[Advisory]] = defaultdict(list)
        self._by_package: dict[tuple[str, str], set[str]] = defaultdict(set)

    def add(self, advisory: Advisory) -> None:
        self._copies[advisory.id].append(advisory)
        for affected in advisory.affected:
            eco = eco_mod.lookup_osv(affected.ecosystem)
            if eco is not None:
                self._by_package[(eco.osv, eco_mod.normalize_name(eco, affected.name))].add(advisory.id)

    def __len__(self) -> int:
        return len(self._copies)

    def ids(self) -> list[str]:
        return sorted(self._copies)

    def copies(self, advisory_id: str) -> list[Advisory]:
        return list(self._copies.get(advisory_id, []))

    def ids_for(self, eco: Ecosystem, name: str) -> set[str]:
        return set(self._by_package.get((eco.osv, eco_mod.normalize_name(eco, name)), set()))

    def at(self, advisory_id: str, t: datetime) -> KnownVersion | None:
        copies = self._copies.get(advisory_id)
        if not copies:
            return None
        sources = tuple(sorted({c.source for c in copies}))
        known = [c for c in copies if c.modified <= t]
        if known:
            chosen = max(known, key=lambda c: (c.modified, -SOURCE_RANK.get(c.source, 9)))
            version = KnownVersion(
                advisory=chosen, known_from=chosen.modified, rule="modified", sources=sources
            )
        else:
            published = [c for c in copies if c.published is not None and c.published <= t]
            if not published:
                return None
            chosen = min(published, key=lambda c: (c.modified, SOURCE_RANK.get(c.source, 9)))
            assert chosen.published is not None
            version = KnownVersion(
                advisory=chosen, known_from=chosen.published, rule="published", sources=sources
            )
        if version.advisory.withdrawn is not None and version.advisory.withdrawn <= t:
            return None
        return version


def load(
    cache_root: Path,
    ecosystems: Iterable[Ecosystem],
    wanted: Iterable[tuple[str, str]] | None = None,
    *,
    ghsa_mode: str = "not read",
) -> tuple[AdvisoryStore, LoadStats]:
    """Read the cached OSV zips and the GHSA tree, keeping the records that name a wanted package."""
    accept = wanted_filter(wanted) if wanted is not None else None
    store = AdvisoryStore()
    per_zip: dict[str, int] = {}
    for eco in ecosystems:
        path = cache.osv_zip_path(cache_root, eco)
        count = 0
        for advisory in read_zip(path, accept):
            store.add(advisory)
            count += 1
        per_zip[eco.osv] = count
    ghsa = 0
    for advisory in read_ghsa_tree(cache.ghsa_root(cache_root), accept):
        store.add(advisory)
        ghsa += 1
    return store, LoadStats(osv_records=per_zip, ghsa_records=ghsa, ghsa_mode=ghsa_mode)
