"""Findings: one per component and advisory, as of a time T.

A component is a distinct package URL in one product's SBOM. For each advisory that names its
package and is known at T (store.AdvisoryStore.at), every affected entry for that package is checked:
the enumerated versions by exact string, then each SEMVER and ECOSYSTEM range by the OSV walk in the
ecosystem's scheme. GIT ranges are skipped and counted; a range whose events do not parse is skipped
and quarantined under Q06. Advisories that alias each other (the same vulnerability in two databases,
GHSA-x and GO-y, say) are grouped into one finding that lists every id.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import datetime

from univers.versions import Version
from unscheduled_core.model import StrictModel

from unscheduled_match import ecosystems as eco_mod
from unscheduled_match import ranges as rng
from unscheduled_match.ecosystems import Ecosystem
from unscheduled_match.osv import Advisory, OsvAffected, Severity
from unscheduled_match.purl import PackageKey, canonical
from unscheduled_match.sbom import Component, Quarantined
from unscheduled_match.store import AdvisoryStore, KnownVersion

ID_PREFERENCE = ("GHSA-", "GO-", "RUSTSEC-", "PYSEC-", "DSA-", "DLA-", "DEBIAN-", "MAL-")
Q06 = "Q06"


class AdvisoryMatch(StrictModel):
    advisory_id: str
    source: str
    sources: tuple[str, ...]
    via: str  # versions: the exact version is enumerated; range: a SEMVER or ECOSYSTEM range holds it
    range_type: str | None = None
    matched_range: str | None = None
    fixed: tuple[str, ...] = ()
    fixed_known: bool = True  # False when the copy used was modified after T: its fixes may be later
    modified: datetime
    published: datetime | None = None
    known_from: datetime
    known_from_rule: str


class Finding(StrictModel):
    product: str
    component: str
    purl: str
    ecosystem: str
    package: str
    binary_package: str | None = None
    version: str
    primary_id: str
    advisory_ids: tuple[str, ...]
    cve_aliases: tuple[str, ...]
    upstream_cves: tuple[str, ...] = ()
    matches: tuple[AdvisoryMatch, ...]
    fixed_versions: tuple[str, ...]
    fix_available: bool | None  # None: every advisory used is dated by rule, so a fix at T is unknown
    severity: tuple[Severity, ...] = ()
    summary: str = ""
    known_from: datetime
    known_from_rule: str
    as_of: datetime

    @property
    def cves(self) -> tuple[str, ...]:
        return tuple(sorted({*self.cve_aliases, *self.upstream_cves}))


class RangeQuarantine(StrictModel):
    rule: str
    advisory_id: str
    ecosystem: str
    package: str
    range_type: str
    error: str


class MatchStats(StrictModel):
    components: int  # distinct package URLs
    keyed: int  # of those, the ones in one of the six ecosystems, with a version
    unsupported: int
    unparseable_versions: int
    advisories_considered: int  # (component, advisory) pairs known at T for the component's package
    git_ranges_skipped: int
    git_only_advisories: int
    unparseable_ranges: int
    findings: int
    quarantined_q07: int


class MatchResult(StrictModel):
    product: str
    as_of: datetime
    findings: tuple[Finding, ...]
    stats: MatchStats
    range_quarantine: tuple[RangeQuarantine, ...]
    quarantined: tuple[Quarantined, ...]
    unparseable_versions: tuple[str, ...]  # purls whose version does not parse in its scheme


def same_package(affected: OsvAffected, key: PackageKey, eco: Ecosystem) -> bool:
    if eco is eco_mod.DEBIAN:
        if affected.ecosystem != key.ecosystem:
            return False
    elif eco_mod.base_osv_ecosystem(affected.ecosystem) != eco.osv:
        return False
    return eco_mod.normalize_name(eco, affected.name) == eco_mod.normalize_name(eco, key.name)


def _preference(advisory_id: str) -> tuple[int, str]:
    for rank, prefix in enumerate(ID_PREFERENCE):
        if advisory_id.startswith(prefix):
            return rank, advisory_id
    return len(ID_PREFERENCE), advisory_id


def group_by_alias(advisories: Sequence[Advisory]) -> list[list[Advisory]]:
    """Union-find over each advisory's id and aliases: aliases are symmetric and transitive."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    for advisory in advisories:
        for alias in advisory.aliases:
            union(advisory.id, alias)
        find(advisory.id)
    groups: dict[str, list[Advisory]] = {}
    for advisory in advisories:
        groups.setdefault(find(advisory.id), []).append(advisory)
    return [sorted(g, key=lambda a: a.id) for _, g in sorted(groups.items())]


class _Tally:
    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.quarantine: list[RangeQuarantine] = []
        self.unparseable: set[str] = set()


def _match_advisory(
    known: KnownVersion,
    key: PackageKey,
    eco: Ecosystem,
    purl: str,
    tally: _Tally,
) -> AdvisoryMatch | None:
    advisory = known.advisory
    hit: AdvisoryMatch | None = None
    saw_numbered = saw_git = False
    for affected in advisory.affected:
        if not same_package(affected, key, eco):
            continue
        if key.version in affected.versions or (eco is eco_mod.GO and f"v{key.version}" in affected.versions):
            hit = hit or _advisory_match(known, "versions", None, None, ())
        for osv_range in affected.ranges:
            if osv_range.type == "GIT":
                tally.counts["git_ranges_skipped"] += 1
                saw_git = True
                continue
            if osv_range.type not in ("SEMVER", "ECOSYSTEM"):
                continue
            saw_numbered = True
            cls = rng.version_class(eco, osv_range.type)
            try:
                version: Version = rng.parse_version(cls, key.version)
            except rng.RangeParseError:
                tally.unparseable.add(purl)
                continue
            events = osv_range.as_events()
            try:
                parsed = rng.parse_events(events, cls)
            except rng.RangeParseError as err:
                tally.quarantine.append(
                    RangeQuarantine(
                        rule=Q06,
                        advisory_id=advisory.id,
                        ecosystem=affected.ecosystem,
                        package=affected.name,
                        range_type=osv_range.type,
                        error=str(err),
                    )
                )
                continue
            if rng.is_affected(version, parsed):
                fixed = tuple(
                    e.text
                    for e in parsed
                    if e.kind == "fixed" and e.version is not None and rng.compare(e.version, version) > 0
                )
                candidate = _advisory_match(known, "range", osv_range.type, rng.to_vers(eco, parsed), fixed)
                if hit is None or hit.via == "versions":
                    hit = candidate
    if saw_git and not saw_numbered:
        tally.counts["git_only_advisories"] += 1
    return hit


def _advisory_match(
    known: KnownVersion, via: str, range_type: str | None, vers: str | None, fixed: tuple[str, ...]
) -> AdvisoryMatch:
    """One advisory's match. A copy modified after T says nothing about the fixes known at T."""
    advisory = known.advisory
    exact = known.rule == "modified"
    return AdvisoryMatch(
        advisory_id=advisory.id,
        source=advisory.source,
        sources=known.sources,
        via=via,
        range_type=range_type,
        matched_range=vers,
        fixed=fixed if exact else (),
        fixed_known=exact,
        modified=advisory.modified,
        published=advisory.published,
        known_from=known.known_from,
        known_from_rule=known.rule,
    )


def _summary(group: Sequence[Advisory]) -> str:
    for advisory in sorted(group, key=lambda a: _preference(a.id)):
        if advisory.summary:
            return advisory.summary
    for advisory in group:
        if advisory.details_head:
            return advisory.details_head.splitlines()[0]
    return ""


def dedupe(components: Iterable[Component]) -> list[Component]:
    """One component per canonical package URL; Syft lists a package once per place it was found."""
    seen: dict[str, Component] = {}
    for component in components:
        if not component.purl:
            continue
        try:
            key = canonical(component.purl)
        except ValueError:
            key = component.purl
        seen.setdefault(key, component)
    return [seen[k] for k in sorted(seen)]


def match(
    product: str,
    components: Iterable[Component],
    store: AdvisoryStore,
    as_of: datetime,
    quarantined: Sequence[Quarantined] = (),
) -> MatchResult:
    tally = _Tally()
    findings: list[Finding] = []
    distinct = dedupe(components)
    keyed = 0
    for component in distinct:
        key = component.key()
        eco = eco_mod.lookup_osv(key.ecosystem) if key else None
        if key is None or eco is None or component.purl is None:
            tally.counts["unsupported"] += 1
            continue
        keyed += 1
        matched: list[tuple[Advisory, AdvisoryMatch]] = []
        for advisory_id in sorted(store.ids_for(eco, key.name)):
            known = store.at(advisory_id, as_of)
            if known is None:
                continue
            tally.counts["advisories_considered"] += 1
            hit = _match_advisory(known, key, eco, component.purl, tally)
            if hit is not None:
                matched.append((known.advisory, hit))
        by_id = {a.id: (a, m) for a, m in matched}
        for group in group_by_alias([a for a, _ in matched]):
            matches = tuple(by_id[a.id][1] for a in group)
            first = min(matches, key=lambda m: (m.known_from, m.advisory_id))
            ids = tuple(a.id for a in group)
            fixed = tuple(sorted({f for m in matches for f in m.fixed}))
            fix_known = any(m.fixed_known for m in matches)
            # Severity, like fixes, is only taken from a copy that was current at T.
            exact_ids = {m.advisory_id for m in matches if m.fixed_known}
            severity = {(s.type, s.score): s for a in group if a.id in exact_ids for s in a.severity}
            findings.append(
                Finding(
                    product=product,
                    component=component.bom_ref,
                    purl=component.purl,
                    ecosystem=key.ecosystem,
                    package=key.name,
                    binary_package=key.binary_name,
                    version=key.version,
                    primary_id=min(ids, key=_preference),
                    advisory_ids=ids,
                    cve_aliases=tuple(sorted({c for a in group for c in a.cve_aliases})),
                    upstream_cves=tuple(
                        sorted({u for a in group for u in a.upstream if u.startswith("CVE-")})
                    ),
                    matches=matches,
                    fixed_versions=fixed,
                    fix_available=bool(fixed) if fix_known else None,
                    severity=tuple(severity[k] for k in sorted(severity)),
                    summary=_summary(group),
                    known_from=first.known_from,
                    known_from_rule=first.known_from_rule,
                    as_of=as_of,
                )
            )
    findings.sort(key=lambda f: (f.package, f.version, f.purl, f.primary_id))
    stats = MatchStats(
        components=len(distinct),
        keyed=keyed,
        unsupported=tally.counts["unsupported"],
        unparseable_versions=len(tally.unparseable),
        advisories_considered=tally.counts["advisories_considered"],
        git_ranges_skipped=tally.counts["git_ranges_skipped"],
        git_only_advisories=tally.counts["git_only_advisories"],
        unparseable_ranges=len(tally.quarantine),
        findings=len(findings),
        quarantined_q07=len(quarantined),
    )
    return MatchResult(
        product=product,
        as_of=as_of,
        findings=tuple(findings),
        stats=stats,
        range_quarantine=tuple(tally.quarantine),
        quarantined=tuple(quarantined),
        unparseable_versions=tuple(sorted(tally.unparseable)),
    )
