"""Where the matcher and osv-scanner disagree, and why, one advisory on one package at a time.

Both engines read the same SBOM and the same OSV files, so a disagreement is a difference in how
they read a package or a range, never in the data. Each one gets the reasons the evidence supports,
from a fixed list. A disagreement with no reason is unexplained; the target is zero.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime

from unscheduled_core.model import StrictModel

from unscheduled_match import ecosystems as eco_mod
from unscheduled_match import purl as purl_mod
from unscheduled_match.matcher import Finding
from unscheduled_match.osvscanner import ScanResult, comparison_key
from unscheduled_match.sbom import Component
from unscheduled_match.store import AdvisoryStore

Key = tuple[str, str, str]

REASONS: dict[str, str] = {
    "release_qualifier": (
        "osv-scanner takes the release from the purl qualifier distro=debian-12.8 as the ecosystem "
        "Debian:12.8, which no OSV record names (Debian records name Debian:12); with only that "
        "qualifier rewritten to debian-12, osv-scanner reports this advisory too"
    ),
    "source_package": (
        "the Debian binary package is built from a source package of another name, which Syft "
        "records in the purl's upstream qualifier; Debian advisories name the source package, the "
        "matcher looks the source up and osv-scanner looks up the binary name"
    ),
    "placeholder_version": (
        "Syft could not resolve this version (pom.xml takes it from a parent BOM that is not read), "
        "wrote UNKNOWN as the component version and left the purl without one; osv-scanner compares "
        "the word UNKNOWN as a version, the matcher does not match a package with no version"
    ),
    "withdrawn": "the advisory is withdrawn; the matcher drops it, osv-scanner still reports it",
    "ghsa_copy_differs": (
        "the GHSA repository holds a newer version of this advisory than OSV's all.zip, and the two "
        "versions disagree on this package version"
    ),
    "version_scheme_edge": (
        "the version or a range bound does not parse in the ecosystem's scheme in univers, so the "
        "matcher skips the range (Q06) where osv-scanner's own parser reads it"
    ),
    "missing_purl": "the component has no package URL (Q07), so the matcher cannot key it",
}

_MINOR_RELEASE = re.compile(r"^Debian:\d+\.\d+")


class Disagreement(StrictModel):
    product: str
    ecosystem: str
    package: str
    version: str
    purl: str | None = None
    advisory_id: str
    reported_by: str  # matcher or osv-scanner
    reasons: tuple[str, ...]
    explained: bool
    evidence: dict[str, str]


class Comparison(StrictModel):
    product: str
    as_of: datetime
    packages_matcher: int
    packages_osv_scanner: int
    pairs_both: int  # (package, advisory id) pairs both engines report
    pairs_matcher_only: int
    pairs_osv_scanner_only: int
    disagreements: tuple[Disagreement, ...]
    unexplained: int
    package_differences: tuple[dict[str, str], ...]
    probe: dict[str, int] | None = None  # the release-normalized osv-scanner run, for Debian


def scanned_pairs(scan: ScanResult) -> dict[Key, set[str]]:
    out: dict[Key, set[str]] = {}
    for package in scan.packages:
        out.setdefault(comparison_key(package.ecosystem, package.name, package.version), set()).update(
            package.ids
        )
    return out


def scanned_ecosystems(scan: ScanResult) -> dict[Key, str]:
    return {comparison_key(p.ecosystem, p.name, p.version): p.ecosystem for p in scan.packages}


def matcher_pairs(components: Iterable[Component], findings: Sequence[Finding]) -> dict[Key, set[str]]:
    out: dict[Key, set[str]] = {}
    for component in components:
        if component.purl:
            key = purl_mod.component_key(component.purl)
            if key is not None:
                out.setdefault(key, set())
    for finding in findings:
        key = purl_mod.component_key(finding.purl)
        if key is not None:
            out.setdefault(key, set()).update(finding.advisory_ids)
    return out


def _components_by_key(components: Iterable[Component]) -> dict[Key, Component]:
    out: dict[Key, Component] = {}
    for component in components:
        if component.purl:
            key = purl_mod.component_key(component.purl)
            if key is not None:
                out.setdefault(key, component)
    return out


def _reasons_matcher_only(
    key: Key,
    advisory_id: str,
    component: Component | None,
    scanned_eco: str | None,
    probe: Mapping[Key, set[str]] | None,
    store: AdvisoryStore,
    as_of: datetime,
) -> tuple[list[str], dict[str, str]]:
    reasons: list[str] = []
    evidence: dict[str, str] = {}
    package_key = component.key() if component is not None else None
    if key[0] == eco_mod.DEBIAN.osv:
        minor = bool(scanned_eco and _MINOR_RELEASE.match(scanned_eco))
        if scanned_eco:
            evidence["osv_scanner_ecosystem"] = scanned_eco
        in_probe = probe is not None and advisory_id in probe.get(key, set())
        if probe is not None:
            evidence["release_normalized_run"] = "reports it" if in_probe else "does not report it"
        source_differs = package_key is not None and package_key.binary_name is not None
        if source_differs and package_key is not None:
            evidence["source_package"] = package_key.name
        if minor and in_probe:
            reasons.append("release_qualifier")
        elif source_differs and not in_probe:
            if minor:
                reasons.append("release_qualifier")
            reasons.append("source_package")
    known = store.at(advisory_id, as_of)
    if known is not None and known.advisory.source == "ghsa" and "osv" in known.sources:
        osv_copies = [c for c in store.copies(advisory_id) if c.source == "osv"]
        if osv_copies and max(c.modified for c in osv_copies) < known.advisory.modified:
            reasons.append("ghsa_copy_differs")
            evidence["ghsa_modified"] = known.advisory.modified.isoformat()
    return reasons, evidence


def _reasons_scanner_only(
    key: Key,
    advisory_id: str,
    component: Component | None,
    store: AdvisoryStore,
    as_of: datetime,
    quarantined_names: set[str],
    unparseable: set[str],
    q06_ids: set[str],
) -> tuple[list[str], dict[str, str]]:
    reasons: list[str] = []
    evidence: dict[str, str] = {}
    if key[2] in ("UNKNOWN", ""):
        reasons.append("placeholder_version")
        evidence["osv_scanner_version"] = key[2] or "(empty)"
    if not key[0] and key[1] in quarantined_names:
        reasons.append("missing_purl")
    copies = store.copies(advisory_id)
    if copies and any(c.withdrawn is not None and c.withdrawn <= as_of for c in copies):
        reasons.append("withdrawn")
    if (component is not None and component.purl in unparseable) or advisory_id in q06_ids:
        reasons.append("version_scheme_edge")
    known = store.at(advisory_id, as_of)
    if known is not None and known.advisory.source == "ghsa":
        osv_copies = [c for c in copies if c.source == "osv"]
        if osv_copies and max(c.modified for c in osv_copies) < known.advisory.modified:
            reasons.append("ghsa_copy_differs")
    return reasons, evidence


def compare(
    product: str,
    components: Sequence[Component],
    findings: Sequence[Finding],
    scan: ScanResult,
    store: AdvisoryStore,
    as_of: datetime,
    *,
    probe: ScanResult | None = None,
    quarantined_names: Iterable[str] = (),
    unparseable: Iterable[str] = (),
    q06_ids: Iterable[str] = (),
) -> Comparison:
    ours = matcher_pairs(components, findings)
    theirs = scanned_pairs(scan)
    their_ecos = scanned_ecosystems(scan)
    probe_pairs = scanned_pairs(probe) if probe is not None else None
    by_key = _components_by_key(components)
    names_q07 = set(quarantined_names)
    bad_versions, bad_ranges = set(unparseable), set(q06_ids)
    disagreements: list[Disagreement] = []
    both = only_ours = only_theirs = 0
    for key in sorted(set(ours) | set(theirs)):
        mine, other = ours.get(key, set()), theirs.get(key, set())
        both += len(mine & other)
        component = by_key.get(key)
        for advisory_id in sorted(mine - other):
            only_ours += 1
            reasons, evidence = _reasons_matcher_only(
                key, advisory_id, component, their_ecos.get(key), probe_pairs, store, as_of
            )
            disagreements.append(_record(product, key, component, advisory_id, "matcher", reasons, evidence))
        for advisory_id in sorted(other - mine):
            only_theirs += 1
            reasons, evidence = _reasons_scanner_only(
                key, advisory_id, component, store, as_of, names_q07, bad_versions, bad_ranges
            )
            disagreements.append(
                _record(product, key, component, advisory_id, "osv-scanner", reasons, evidence)
            )
    package_differences = _package_differences(ours, theirs, names_q07)
    probe_summary = None
    if probe_pairs is not None:
        probe_summary = {
            "pairs_reported": sum(len(v) for v in probe_pairs.values()),
            "pairs_shared_with_matcher": sum(len(v & ours.get(k, set())) for k, v in probe_pairs.items()),
        }
    return Comparison(
        product=product,
        as_of=as_of,
        packages_matcher=len(ours),
        packages_osv_scanner=len(theirs),
        pairs_both=both,
        pairs_matcher_only=only_ours,
        pairs_osv_scanner_only=only_theirs,
        disagreements=tuple(disagreements),
        unexplained=sum(1 for d in disagreements if not d.explained),
        package_differences=tuple(package_differences),
        probe=probe_summary,
    )


def _record(
    product: str,
    key: Key,
    component: Component | None,
    advisory_id: str,
    side: str,
    reasons: list[str],
    evidence: dict[str, str],
) -> Disagreement:
    unique = tuple(dict.fromkeys(reasons))
    return Disagreement(
        product=product,
        ecosystem=key[0],
        package=key[1],
        version=key[2],
        purl=component.purl if component is not None else None,
        advisory_id=advisory_id,
        reported_by=side,
        reasons=unique,
        explained=bool(unique),
        evidence=evidence,
    )


def _package_differences(
    ours: Mapping[Key, set[str]], theirs: Mapping[Key, set[str]], names_q07: set[str]
) -> list[dict[str, str]]:
    """Packages one engine lists and the other does not, with what accounts for each."""
    out: list[dict[str, str]] = []
    lower_ours = {(k[0], k[1].lower(), k[2]): k for k in ours}
    for key in sorted(set(theirs) - set(ours)):
        if not key[0] and key[1] in names_q07:
            why = "no package URL (Q07): osv-scanner lists it with no ecosystem and matches nothing"
        elif key[2] in ("UNKNOWN", ""):
            why = "no version in the purl; osv-scanner keeps the component version UNKNOWN"
        elif (key[0], key[1].lower(), key[2]) in lower_ours:
            why = "the same package: the purl lowercases npm names, osv-scanner keeps the component name"
        else:
            why = "listed by osv-scanner only"
        out.append({"listed_by": "osv-scanner", "package": "/".join(key), "why": why})
    lower_theirs = {(k[0], k[1].lower(), k[2]) for k in theirs}
    for key in sorted(set(ours) - set(theirs)):
        if (key[0], key[1].lower(), key[2]) in lower_theirs:
            why = "the same package: the purl lowercases npm names, osv-scanner keeps the component name"
        else:
            why = "listed by the matcher only"
        out.append({"listed_by": "matcher", "package": "/".join(key), "why": why})
    return out
