"""The reasons a disagreement gets, from the evidence: none is given without it."""

from __future__ import annotations

from datetime import UTC, datetime

from unscheduled_match import disagreements
from unscheduled_match.matcher import match
from unscheduled_match.osvscanner import ScannedPackage, ScanResult
from unscheduled_match.sbom import Component

from tests.match import helpers

T = datetime(2026, 11, 7, tzinfo=UTC)
LIBC = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u9?arch=arm64&distro=debian-12.8&upstream=glibc"
TAR = "pkg:deb/debian/tar@1.34%2Bdfsg-1.2%2Bdeb12u1?arch=arm64&distro=debian-12.8"


def comp(purl: str) -> Component:
    return Component(bom_ref=purl, type="library", name=purl, purl=purl)


def scan(*packages: ScannedPackage) -> ScanResult:
    return ScanResult(sbom="x", packages=packages, exit_code=1)


def debian_store() -> object:
    return helpers.store_of(
        helpers.record(
            "DEBIAN-CVE-2026-0001", "Debian:12", "glibc", [{"introduced": "0"}], range_type="ECOSYSTEM"
        ),
        helpers.record(
            "DEBIAN-CVE-2026-0002", "Debian:12", "tar", [{"introduced": "0"}], range_type="ECOSYSTEM"
        ),
    )


def test_the_debian_release_and_source_package_explain_what_osv_scanner_misses() -> None:
    store = debian_store()
    components = [comp(LIBC), comp(TAR)]
    result = match("fw", components, store, T)  # type: ignore[arg-type]
    raw = scan(
        ScannedPackage(ecosystem="Debian:12.8", name="libc6", version="2.36-9+deb12u9", ids=()),
        ScannedPackage(ecosystem="Debian:12.8", name="tar", version="1.34+dfsg-1.2+deb12u1", ids=()),
    )
    probe = scan(
        ScannedPackage(ecosystem="Debian:12", name="libc6", version="2.36-9+deb12u9", ids=()),
        ScannedPackage(
            ecosystem="Debian:12", name="tar", version="1.34+dfsg-1.2+deb12u1", ids=("DEBIAN-CVE-2026-0002",)
        ),
    )
    out = disagreements.compare("fw", components, result.findings, raw, store, T, probe=probe)  # type: ignore[arg-type]
    reasons = {d.package: d.reasons for d in out.disagreements}
    assert reasons == {"libc6": ("release_qualifier", "source_package"), "tar": ("release_qualifier",)}
    assert out.unexplained == 0 and out.probe == {"pairs_reported": 1, "pairs_shared_with_matcher": 1}


def test_without_the_probe_a_matcher_only_finding_on_a_same_name_package_is_unexplained() -> None:
    store = debian_store()
    components = [comp(TAR)]
    result = match("fw", components, store, T)  # type: ignore[arg-type]
    raw = scan(ScannedPackage(ecosystem="Debian:12.8", name="tar", version="1.34+dfsg-1.2+deb12u1", ids=()))
    out = disagreements.compare("fw", components, result.findings, raw, store, T)  # type: ignore[arg-type]
    assert out.unexplained == 1


def test_a_placeholder_version_explains_what_only_osv_scanner_reports() -> None:
    store = helpers.store_of(
        helpers.record(
            "GHSA-x",
            "Maven",
            "org.springframework.boot:spring-boot-starter-web",
            [{"introduced": "0"}],
            range_type="ECOSYSTEM",
        )
    )
    components = [comp("pkg:maven/org.springframework.boot/spring-boot-starter-web")]
    raw = scan(
        ScannedPackage(
            ecosystem="Maven",
            name="org.springframework.boot:spring-boot-starter-web",
            version="UNKNOWN",
            ids=("GHSA-x",),
        )
    )
    out = disagreements.compare("java", components, (), raw, store, T)  # type: ignore[arg-type]
    assert [d.reasons for d in out.disagreements] == [("placeholder_version",)]


def test_a_withdrawn_advisory_explains_what_only_osv_scanner_reports() -> None:
    store = helpers.store_of(
        helpers.record("GHSA-w", "npm", "x", [{"introduced": "0"}], withdrawn="2026-01-01T00:00:00Z")
    )
    components = [comp("pkg:npm/x@1.0.0")]
    result = match("p", components, store, T)  # type: ignore[arg-type]
    raw = scan(ScannedPackage(ecosystem="npm", name="x", version="1.0.0", ids=("GHSA-w",)))
    out = disagreements.compare("p", components, result.findings, raw, store, T)  # type: ignore[arg-type]
    assert [d.reasons for d in out.disagreements] == [("withdrawn",)]


def test_agreement_is_counted_and_an_unknown_difference_is_unexplained() -> None:
    store = helpers.store_of(
        helpers.record("GHSA-a", "npm", "x", [{"introduced": "0"}]),
        helpers.record("GHSA-b", "npm", "x", [{"introduced": "0"}, {"fixed": "0.1.0"}]),
    )
    components = [comp("pkg:npm/x@1.0.0")]
    result = match("p", components, store, T)  # type: ignore[arg-type]
    raw = scan(ScannedPackage(ecosystem="npm", name="x", version="1.0.0", ids=("GHSA-a", "GHSA-b")))
    out = disagreements.compare("p", components, result.findings, raw, store, T)  # type: ignore[arg-type]
    assert out.pairs_both == 1 and out.pairs_osv_scanner_only == 1 and out.unexplained == 1
