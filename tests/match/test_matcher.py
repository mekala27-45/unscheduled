"""The matcher: one finding per component and advisory group, exactly as of a time, and a planted
vulnerable component that the matcher and osv-scanner must both find."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from unscheduled_match import cache, osvscanner
from unscheduled_match import ecosystems as eco_mod
from unscheduled_match import store as store_mod
from unscheduled_match.matcher import group_by_alias, match
from unscheduled_match.sbom import Component
from unscheduled_match.sbom import read as read_sbom

from tests.match import helpers

T = datetime(2025, 6, 1, tzinfo=UTC)


def component(purl: str) -> Component:
    return Component(bom_ref=purl, type="library", name=purl, purl=purl)


def test_a_version_inside_the_range_is_a_finding_with_its_range_and_fix() -> None:
    store = helpers.store_of(
        helpers.record(
            "GHSA-aaaa-bbbb-cccc",
            "npm",
            "left-pad",
            [{"introduced": "0"}, {"fixed": "1.3.0"}],
            aliases=["CVE-2024-0001"],
        )
    )
    result = match("p", [component("pkg:npm/left-pad@1.1.0")], store, T)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.advisory_ids == ("GHSA-aaaa-bbbb-cccc",)
    assert finding.cve_aliases == ("CVE-2024-0001",)
    assert finding.matches[0].matched_range == "vers:npm/<1.3.0"
    assert finding.fixed_versions == ("1.3.0",)
    assert finding.fix_available is True
    assert match("p", [component("pkg:npm/left-pad@1.3.0")], store, T).findings == ()


def test_advisories_that_alias_each_other_make_one_finding() -> None:
    events = [{"introduced": "0"}, {"fixed": "0.33.0"}]
    store = helpers.store_of(
        helpers.record(
            "GHSA-qxp5-gwg8-xv66",
            "Go",
            "golang.org/x/net",
            events,
            aliases=["CVE-2025-22870", "GO-2025-3503"],
        ),
        helpers.record(
            "GO-2025-3503",
            "Go",
            "golang.org/x/net",
            events,
            aliases=["CVE-2025-22870", "GHSA-qxp5-gwg8-xv66"],
        ),
    )
    result = match("p", [component("pkg:golang/golang.org/x/net@v0.23.0")], store, T)
    assert len(result.findings) == 1
    assert result.findings[0].advisory_ids == ("GHSA-qxp5-gwg8-xv66", "GO-2025-3503")
    assert result.findings[0].primary_id == "GHSA-qxp5-gwg8-xv66"


def test_grouping_is_transitive() -> None:
    a = helpers.advisory(helpers.record("A-1", "npm", "x", [{"introduced": "0"}], aliases=["B-1"]))
    b = helpers.advisory(helpers.record("B-1", "npm", "x", [{"introduced": "0"}], aliases=["C-1"]))
    c = helpers.advisory(helpers.record("C-1", "npm", "x", [{"introduced": "0"}]))
    d = helpers.advisory(helpers.record("D-1", "npm", "x", [{"introduced": "0"}]))
    groups = group_by_alias([a, b, c, d])
    assert [[x.id for x in g] for g in groups] == [["A-1", "B-1", "C-1"], ["D-1"]]


def test_an_advisory_published_after_t_is_not_known_at_t() -> None:
    store = helpers.store_of(
        helpers.record(
            "GHSA-late-0000-0000",
            "npm",
            "x",
            [{"introduced": "0"}],
            published="2025-07-01T00:00:00Z",
            modified="2025-07-01T00:00:00Z",
        )
    )
    assert match("p", [component("pkg:npm/x@1.0.0")], store, T).findings == ()
    assert (
        len(match("p", [component("pkg:npm/x@1.0.0")], store, datetime(2025, 8, 1, tzinfo=UTC)).findings) == 1
    )


def test_a_copy_modified_after_t_stands_in_by_rule_and_withholds_its_fix() -> None:
    store = helpers.store_of(
        helpers.record(
            "GHSA-rule-0000-0000",
            "npm",
            "x",
            [{"introduced": "0"}, {"fixed": "2.0.0"}],
            published="2025-01-01T00:00:00Z",
            modified="2026-01-01T00:00:00Z",
            severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        )
    )
    finding = match("p", [component("pkg:npm/x@1.0.0")], store, T).findings[0]
    assert finding.known_from_rule == "published"
    assert finding.known_from == datetime(2025, 1, 1, tzinfo=UTC)
    assert finding.fix_available is None and finding.fixed_versions == ()
    assert finding.severity == ()
    later = match("p", [component("pkg:npm/x@1.0.0")], store, datetime(2026, 2, 1, tzinfo=UTC)).findings[0]
    assert later.known_from_rule == "modified" and later.fix_available is True and later.severity


def test_a_withdrawn_advisory_matches_nothing_from_its_withdrawal() -> None:
    store = helpers.store_of(
        helpers.record(
            "GHSA-gone-0000-0000", "npm", "x", [{"introduced": "0"}], withdrawn="2025-03-01T00:00:00Z"
        )
    )
    assert match("p", [component("pkg:npm/x@1.0.0")], store, T).findings == ()
    assert (
        len(match("p", [component("pkg:npm/x@1.0.0")], store, datetime(2025, 2, 1, tzinfo=UTC)).findings) == 1
    )


def test_the_newest_copy_known_at_t_wins_and_osv_wins_a_tie() -> None:
    old = helpers.record(
        "GHSA-twin-0000-0000",
        "npm",
        "x",
        [{"introduced": "0"}, {"fixed": "1.5.0"}],
        modified="2024-02-01T00:00:00Z",
    )
    new = helpers.record(
        "GHSA-twin-0000-0000",
        "npm",
        "x",
        [{"introduced": "0"}, {"fixed": "1.2.0"}],
        modified="2025-02-01T00:00:00Z",
    )
    store = store_mod.AdvisoryStore()
    store.add(helpers.advisory(old, "osv"))
    store.add(helpers.advisory(new, "ghsa"))
    known = store.at("GHSA-twin-0000-0000", T)
    assert known is not None and known.advisory.source == "ghsa" and known.sources == ("ghsa", "osv")
    assert match("p", [component("pkg:npm/x@1.3.0")], store, T).findings == ()
    tie = store_mod.AdvisoryStore()
    tie.add(helpers.advisory(new, "ghsa"))
    tie.add(helpers.advisory(new, "osv"))
    picked = tie.at("GHSA-twin-0000-0000", T)
    assert picked is not None and picked.advisory.source == "osv"


def test_git_ranges_are_skipped_and_counted_and_bad_ranges_quarantined() -> None:
    store = helpers.store_of(
        helpers.record(
            "PYSEC-0000-1",
            "PyPI",
            "Django",
            [{"introduced": "abc123"}, {"fixed": "def456"}],
            range_type="GIT",
        ),
        helpers.record(
            "PYSEC-0000-2",
            "PyPI",
            "django",
            [{"introduced": "0"}, {"fixed": "not a version"}],
            range_type="ECOSYSTEM",
        ),
    )
    result = match("p", [component("pkg:pypi/django@4.2.0")], store, T)
    assert result.findings == ()
    assert result.stats.git_ranges_skipped == 1 and result.stats.git_only_advisories == 1
    assert result.stats.unparseable_ranges == 1
    assert result.range_quarantine[0].rule == "Q06"


def test_an_enumerated_version_matches_even_with_only_a_git_range() -> None:
    store = helpers.store_of(
        helpers.record(
            "PYSEC-0000-3", "PyPI", "pillow", [{"introduced": "abc"}], range_type="GIT", versions=["9.0.0"]
        )
    )
    finding = match("p", [component("pkg:pypi/Pillow@9.0.0")], store, T).findings[0]
    assert finding.matches[0].via == "versions"


def test_a_debian_binary_package_matches_its_source_in_its_release_only() -> None:
    store = helpers.store_of(
        helpers.record(
            "DEBIAN-CVE-2024-0002",
            "Debian:12",
            "glibc",
            [{"introduced": "0"}, {"fixed": "2.36-9+deb12u10"}],
            range_type="ECOSYSTEM",
        ),
        helpers.record(
            "DEBIAN-CVE-2024-0003", "Debian:11", "glibc", [{"introduced": "0"}], range_type="ECOSYSTEM"
        ),
    )
    purl = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u9?arch=arm64&distro=debian-12.8&upstream=glibc"
    findings = match("p", [component(purl)], store, T).findings
    assert [f.primary_id for f in findings] == ["DEBIAN-CVE-2024-0002"]
    assert findings[0].binary_package == "libc6" and findings[0].package == "glibc"


def test_a_component_listed_twice_is_one_component() -> None:
    store = helpers.store_of(
        helpers.record("GHSA-dupe-0000-0000", "crates.io", "anyhow", [{"introduced": "0"}])
    )
    result = match(
        "p", [component("pkg:cargo/anyhow@1.0.86"), component("pkg:cargo/anyhow@1.0.86")], store, T
    )
    assert result.stats.components == 1 and len(result.findings) == 1


PLANTED = helpers.record(
    "PLANTED-2026-0001",
    "npm",
    "velloran-planted-widget",
    [{"introduced": "1.0.0"}, {"fixed": "1.4.2"}],
    aliases=["CVE-2026-99999"],
    published="2026-01-05T00:00:00Z",
    modified="2026-01-05T00:00:00Z",
)


def planted_sbom(tmp: Path) -> Path:
    return helpers.sbom(
        tmp / "planted.cdx.json",
        [
            helpers.library("velloran-planted-widget", "1.3.0", "pkg:npm/velloran-planted-widget@1.3.0"),
            helpers.library("velloran-safe-widget", "1.3.0", "pkg:npm/velloran-safe-widget@1.3.0"),
        ],
    )


def test_the_matcher_finds_the_planted_component(tmp_path: Path) -> None:
    root = helpers.osv_cache(tmp_path / "cache", {"npm": [PLANTED]})
    sbom = read_sbom(planted_sbom(tmp_path))
    store, stats = store_mod.load(root, [eco_mod.NPM], [("npm", "velloran-planted-widget")])
    assert stats.osv_records == {"npm": 1}
    result = match("planted", sbom.components, store, datetime(2026, 11, 7, tzinfo=UTC))
    assert [(f.package, f.version, f.primary_id) for f in result.findings] == [
        ("velloran-planted-widget", "1.3.0", "PLANTED-2026-0001")
    ]


@pytest.mark.skipif(not helpers.OSV_SCANNER.exists(), reason="run scripts/make_sboms.py tools first")
def test_osv_scanner_finds_the_planted_component_from_the_same_file(tmp_path: Path) -> None:
    root = helpers.osv_cache(tmp_path / "cache", {"npm": [PLANTED]})
    db = cache.osv_scanner_db_dir(root, [eco_mod.NPM], tmp_path / "db")
    out = tmp_path / "osv.json"
    code = osvscanner.run(helpers.OSV_SCANNER, planted_sbom(tmp_path), db, out)
    scan = osvscanner.read(out, "planted", code)
    found = {(p.name, p.version): p.ids for p in scan.packages}
    assert found[("velloran-planted-widget", "1.3.0")] == ("PLANTED-2026-0001",)
    assert found[("velloran-safe-widget", "1.3.0")] == ()
    assert code == 1


@pytest.mark.skipif(not helpers.OSV_SCANNER.exists(), reason="run scripts/make_sboms.py tools first")
def test_both_engines_find_a_component_planted_in_a_real_sbom(tmp_path: Path) -> None:
    real = helpers.ROOT / "customer" / "sboms" / "go-edge-service.cdx.json"
    document = json.loads(real.read_text(encoding="utf-8"))
    document["components"].append(
        helpers.library("velloran-planted-widget", "1.0.0", "pkg:npm/velloran-planted-widget@1.0.0")
    )
    planted = tmp_path / "go-edge-service-planted.cdx.json"
    planted.write_text(json.dumps(document), encoding="utf-8")
    # osv-scanner wants a database for every ecosystem the SBOM holds: an empty one for Go.
    root = helpers.osv_cache(tmp_path / "cache", {"npm": [PLANTED], "Go": []})
    store, _ = store_mod.load(root, [eco_mod.NPM, eco_mod.GO], [("npm", "velloran-planted-widget")])
    ours = match("planted", read_sbom(planted).components, store, datetime(2026, 11, 7, tzinfo=UTC))
    assert "PLANTED-2026-0001" in {f.primary_id for f in ours.findings}
    db = cache.osv_scanner_db_dir(root, [eco_mod.NPM, eco_mod.GO], tmp_path / "db")
    out = tmp_path / "osv.json"
    scan = osvscanner.read(out, "planted", osvscanner.run(helpers.OSV_SCANNER, planted, db, out))
    assert any("PLANTED-2026-0001" in p.ids for p in scan.packages)
