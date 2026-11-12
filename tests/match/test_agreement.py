"""The matcher and osv-scanner on the six SBOMs: every disagreement explained.

The committed results are checked first, without any advisory data: the pair counts in
disagreements.json follow from the committed findings and osv-scanner output, and nothing is
unexplained. When the OSV files and the pinned osv-scanner are on disk (the exposure workflow), the
comparison is also run again live for the products small enough to keep the suite quick.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from unscheduled_match import cache, disagreements, osvscanner
from unscheduled_match import ecosystems as eco_mod
from unscheduled_match import purl as purl_mod
from unscheduled_match import store as store_mod
from unscheduled_match.matcher import match
from unscheduled_match.products import load_config
from unscheduled_match.sbom import read as read_sbom

from tests.match import helpers

ROOT = helpers.ROOT
EXPOSURE = ROOT / "results" / "exposure"
CACHE = ROOT / "data" / "cache"
PRODUCTS = [s.product for s in load_config(ROOT / "config" / "products.yaml").stand_ins]


def load(name: str) -> Any:
    return json.loads((EXPOSURE / name).read_text(encoding="utf-8"))


def test_the_committed_comparison_covers_the_six_products_and_explains_everything() -> None:
    data = load("disagreements.json")
    assert sorted(data["products"]) == sorted(PRODUCTS)
    assert data["unexplained"] == 0
    assert data["pairs_both"] > 0
    for product in data["products"].values():
        for item in product["disagreements"]:
            assert item["explained"] and item["reasons"], item
            assert set(item["reasons"]) <= set(disagreements.REASONS), item["reasons"]


def test_the_committed_pair_counts_follow_from_the_committed_outputs() -> None:
    findings = load("findings_today.json")["products"]
    scans = load("osv_scanner.json")["products"]
    data = load("disagreements.json")["products"]
    for product in PRODUCTS:
        ours: dict[tuple[str, str, str], set[str]] = {}
        for finding in findings[product]["findings"]:
            key = purl_mod.component_key(finding["purl"])
            assert key is not None
            ours.setdefault(key, set()).update(finding["advisory_ids"])
        theirs: dict[tuple[str, str, str], set[str]] = {}
        for package in scans[product]["packages"]:
            key = osvscanner.comparison_key(package["ecosystem"], package["name"], package["version"])
            theirs.setdefault(key, set()).update(package["ids"])
        both = sum(len(ids & theirs.get(k, set())) for k, ids in ours.items())
        only_ours = sum(len(ids - theirs.get(k, set())) for k, ids in ours.items())
        only_theirs = sum(len(ids - ours.get(k, set())) for k, ids in theirs.items())
        recorded = data[product]
        assert (both, only_ours, only_theirs) == (
            recorded["pairs_both"],
            recorded["pairs_matcher_only"],
            recorded["pairs_osv_scanner_only"],
        ), product


def test_the_two_engines_read_the_same_osv_files() -> None:
    files = load("findings_today.json")["osv_files"]
    assert {f["ecosystem"] for f in files} == {e.osv for e in eco_mod.ALL}
    assert all(f["same_as_sources_lock"] in (True, None) for f in files)


def ecosystems_of(components: Any) -> list[eco_mod.Ecosystem]:
    found: dict[str, eco_mod.Ecosystem] = {}
    for component in components:
        eco = purl_mod.ecosystem_of(purl_mod.parse(component.purl)) if component.purl else None
        if eco is not None:
            found[eco.osv] = eco
    return [found[k] for k in sorted(found)]


LIVE = all(cache.osv_zip_path(CACHE, e).exists() for e in eco_mod.ALL) and helpers.OSV_SCANNER.exists()


@pytest.mark.skipif(not LIVE, reason="needs data/cache/osv and tools/bin/osv-scanner (the exposure workflow)")
@pytest.mark.parametrize(
    "product", ["go-edge-service", "java-integration-service", "door-controller-firmware"]
)
def test_the_engines_agree_live_on_the_same_files(product: str, tmp_path: Path) -> None:
    sbom_path = ROOT / "customer" / "sboms" / f"{product}.cdx.json"
    sbom = read_sbom(sbom_path)
    wanted = [(k.ecosystem, k.name) for c in sbom.components if (k := c.key())]
    ecosystems = ecosystems_of(sbom.components)
    advisories, _ = store_mod.load(CACHE, ecosystems, wanted)
    now = datetime.now(UTC).replace(microsecond=0)
    result = match(product, sbom.components, advisories, now, sbom.quarantined)
    db = cache.osv_scanner_db_dir(CACHE, ecosystems, tmp_path / "db")
    out = tmp_path / "osv.json"
    scan = osvscanner.read(out, product, osvscanner.run(helpers.OSV_SCANNER, sbom_path, db, out))
    probe = None
    if product == "door-controller-firmware":
        copy = tmp_path / sbom_path.name
        copy.write_text(
            sbom_path.read_text(encoding="utf-8").replace("distro=debian-12.8", "distro=debian-12"),
            encoding="utf-8",
        )
        probe_out = tmp_path / "probe.json"
        probe = osvscanner.read(probe_out, "probe", osvscanner.run(helpers.OSV_SCANNER, copy, db, probe_out))
    comparison = disagreements.compare(
        product,
        sbom.components,
        result.findings,
        scan,
        advisories,
        now,
        probe=probe,
        quarantined_names=[q.name for q in sbom.quarantined],
        unparseable=result.unparseable_versions,
        q06_ids=[q.advisory_id for q in result.range_quarantine],
    )
    assert comparison.unexplained == 0, [d for d in comparison.disagreements if not d.explained][:5]
