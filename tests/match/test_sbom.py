"""The six committed SBOMs: CycloneDX 1.6, the digests the lock records, and Q07 for packages with no purl."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from unscheduled_match.products import load_config
from unscheduled_match.sbom import read, validate_cyclonedx_16

from tests.match import helpers

SBOMS = helpers.ROOT / "customer" / "sboms"
LOCK = json.loads((SBOMS / "sboms.lock.json").read_text(encoding="utf-8"))
PRODUCTS = [s.product for s in load_config(helpers.ROOT / "config" / "products.yaml").stand_ins]


def test_there_is_one_sbom_per_stand_in() -> None:
    assert sorted(e["product"] for e in LOCK["sboms"]) == sorted(PRODUCTS)
    assert LOCK["tool"]["name"] == "syft" and LOCK["tool"]["version"] == "1.57.0"


@pytest.mark.parametrize("entry", LOCK["sboms"], ids=[e["product"] for e in LOCK["sboms"]])
def test_each_sbom_is_valid_cyclonedx_16_with_the_digest_the_lock_records(entry: dict[str, object]) -> None:
    path = helpers.ROOT / str(entry["file"])
    assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"]
    assert validate_cyclonedx_16(path) is None
    sbom = read(path)
    assert sbom.spec_version == "1.6"
    assert len(sbom.components) == entry["components_with_purl"]
    assert len(sbom.quarantined) == entry["quarantined_q07"]


def test_a_package_without_a_purl_goes_to_q07_and_a_file_is_not_a_package(tmp_path: Path) -> None:
    path = helpers.sbom(
        tmp_path / "q07.cdx.json",
        [
            helpers.library("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0"),
            helpers.library("hbb_common", "0.1.0", None),
            {"bom-ref": "f1", "type": "file", "name": "/Cargo.lock"},
            {"bom-ref": "os", "type": "operating-system", "name": "debian", "version": "12.8"},
        ],
    )
    sbom = read(path)
    assert [c.name for c in sbom.components] == ["left-pad"]
    assert [(q.rule, q.name) for q in sbom.quarantined] == [("Q07", "hbb_common")]
    assert sbom.non_package == {"file": 1, "operating-system": 1}


def test_validation_refuses_a_broken_sbom(tmp_path: Path) -> None:
    path = tmp_path / "broken.cdx.json"
    path.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": "not a list"}),
        encoding="utf-8",
    )
    assert validate_cyclonedx_16(path) is not None
