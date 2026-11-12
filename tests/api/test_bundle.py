"""The bundle contract read row by row: types, digests, keys, and what a broken manifest says."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime

import pytest
from unscheduled_api import bundle as bnd
from unscheduled_api.bundle import BundleError, parse_manifest

from tests.api.fixtures.bundle import rows


def manifest(**changes: object) -> bytes:
    base = {
        "generated_at": "2026-11-07T05:00:00Z",
        "lake_digest": "sha256:x",
        "files": [{"file": name, "sha256": "a" * 64, "rows": 1} for name in bnd.FILES],
    }
    base.update(changes)
    return json.dumps(base).encode()


def test_a_manifest_that_names_every_file_parses() -> None:
    parsed = parse_manifest(manifest(locks={"kev": {"sha256": "b" * 64}}))
    assert [f.file for f in parsed.files] == list(bnd.FILES)
    assert parsed.locks == {"kev": {"sha256": "b" * 64}}


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"not json", "is not JSON"),
        (b"[]", "is not a JSON object"),
        (manifest(files=[{"file": "cve.parquet", "sha256": "a" * 64}]), "does not name"),
        (manifest(files=[{"file": n, "sha256": "A" * 64} for n in bnd.FILES]), "64 lowercase hex"),
        (
            manifest(files=[{"file": n, "sha256": "a" * 64, "rows": -1} for n in bnd.FILES]),
            "negative row count",
        ),
        (manifest(files=[{"file": n, "sha256": "a" * 64} for n in (*bnd.FILES, "cve.parquet")]), "twice"),
        (manifest(lake_digest=None), "does not match the contract"),
    ],
)
def test_a_broken_manifest_says_what_is_wrong(data: bytes, message: str) -> None:
    with pytest.raises(BundleError, match=message):
        parse_manifest(data)


def test_a_cve_row_is_typed_and_its_digest_is_stable() -> None:
    raw = dict(rows("cve")[0])
    first = bnd.cve_row(raw)
    assert first["published"] == datetime(2021, 3, 1, 12, tzinfo=UTC)
    assert first["kev_date_added"] == date(2021, 12, 10)
    assert first["cwes"] == ["CWE-502"] and first["has_cpe"] is True
    assert first["provenance"]["nvd_status"]["source"] == "nvd@nist.gov"
    again = bnd.cve_row(dict(reversed(list(raw.items()))))
    assert again["row_digest"] == first["row_digest"]
    raw["epss_score"] = 0.5
    assert bnd.cve_row(raw)["row_digest"] != first["row_digest"]


@pytest.mark.parametrize(
    ("column", "value", "message"),
    [
        ("published", "not a time", "is not a timestamp"),
        ("kev_date_added", 12, "is not a date"),
        ("epss_score", "high", "is not a number"),
        ("has_cpe", "maybe", "is not a boolean"),
        ("provenance_json", "{broken", "is not JSON"),
        ("provenance_json", "[1, 2]", "is not a JSON object"),
    ],
)
def test_a_value_of_the_wrong_type_is_refused_by_column(column: str, value: object, message: str) -> None:
    raw = dict(rows("cve")[0], **{column: value})
    with pytest.raises(BundleError, match=message):
        bnd.cve_row(raw)


def test_text_loses_nul_bytes_the_database_cannot_hold() -> None:
    raw = dict(rows("cve")[0], description="a\x00b")
    assert bnd.cve_row(raw)["description"] == "ab"


def test_lists_arrive_in_any_of_the_shapes_a_writer_uses() -> None:
    assert bnd.READERS["text_list"]('["CWE-79", "CWE-79", "CWE-20"]', "c") == ["CWE-20", "CWE-79"]
    assert bnd.READERS["text_list"]("CWE-79; CWE-20", "c") == ["CWE-20", "CWE-79"]
    assert bnd.READERS["text_list"](None, "c") == []


def test_an_event_id_is_a_digest_of_its_content() -> None:
    raw = rows("cve_event")[2]
    one, two = bnd.event_row(raw), bnd.event_row(dict(raw))
    assert one["event_id"] == two["event_id"] and len(one["event_id"]) == 16
    assert bnd.event_row(dict(raw, kind="other"))["event_id"] != one["event_id"]


def test_a_finding_names_every_cve_it_carries() -> None:
    raw = dict(rows("finding")[0], cve_id="cve-2020-0001", upstream_cves=["CVE-2019-0002"])
    built = bnd.finding_row(raw)
    assert built["cve_ids"] == ["CVE-2019-0002", "CVE-2020-0001", "CVE-2021-90001"]
    assert built["product_id"] == "go-edge-service" and built["as_of"] == date(2024, 12, 31)
    assert len(built["finding_id"]) == 32


def test_a_product_takes_its_key_from_product_id_or_product() -> None:
    assert bnd.product_row({"product_id": "a", "name": "A"})["name"] == "A"
    assert bnd.product_row({"product": "b"})["product_id"] == "b"
    with pytest.raises(BundleError):
        bnd.product_row({"name": "nobody"})


def test_the_column_check_names_what_is_missing() -> None:
    assert bnd.check_columns("cve", [c.name for c in bnd.CVE_COLUMNS if c.required]) == [
        "state",
        "adp_cvss31_score",
        "adp_cvss31_band",
        "epss_percentile",
    ]
    with pytest.raises(BundleError, match="product_id or product"):
        bnd.check_columns("finding", ["as_of"])
