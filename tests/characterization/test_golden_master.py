"""Golden master: the legacy script's behavior today, pinned before anything replaces it.

Two scenarios. Sample feeds in the 1.1 layout, built by convert.py from current NVD records: the CSV,
the mail and the console line must equal the golden files byte for byte. Retired feeds, a location
that answers nothing as the 1.1 feeds have since 2023: the script still exits 0, writes a CSV with
only the header and mails it as a report of 0 CVEs. That silent failure is behavior too, and it is
pinned like the rest.
"""

from __future__ import annotations

import configparser
import csv
import io
import json
from pathlib import Path

import pytest

from tests.characterization import convert, harness


@pytest.fixture(scope="module")
def sample_run(tmp_path_factory: pytest.TempPathFactory) -> harness.Run:
    tmp = tmp_path_factory.mktemp("sample")
    base_url, years = harness.sample_feeds(tmp)
    return harness.run(tmp, base_url, years)


@pytest.fixture(scope="module")
def retired_run(tmp_path_factory: pytest.TempPathFactory) -> harness.Run:
    tmp = tmp_path_factory.mktemp("retired")
    return harness.run(tmp, harness.retired_feeds(tmp), None)


def test_on_sample_feeds_the_csv_is_the_golden_master(sample_run: harness.Run) -> None:
    assert sample_run.exit_code == 0
    assert sample_run.csv_bytes == harness.golden("sample_feeds.csv")


def test_on_sample_feeds_the_mail_and_the_console_line_are_the_golden_master(sample_run: harness.Run) -> None:
    assert sample_run.mail == harness.golden("sample_feeds.mail.txt").decode("utf-8")
    assert f"exit code {sample_run.exit_code}\n{sample_run.stdout}" == harness.golden(
        "sample_feeds.stdout.txt"
    ).decode("utf-8")
    assert sample_run.attachment == sample_run.csv_bytes


def test_on_retired_feeds_it_fails_silently_with_a_header_only_report(retired_run: harness.Run) -> None:
    assert retired_run.exit_code == 0, "the bare except swallows the download failure"
    assert retired_run.csv_bytes == harness.golden("retired_feeds.csv")
    assert retired_run.csv_bytes.count(b"\r\n") == 1, "only the header line"
    assert "0 CVEs" in retired_run.mail
    assert retired_run.mail == harness.golden("retired_feeds.mail.txt").decode("utf-8")
    assert retired_run.stdout.strip().endswith("with 0 rows")


def test_the_mail_subject_counts_rows_and_calls_them_cves(sample_run: harness.Run) -> None:
    rows = list(csv.reader(io.StringIO(sample_run.csv_bytes.decode("utf-8"))))[1:]
    distinct = {r[0] for r in rows}
    assert f": {len(rows)} CVEs" in sample_run.mail
    assert len(distinct) < len(rows)


def test_products_only_in_and_configurations_are_never_reported(sample_run: harness.Run) -> None:
    """The script reads cpe_match of the top level nodes only, so an AND configuration (firmware
    running on a device, say) never reaches the report."""
    vendors = {v.strip() for v in harness_config()["filter"]["vendors"].split(",")}
    reported = {
        (r[0], r[3], r[4]) for r in list(csv.reader(io.StringIO(sample_run.csv_bytes.decode("utf-8"))))[1:]
    }
    only_in_and: set[tuple[str, str, str]] = set()
    in_or: set[tuple[str, str, str]] = set()
    for cve in convert.load_sample():
        for config in cve.get("configurations", []):
            for node in config["nodes"]:
                for m in node.get("cpeMatch", []):
                    parts = m["criteria"].split(":")
                    key = (cve["id"], parts[3], parts[4])
                    if parts[3] in vendors and m.get("vulnerable"):
                        (only_in_and if config.get("operator") == "AND" else in_or).add(key)
    missed = only_in_and - in_or
    assert missed, "the sample holds products that appear only in AND configurations"
    assert not missed & reported


def test_a_cve_the_nvd_has_not_analyzed_never_reaches_the_report(sample_run: harness.Run) -> None:
    unanalyzed = [c["id"] for c in convert.load_sample() if not c.get("configurations")]
    assert unanalyzed
    assert not any(cve.encode() in sample_run.csv_bytes for cve in unanalyzed)


def test_the_converter_gives_the_same_bytes_every_time(tmp_path: Path) -> None:
    records = convert.load_sample()
    first = [p.read_bytes() for p in convert.write(tmp_path / "a", records, harness.REFERENCE_DAY)]
    second = [p.read_bytes() for p in convert.write(tmp_path / "b", records, harness.REFERENCE_DAY)]
    assert first == second


def test_the_converter_writes_the_11_layout(tmp_path: Path) -> None:
    import gzip

    records = convert.load_sample()
    paths = convert.write(tmp_path, records, harness.REFERENCE_DAY)
    names = sorted(p.name for p in paths)
    assert "nvdcve-1.1-recent.json.gz" in names and "nvdcve-1.1-modified.json.gz" in names
    doc = json.loads(gzip.decompress((tmp_path / "nvdcve-1.1-2021.json.gz").read_bytes()))
    assert doc["CVE_data_version"] == "4.0" and doc["CVE_data_numberOfCVEs"] == str(len(doc["CVE_Items"]))
    item = doc["CVE_Items"][0]
    assert set(item) == {"cve", "configurations", "impact", "publishedDate", "lastModifiedDate"}
    assert item["publishedDate"].endswith("Z") and len(item["publishedDate"]) == 17


def harness_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(harness.CONFIG, encoding="utf-8")
    return cfg


def test_the_handed_over_config_still_points_at_the_retired_feeds() -> None:
    cfg = harness_config()
    assert cfg["feeds"]["base_url"] == "https://nvd.nist.gov/feeds/json/cve/1.1/"
    assert cfg["mail"]["smtp_host"].endswith(".example"), "a reserved domain: nothing is ever mailed"


def test_the_fixture_says_it_is_a_fixture() -> None:
    head = harness.SCRIPT.read_text(encoding="utf-8")[:1200]
    assert "FIXTURE" in head and "written in November 2026 for the unscheduled demonstration" in head
    assert "never run against the live NVD" in head
