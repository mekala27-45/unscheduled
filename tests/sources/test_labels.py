"""A source that answers with a status value nobody registered fails until it is registered."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from unscheduled_sources import labels
from unscheduled_sources.labels import Seen, UnregisteredStatus
from unscheduled_sources.nvd import parse_cves

from tests.sources.conftest import ROOT, fixture_bytes

WHEN = datetime(2026, 11, 8, 3, 0, tzinfo=UTC)


def _page() -> dict[str, object]:
    body: dict[str, object] = json.loads(fixture_bytes("nvd_cves_page.json.gz", unzip=True))
    return body


def test_every_status_in_the_recorded_page_is_registered() -> None:
    known = labels.registered(ROOT / "config" / "labels.yaml")
    cves, _, _ = parse_cves(_page(), WHEN, known)  # type: ignore[arg-type]
    assert {c["vuln_status"] for c in cves} <= known


def test_a_new_status_value_stops_the_parse_and_names_the_value() -> None:
    page = _page()
    vulns = page["vulnerabilities"]
    assert isinstance(vulns, list)
    # A planted value, in the shape a new NVD label would arrive in.
    vulns[0]["cve"]["vulnStatus"] = "Not Scheduled"
    known = labels.registered(ROOT / "config" / "labels.yaml")
    with pytest.raises(UnregisteredStatus, match="'Not Scheduled'"):
        parse_cves(page, WHEN, known)  # type: ignore[arg-type]


def test_registering_the_value_lets_the_parse_through(tmp_path: Path) -> None:
    path = tmp_path / "labels.yaml"
    data = labels.load(ROOT / "config" / "labels.yaml")
    data["nvd_vuln_status"]["Not Scheduled"] = {"meaning": "planted for the test"}
    labels.dump(path, data)
    page = _page()
    vulns = page["vulnerabilities"]
    assert isinstance(vulns, list)
    vulns[0]["cve"]["vulnStatus"] = "Not Scheduled"
    cves, _, _ = parse_cves(page, WHEN, labels.registered(path))  # type: ignore[arg-type]
    assert cves[0]["vuln_status"] == "Not Scheduled"


def test_the_registry_holds_the_april_2026_label_with_its_dates() -> None:
    data = yaml.safe_load((ROOT / "config" / "labels.yaml").read_text(encoding="utf-8"))
    statuses = data["nvd_vuln_status"]
    flagged = [k for k, v in statuses.items() if v.get("april_2026_label")]
    assert flagged == ["Deferred"]
    for value, entry in statuses.items():
        assert entry["meaning"], value
        assert date.fromisoformat(entry["first_seen"]) <= date.fromisoformat(entry["last_seen"])


def test_observe_moves_the_dates_forward_and_refuses_an_unknown_value(tmp_path: Path) -> None:
    path = tmp_path / "labels.yaml"
    labels.dump(path, labels.load(ROOT / "config" / "labels.yaml"))
    # The committed file moves with every fetch, so the test observes a day after anything in it.
    later = date.fromisoformat(labels.load(path)["nvd_vuln_status"]["Deferred"]["last_seen"]) + timedelta(
        days=1
    )
    labels.observe(path, {"Deferred": Seen(date(2026, 11, 7), later, 12)})
    entry = labels.load(path)["nvd_vuln_status"]["Deferred"]
    assert entry["first_seen"] <= "2026-11-07" and entry["last_seen"] == later.isoformat()
    assert entry["cves_at_last_fetch"] == 12
    with pytest.raises(UnregisteredStatus):
        labels.observe(path, {"Something New": Seen(date(2026, 11, 9), date(2026, 11, 9), 1)})
