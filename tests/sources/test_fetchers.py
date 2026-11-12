"""Every fetcher against recorded answers: fetch through a mock transport, lock, parse to bronze."""

from __future__ import annotations

import gzip
import json
import subprocess
from datetime import UTC, date, datetime
from pathlib import Path

import httpx
import polars as pl
import pytest
from unscheduled_sources import base, cvelist, gitrepo, kev, ledger, locks
from unscheduled_sources.cna_list import build, group_for
from unscheduled_sources.contract import frame
from unscheduled_sources.cvelist import CveList, parse_record
from unscheduled_sources.cwe import Cwe, parse_catalog
from unscheduled_sources.epss import Epss, read_header, read_scores
from unscheduled_sources.exploits import module_cves
from unscheduled_sources.ghsa import ghsa_row
from unscheduled_sources.kev import Kev, first_seen_from_log
from unscheduled_sources.nvd import Nvd, parse_history, source_type
from unscheduled_sources.osv import Osv, source_db
from unscheduled_sources.registries import Registries, gleif_matches, name_check
from unscheduled_sources.vulnrichment import vulnrichment_row

from tests.sources.conftest import fixture_bytes, make_context

WHEN = datetime(2026, 11, 8, 3, 0, tzinfo=UTC)


def _rows(ctx: base.Context, table: str) -> pl.DataFrame:
    return ctx.bronze.read(table)


# The CVE List.


def test_cvelist_baseline_and_delta_from_recorded_releases(
    tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    served: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        served.append(request.url.path)
        name = "cvelist_baseline.zip.zip" if request.url.path.endswith(".zip.zip") else "cvelist_delta.zip"
        return httpx.Response(200, content=fixture_bytes(name))

    monkeypatch.setattr(
        cvelist, "release_tags", lambda _url: [("2026-11-08", "0000"), ("2026-11-08", "0200")]
    )
    ctx = make_context(tmp_root, handler)
    summary = base.run(CveList(ctx))
    assert summary.units == 2
    assert served[0].endswith("/cve_2026-11-08_0000Z/2026-11-08_all_CVEs_at_midnight.zip.zip")
    assert served[1].endswith("/cve_2026-11-08_0200Z/2026-11-08_delta_CVEs_at_0200Z.zip")
    records = _rows(ctx, "cve_records")
    # The delta holds the same three records as the baseline, so it adds none.
    assert records.height == 3
    assert set(records.get_column("snapshot_at").to_list()) == {datetime(2026, 11, 8, tzinfo=UTC)}
    assert records.get_column("cve_id").str.starts_with("CVE-2026-").all()
    metrics = _rows(ctx, "cve_metrics")
    assert metrics.height > 0 and set(metrics.get_column("origin").to_list()) == {"cvelist"}
    lock = locks.load(ctx.locks_dir, "cvelist")
    assert [e.rows for e in lock.entries] == [3, 3]


def test_a_cve_record_is_read_field_by_field() -> None:
    import zipfile

    with zipfile.ZipFile(Path(__file__).parent / "fixtures" / "cvelist_delta.zip") as z:
        record = json.loads(z.read(z.namelist()[0]))
    row, metrics, _ = parse_record(record, WHEN)
    meta = record["cveMetadata"]
    assert row["cve_id"] == meta["cveId"]
    assert row["assigner_short_name"] == meta["assignerShortName"]
    assert row["date_published"] is not None and row["date_published"].tzinfo is not None
    assert row["references_count"] == len(record["containers"]["cna"].get("references") or [])
    assert len(row["record_digest"]) == 64
    assert all(m["source_type"] in ("cna", "adp") for m in metrics)


def test_affected_versions_need_a_real_version() -> None:
    assert not cvelist.has_versions([{"versions": [{"version": "n/a", "status": "affected"}]}])
    assert cvelist.has_versions([{"versions": [{"version": "0", "lessThan": "2.1", "status": "affected"}]}])
    assert cvelist.has_versions([{"versions": [{"version": "1.4.2", "status": "affected"}]}])


# The NVD.


def test_nvd_pages_and_history_from_recorded_answers(tmp_root: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        name = "nvd_history_page.json.gz" if "cvehistory" in request.url.path else "nvd_cves_page.json.gz"
        return httpx.Response(200, content=fixture_bytes(name, unzip=True))

    ctx = make_context(tmp_root, handler)
    fetcher = Nvd(ctx)
    fetcher.cfg["history_start"] = "2026-11-06T00:00:00Z"
    summary = base.run(fetcher)
    assert summary.units >= 2
    cves = _rows(ctx, "nvd_cves")
    assert cves.height == 4
    assert set(cves.get_column("vuln_status").to_list()) == {"Received", "Deferred", "Analyzed", "Rejected"}
    changes = _rows(ctx, "nvd_changes")
    assert changes.height == 5 and changes.get_column("cve_change_id").n_unique() == 5
    windows = [r.window for r in ledger.rows(ctx.locks_dir, "nvd")]
    assert windows[0].startswith("cves full ") and any(w.startswith("history ") for w in windows)
    assert all("apiKey" not in e.url for e in locks.load(ctx.locks_dir, "nvd").entries)


def test_nvd_resumes_from_the_ledger_without_refetching(tmp_root: Path) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=fixture_bytes("nvd_cves_page.json.gz", unzip=True))

    ctx = make_context(tmp_root, handler)
    base.run(Nvd(ctx, parts=("cves",)))
    first = len(calls)
    base.run(Nvd(ctx, parts=("cves",)))
    assert len(calls) == first


def test_nvd_sends_the_key_in_a_header_and_never_in_the_url(tmp_root: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=fixture_bytes("nvd_cves_page.json.gz", unzip=True))

    ctx = make_context(tmp_root, handler, env={"NVD_API_KEY": "k" * 36})
    fetcher = Nvd(ctx, parts=("cves",))
    assert fetcher.limit.requests == 50
    base.run(fetcher)
    assert seen and all(r.headers.get("apiKey") == "k" * 36 and "k" * 36 not in str(r.url) for r in seen)


def test_metric_providers_are_typed_by_who_wrote_them() -> None:
    assert source_type("nvd@nist.gov", "cna@vuldb.com") == "nvd"
    assert source_type("cna@vuldb.com", "cna@vuldb.com") == "cna"
    assert source_type("134c704f-9b21-4f2e-91b3-4a467353bcc0", "x") == "adp"
    assert source_type("security-advisories@github.com", "cve@mitre.org") == "secondary"


def test_history_events_keep_their_details_as_canonical_json() -> None:
    body = json.loads(fixture_bytes("nvd_history_page.json.gz", unzip=True))
    rows = parse_history(body)
    assert len(rows) == 5
    assert all(r["created"].tzinfo is not None for r in rows)
    assert json.loads(rows[2]["details_json"]) == body["cveChanges"][2]["change"]["details"]


# KEV.


def test_kev_from_the_pinned_commit_with_its_first_appearance(
    tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith(".csv"):
            return httpx.Response(200, content=fixture_bytes("kev.csv.gz", unzip=True))
        if "cisa.gov" in str(request.url):
            return httpx.Response(200, content=fixture_bytes("kev_cisa_feed.json.gz", unzip=True))
        return httpx.Response(200, content=fixture_bytes("kev.json.gz", unzip=True))

    commit = "e5b3a9b25050a8da26c96266c5bfe438ee0bdebc"
    monkeypatch.setattr(gitrepo, "remote_head", lambda *_a, **_k: commit)
    monkeypatch.setattr(gitrepo, "ensure_clone", lambda *a, **k: Path("."))
    log = fixture_bytes("kev_gitlog.txt.gz", unzip=True).decode()
    monkeypatch.setattr(gitrepo, "git", lambda *a, **k: log)
    ctx = make_context(tmp_root, handler)
    base.run(Kev(ctx))
    table = _rows(ctx, "kev")
    assert table.height == 3
    assert table.get_column("first_seen_commit").null_count() == 0
    log4shell = table.filter(pl.col("cve_id") == "CVE-2021-44228").row(0, named=True)
    assert log4shell["date_added"] == date(2021, 12, 10)
    note = next(r.note for r in ledger.rows(ctx.locks_dir, "kev"))
    assert note is not None and "only in repo 0" in note and "only on cisa.gov 0" in note
    entries = locks.load(ctx.locks_dir, "kev").entries
    assert any(e.url.endswith(f"/{commit}/known_exploited_vulnerabilities.json") for e in entries)


def test_the_first_appearance_is_the_oldest_adding_commit() -> None:
    log = (
        "commit aaa 2025-01-27T16:28:08-06:00\n"
        '+        "cveID": "CVE-2021-44228",\n'
        "commit bbb 2025-03-01T10:00:00+00:00\n"
        '+        "cveID": "CVE-2021-44228",\n'
        '+        "cveID": "CVE-2026-0001",\n'
    )
    first = first_seen_from_log(log)
    assert first["CVE-2021-44228"] == datetime(2025, 1, 27, 22, 28, 8, tzinfo=UTC)
    assert first["CVE-2026-0001"] == datetime(2025, 3, 1, 10, 0, tzinfo=UTC)


# EPSS.


def test_epss_reads_the_header_and_the_headerless_format() -> None:
    model, day = read_header("#model_version:v2026.06.15,score_date:2026-11-06T12:00:23Z")
    assert model == "v2026.06.15" and day == date(2026, 11, 6)
    scores, model, day = read_scores(fixture_bytes("epss_scores-2021-04-14.csv.gz"), date(2021, 4, 14))
    assert model is None and day == date(2021, 4, 14)
    assert scores.get_column("percentile").null_count() == scores.height


def test_epss_keeps_only_the_registered_offsets_and_daily_kev(
    tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "HEAD":
            ok = request.url.path.endswith("2026-11-06.csv.gz")
            return httpx.Response(200 if ok else 404)
        if request.url.path.endswith("2026-11-06.csv.gz"):
            return httpx.Response(200, content=fixture_bytes("epss_scores-2026-11-06.csv.gz"))
        return httpx.Response(404)

    ctx = make_context(tmp_root, handler)
    ctx.config["sources"]["epss"]["first_day"] = "2026-11-05"
    scores, _, _ = read_scores(fixture_bytes("epss_scores-2026-11-06.csv.gz"), date(2026, 11, 6))
    ids = scores.get_column("cve_id").to_list()
    # Plant publication dates so each offset and a non offset appear once, and one KEV entry.
    published = {
        ids[0]: date(2026, 11, 6),
        ids[1]: date(2026, 11, 5),
        ids[2]: date(2026, 10, 7),
        ids[3]: date(2026, 10, 1),
        ids[4]: date(2019, 11, 6),
    }
    ctx.bronze.write(
        "cve_records",
        frame(
            "cve_records",
            [
                {
                    "cve_id": cve,
                    "date_published": datetime(d.year, d.month, d.day, 9, tzinfo=UTC),
                    "snapshot_at": WHEN,
                    "record_digest": cve,
                    "problem_cwes": [],
                }
                for cve, d in published.items()
            ],
        ),
        "planted",
    )
    ctx.bronze.write("kev", frame("kev", [{"cve_id": ids[5], "catalog_version": "x", "cwes": []}]), "planted")
    base.run(Epss(ctx))
    kept = _rows(ctx, "epss_offsets").sort("cve_id")
    got = {(r["cve_id"], r["offset_days"]) for r in kept.iter_rows(named=True)}
    assert got == {(ids[0], 0), (ids[1], 1), (ids[2], 30), (ids[5], -1)}
    assert set(kept.get_column("model_version").to_list()) == {"v2026.06.15"}
    rows = list(ledger.rows(ctx.locks_dir, "epss"))
    assert [r.window for r in rows] == ["month 2026-11 days 2026-11-05 to 2026-11-06"]
    assert rows[0].status == "ok" and "missing 2026-11-05" in (rows[0].note or "")
    # The day found missing is not asked for again, and the day read is in the lock.
    again = Epss(make_context(tmp_root, handler))
    again.cfg["first_day"] = "2026-11-05"
    assert list(again.units()) == []


def test_epss_falls_back_to_the_api_time_series(tmp_root: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "empiricalsecurity" in str(request.url):
            raise httpx.ConnectError("unreachable", request=request)
        return httpx.Response(200, content=fixture_bytes("epss_api_time_series.json.gz", unzip=True))

    ctx = make_context(tmp_root, handler)
    ctx.bronze.write(
        "kev", frame("kev", [{"cve_id": "CVE-2021-44228", "catalog_version": "x", "cwes": []}]), "planted"
    )
    base.run(Epss(ctx))
    kept = _rows(ctx, "epss_offsets")
    assert kept.height > 1 and set(kept.get_column("offset_days").to_list()) == {-1}
    note = next(r.note for r in ledger.rows(ctx.locks_dir, "epss"))
    assert note is not None and "api.first.org" in note


# OSV, CWE and the registries.


def test_osv_reads_each_advisory_with_its_database(tmp_root: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "/crates.io/" in request.url.path:
            return httpx.Response(
                200, content=fixture_bytes("osv_crates.zip"), headers={"x-goog-generation": "1"}
            )
        return httpx.Response(200, content=b"PK\x05\x06" + b"\x00" * 18)

    ctx = make_context(tmp_root, handler)
    base.run(Osv(ctx))
    table = _rows(ctx, "osv_advisories")
    assert table.height == 3
    assert set(table.get_column("ecosystem").to_list()) == {"crates.io"}
    assert set(table.get_column("source_db").to_list()) == {"GHSA"}
    assert source_db("RUSTSEC-2024-0001") == "RUSTSEC" and source_db("MAL-2025-1") == "MAL"


def test_cwe_catalog_with_parents_in_the_research_view(tmp_root: Path) -> None:
    import zipfile

    with zipfile.ZipFile(Path(__file__).parent / "fixtures" / "cwec_latest.xml.zip") as z:
        xml = z.read(z.namelist()[0])
    rows, info = parse_catalog(xml)
    by_id = {r["cwe_id"]: r for r in rows}
    assert by_id["CWE-79"]["abstraction"] == "Base" and "CWE-74" in by_id["CWE-79"]["parents"]
    assert by_id["CWE-16"]["abstraction"] == "Grouping"
    assert info.get("Version")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=fixture_bytes("cwec_latest.xml.zip"))

    ctx = make_context(tmp_root, handler)
    base.run(Cwe(ctx))
    assert _rows(ctx, "cwe").height == len(rows)


def test_a_registry_refusal_is_a_result_not_a_crash(tmp_root: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "sec.gov" in str(request.url):
            return httpx.Response(403, content=fixture_bytes("edgar_refusal.html.gz", unzip=True))
        return httpx.Response(200, content=fixture_bytes("gleif_velloran.json.gz", unzip=True))

    ctx = make_context(tmp_root, handler)
    summary = base.run(Registries(ctx))
    assert summary.refused == ["edgar company_tickers 2026-11-08"]
    checks = name_check(ctx.locks_dir)
    assert checks["edgar company_tickers"]["status"] == "refused"
    assert "0 with the name" in checks["gleif legalName Velloran Systems"]["note"]
    assert gleif_matches(
        {"data": [{"attributes": {"entity": {"legalName": {"name": "VELLORAN SYSTEMS OY"}}}}]},
        "Velloran Systems",
    )


# The repository sources: their parsers on recorded files, and the log pass on a real repository.


def test_ghsa_and_vulnrichment_records_on_recorded_files() -> None:
    advisory = json.loads(fixture_bytes("ghsa_GHSA-jfh8-c2jp-5v3q.json.gz", unzip=True))
    row = ghsa_row(advisory, None)
    assert row["ghsa_id"] == "GHSA-jfh8-c2jp-5v3q" and row["cve_ids"] == ["CVE-2021-44228"]
    assert row["severity"] == "CRITICAL" and "CWE-502" in row["cwe_ids"]
    record = json.loads(fixture_bytes("vulnrichment_CVE-2021-44228.json.gz", unzip=True))
    vr = vulnrichment_row(record, WHEN)
    assert vr["cve_id"] == "CVE-2021-44228"
    assert vr["ssvc_exploitation"] == "active" and vr["ssvc_automatable"] == "yes"
    assert vr["ssvc_technical_impact"] == "total" and vr["last_modified"] is not None


def test_metasploit_references_in_ruby_and_python() -> None:
    ruby = "'References' => [\n  [ 'CVE', '2021-44228' ],\n  ['URL', 'https://example.invalid']\n]"
    python = "'references': [{'type': 'cve', 'ref': '2020-1472'}, {'type': 'url', 'ref': 'x'}]"
    assert module_cves(ruby) == ["CVE-2021-44228"]
    assert module_cves(python) == ["CVE-2020-1472"]
    assert module_cves("no references here") == []


def test_one_log_pass_dates_every_path_by_its_oldest_addition(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def run(*args: str, when: str | None = None) -> None:
        env = {
            "GIT_AUTHOR_DATE": when or "",
            "GIT_COMMITTER_DATE": when or "",
            "HOME": str(tmp_path),
            "PATH": "/usr/bin:/bin",
        }
        subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            env={k: v for k, v in env.items() if v},
        )

    run("init", "-q")
    run("config", "user.email", "test@example.invalid")
    run("config", "user.name", "test")
    (repo / "modules").mkdir()
    (repo / "modules" / "a.rb").write_text("['CVE', '2021-1']")
    run("add", ".")
    run("commit", "-qm", "a", when="2020-01-01T00:00:00+00:00")
    (repo / "modules" / "b.rb").write_text("['CVE', '2022-2']")
    (repo / "modules" / "a.rb").write_text("['CVE', '2021-1'] changed")
    run("add", ".")
    run("commit", "-qm", "b", when="2021-06-01T00:00:00+00:00")
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    _, first = gitrepo.first_added(repo, head, ["modules"])
    assert first["modules/a.rb"][1] == datetime(2020, 1, 1, tzinfo=UTC)
    assert first["modules/b.rb"][1] == datetime(2021, 6, 1, tzinfo=UTC)


def test_a_commit_with_an_unset_clock_does_not_date_a_file() -> None:
    log = (
        "commit new 2024-02-01T00:00:00+00:00\nhttp/cves/2024/CVE-2024-1380.yaml\n"
        "commit old 1970-01-01T00:00:00+00:00\nhttp/cves/2024/CVE-2024-1380.yaml\n"
    )
    first = gitrepo.parse_first_added(log)
    assert first["http/cves/2024/CVE-2024-1380.yaml"] == ("new", datetime(2024, 2, 1, tzinfo=UTC))


# The filers.


def test_filers_are_grouped_by_the_first_rule_their_types_meet() -> None:
    assert group_for("mitre", ["N/A"]) == "MITRE"
    assert group_for("certcc", ["CERT"]) == "national CERT"
    assert group_for("Leonardo", ["Vendor", "CERT"]) == "vendor"
    assert group_for("VulDB", ["Researcher"]) == "research or bug bounty platform"
    assert (
        group_for("Patchstack", ["Bug Bounty Provider", "Vendor", "Researcher"])
        == "research or bug bounty platform"
    )
    assert group_for("apache", ["Vendor", "Open Source"]) == "open source project"
    assert group_for("adobe", ["Vendor"]) == "vendor"
    assert group_for("hosted", ["Hosted Service"]) == "other"


def test_the_filer_file_counts_listed_and_unlisted_filers() -> None:
    cnas = json.loads(fixture_bytes("cnas_sample.json.gz", unzip=True))
    data = build(
        cnas, {"adobe": 10, "VulDB": 5, "flexera": 2}, read_on=date(2026, 11, 8), source={"reachable": True}
    )
    assert data["filers"]["adobe"]["group"] == "vendor" and data["filers"]["adobe"]["cves"] == 10
    assert data["filers"]["flexera"]["listed"] is False
    assert sum(g["cves"] for g in data["groups"].values()) == 17
    unreachable = build(
        None, {"mitre": 3, "jpcert": 1}, read_on=date(2026, 11, 8), source={"reachable": False}
    )
    assert unreachable["filers"]["mitre"]["group"] == "MITRE"
    assert unreachable["filers"]["jpcert"]["group"] == "national CERT"


def test_stored_text_raw_files_round_trip(tmp_path: Path) -> None:
    sha, size = kev.write_text(tmp_path / "x.txt.gz", "commit a 2025-01-01T00:00:00Z\n")
    assert kev.read_text(tmp_path / "x.txt.gz").startswith("commit a")
    assert size == len(b"commit a 2025-01-01T00:00:00Z\n")
    with gzip.open(tmp_path / "x.txt.gz", "rb") as h:
        import hashlib

        assert hashlib.sha256(h.read()).hexdigest() == sha
