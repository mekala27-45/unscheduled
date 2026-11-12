"""The repository sources end to end against local repositories served over file://.

Each test builds a small repository with dated commits, points the source at it, and runs the real
fetcher: the head read with ls-remote, the clone without blobs (the source repository allows
filters, as GitHub does), the one log pass, the sparse checkout and the parse to bronze. The
recorded GHSA and Vulnrichment files are the records the publishers served on 8 November 2026.
"""

from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from unscheduled_sources import base, ledger
from unscheduled_sources.exploits import Exploits
from unscheduled_sources.ghsa import Ghsa
from unscheduled_sources.vulnrichment import Vulnrichment

from tests.sources.conftest import fixture_bytes, make_context


def _git(repo: Path, *args: str, when: str | None = None) -> None:
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1"}
    if when:
        env.update(GIT_AUTHOR_DATE=when, GIT_COMMITTER_DATE=when)
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


def make_repo(path: Path, commits: list[tuple[str, dict[str, bytes]]]) -> str:
    """A repository with one commit per (date, files) step; returns its file:// URL."""
    path.mkdir(parents=True)
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "test@example.invalid")
    _git(path, "config", "user.name", "test")
    _git(path, "config", "uploadpack.allowFilter", "true")
    _git(path, "config", "uploadpack.allowAnySHA1InWant", "true")
    for when, files in commits:
        for name, data in files.items():
            target = path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        _git(path, "add", "-A")
        _git(path, "commit", "-qm", f"commit at {when}", when=when)
    return f"file://{path}"


def test_exploit_signals_from_both_repositories(tmp_root: Path, tmp_path: Path) -> None:
    msf = make_repo(
        tmp_path / "msf",
        [
            (
                "2021-12-11T00:00:00+00:00",
                {"modules/exploits/multi/log4shell.rb": b"'References' => [['CVE', '2021-44228']]"},
            ),
            (
                "2022-01-05T00:00:00+00:00",
                {
                    "modules/auxiliary/zerologon.py": b"'references': [{'type': 'cve', 'ref': '2020-1472'}]",
                    "README.md": b"metasploit",
                },
            ),
        ],
    )
    nuclei = make_repo(
        tmp_path / "nuclei",
        [
            ("2021-12-12T00:00:00+00:00", {"cves/2021/CVE-2021-44228.yaml": b"id: CVE-2021-44228"}),
            ("2022-02-01T00:00:00+00:00", {"http/misconfiguration/x.yaml": b"id: x", "README.md": b"nuclei"}),
        ],
    )
    # The 2023 move: the template leaves cves/ for http/cves/ and keeps its first date.
    moved = tmp_path / "nuclei"
    (moved / "http" / "cves" / "2021").mkdir(parents=True)
    (moved / "cves" / "2021" / "CVE-2021-44228.yaml").rename(
        moved / "http" / "cves" / "2021" / "CVE-2021-44228.yaml"
    )
    _git(moved, "add", "-A")
    _git(moved, "commit", "-qm", "move", when="2023-03-03T09:30:28+00:00")
    ctx = make_context(tmp_root)
    ctx.config["sources"]["exploits"]["metasploit"]["git"] = msf
    ctx.config["sources"]["exploits"]["nuclei"]["git"] = nuclei
    base.run(Exploits(ctx))
    rows = {(r["cve_id"], r["source"]): r for r in ctx.bronze.read("exploit_signals").iter_rows(named=True)}
    assert set(rows) == {
        ("CVE-2021-44228", "metasploit"),
        ("CVE-2020-1472", "metasploit"),
        ("CVE-2021-44228", "nuclei"),
    }
    assert rows[("CVE-2021-44228", "metasploit")]["first_seen"] == datetime(2021, 12, 11, tzinfo=UTC)
    assert rows[("CVE-2020-1472", "metasploit")]["first_seen"] == datetime(2022, 1, 5, tzinfo=UTC)
    assert rows[("CVE-2021-44228", "nuclei")]["path"] == "http/cves/2021/CVE-2021-44228.yaml"
    assert rows[("CVE-2021-44228", "nuclei")]["first_seen"] == datetime(2021, 12, 12, tzinfo=UTC)
    # The clones are removed once parsed; only the digests of the log and tree files stay.
    assert not (ctx.cache_dir / "metasploit-framework").exists()


def test_vulnrichment_points_and_first_addition(tmp_root: Path, tmp_path: Path) -> None:
    record = fixture_bytes("vulnrichment_CVE-2021-44228.json.gz", unzip=True)
    url = make_repo(
        tmp_path / "vulnrichment",
        [
            ("2024-05-01T12:00:00+00:00", {"README.md": b"vulnrichment"}),
            ("2024-06-02T12:00:00+00:00", {"2021/44xxx/CVE-2021-44228.json": record}),
        ],
    )
    ctx = make_context(tmp_root)
    ctx.config["sources"]["vulnrichment"]["git"] = url
    base.run(Vulnrichment(ctx))
    row = ctx.bronze.read("vulnrichment").row(0, named=True)
    assert row["cve_id"] == "CVE-2021-44228"
    assert row["first_added"] == datetime(2024, 6, 2, 12, tzinfo=UTC)
    assert row["ssvc_exploitation"] == "active"


def test_ghsa_with_and_without_the_history(tmp_root: Path, tmp_path: Path) -> None:
    advisory = fixture_bytes("ghsa_GHSA-jfh8-c2jp-5v3q.json.gz", unzip=True)
    path = "advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"
    url = make_repo(
        tmp_path / "advisory-database",
        [
            ("2022-04-01T00:00:00+00:00", {"README.md": b"advisories"}),
            ("2022-04-14T00:00:00+00:00", {path: advisory}),
        ],
    )
    with_history = make_context(tmp_root / "a")
    with_history.config["sources"]["ghsa"].update(git=url, history="always")
    base.run(Ghsa(with_history))
    row = with_history.bronze.read("ghsa").row(0, named=True)
    assert row["ghsa_id"] == "GHSA-jfh8-c2jp-5v3q"
    assert row["first_seen_commit"] == datetime(2022, 4, 14, tzinfo=UTC)

    shallow = make_context(tmp_root / "b")
    shallow.config["sources"]["ghsa"].update(git=url, history="never")
    base.run(Ghsa(shallow))
    assert shallow.bronze.read("ghsa").row(0, named=True)["first_seen_commit"] is None
    note = next(r.note for r in ledger.rows(shallow.locks_dir, "ghsa"))
    assert note is not None and "first_seen_commit not computed" in note
