"""The commands that hand off to the pipeline scripts, and the sync from the command line."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner
from unscheduled_api.services import Services
from unscheduled_api.settings import Settings
from unscheduled_cli import main as cli_main
from unscheduled_cli.main import create_cli


@pytest.fixture
def fake_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name in (
        "probe_hosts.py",
        "fetch.py",
        "build_lake.py",
        "build_manifest.py",
        "check_published_numbers.py",
    ):
        (scripts / name).write_text(
            "import json, pathlib, sys\n"
            "pathlib.Path(sys.argv[0]).with_suffix('.ran').write_text(json.dumps(sys.argv[1:]))\n",
            encoding="utf-8",
        )
    monkeypatch.setattr(cli_main.paths, "root", lambda: tmp_path)
    return tmp_path


def ran(root: Path, name: str) -> list[str]:
    data: list[str] = json.loads((root / "scripts" / name).with_suffix(".ran").read_text(encoding="utf-8"))
    return data


def cli() -> typer.Typer:
    return create_cli(lambda: Services.build(Settings.from_env({})))


def test_fetch_passes_its_sources_and_options_to_the_fetch_script(fake_root: Path) -> None:
    result = CliRunner().invoke(cli(), ["fetch", "kev", "cvelist", "--budget-minutes", "30"])
    assert result.exit_code == 0, result.output
    assert ran(fake_root, "fetch.py") == ["kev", "cvelist", "--budget-minutes", "30"]


def test_probe_and_build_run_their_scripts(fake_root: Path) -> None:
    assert CliRunner().invoke(cli(), ["probe", "--skip-nvd-burst"]).exit_code == 0
    assert ran(fake_root, "probe_hosts.py") == ["--skip-nvd-burst"]
    assert CliRunner().invoke(cli(), ["build", "--keep-work"]).exit_code == 0
    assert ran(fake_root, "build_lake.py") == ["--keep-work"]


def test_render_assembles_the_manifest_then_renders_or_checks(fake_root: Path) -> None:
    assert CliRunner().invoke(cli(), ["render"]).exit_code == 0
    assert ran(fake_root, "build_manifest.py") == [] and ran(fake_root, "check_published_numbers.py") == [
        "--write"
    ]
    assert CliRunner().invoke(cli(), ["render", "--check"]).exit_code == 0
    assert ran(fake_root, "check_published_numbers.py") == []


def test_a_missing_script_is_named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main.paths, "root", lambda: tmp_path)
    result = CliRunner().invoke(cli(), ["build"])
    assert result.exit_code == 2 and "build_lake.py" in result.stderr


def test_a_data_command_without_a_database_prints_the_problem_and_exits_one() -> None:
    result = CliRunner().invoke(cli(), ["cve", "CVE-2021-90001"])
    assert result.exit_code == 1
    problem = json.loads(result.stderr[: result.stderr.rindex("}") + 1])
    assert (
        problem["type"].endswith("#problem-database-unavailable")
        and problem["instance"] == "unsched cve CVE-2021-90001"
    )


def test_a_malformed_date_is_an_invalid_request() -> None:
    result = CliRunner().invoke(cli(), ["cve", "CVE-2021-90001", "--as-of", "soon"])
    assert result.exit_code == 1 and "#problem-invalid-request" in result.stderr


def test_the_sync_runs_step_by_step_until_done(shared: Services) -> None:
    result = CliRunner().invoke(create_cli(lambda: shared), ["sync", "--until-done"])
    assert result.exit_code == 0, result.output
    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert lines[-1]["status"] in {"done", "current"} and lines[-1]["statement"]
