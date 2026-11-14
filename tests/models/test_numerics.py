"""The numeric pins: one source, the same values in the models workflow and in reset and rederive, and
a full exploitation run that refuses to start without them."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from unscheduled_models import numerics

from scripts import reset_and_rederive, train_rank

ROOT = Path(__file__).resolve().parents[2]


def test_the_models_workflow_sets_exactly_the_pins() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "models.yml").read_text(encoding="utf-8"))
    env = workflow["jobs"]["fit"]["env"]
    assert {name: str(env.get(name)) for name in numerics.PINS} == numerics.PINS


def test_the_rederive_steps_run_with_the_pins(tmp_path: Path) -> None:
    env = reset_and_rederive.step_env(tmp_path)
    assert numerics.missing(env) == {}
    assert env["UNSCHED_ROOT"] == str(tmp_path)


def test_missing_names_each_absent_or_different_pin() -> None:
    assert numerics.missing(numerics.PINS) == {}
    partial = {**numerics.PINS, "OPENBLAS_NUM_THREADS": "4"}
    partial.pop("OPENBLAS_CORETYPE")
    assert numerics.missing(partial) == {
        "OPENBLAS_CORETYPE": "Haswell",
        "OPENBLAS_NUM_THREADS": "1",
    }


def test_a_full_exploitation_run_refuses_to_start_without_the_pins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in numerics.PINS:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(SystemExit, match="numeric pins are not set"):
        train_rank.main(["--sets", str(tmp_path)], root=tmp_path)


def test_the_description_reads_the_libraries_back() -> None:
    described = numerics.describe()
    assert set(described) == {"processor", "pins", "openblas", "numpy_dispatch"}
    assert all("architecture" in lib for lib in described["openblas"])
