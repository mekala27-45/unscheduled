"""The test measures: paired kappas, the clustered ECE, paired recalls, slices, and the scorer's locks."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest
from unscheduled_models import calibrate, evaluate

from scripts import score_test


def bands(n: int, seed: int) -> tuple[list[str], np.ndarray, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    keys = [f"filer-{i % 25}" for i in range(n)]
    truth = rng.integers(0, 4, n)
    good = np.where(rng.random(n) < 0.8, truth, rng.integers(0, 4, n))
    poor = np.where(rng.random(n) < 0.4, truth, rng.integers(0, 4, n))
    return keys, truth, good, poor


def test_a_better_model_wins_and_a_twin_ties() -> None:
    keys, truth, good, poor = bands(2000, 1)
    ahead = evaluate.kappa_paired(keys, truth, good, poor, 4, seed=3, resamples=300)
    assert ahead["model"]["value"] > ahead["floor"]["value"]
    assert ahead["difference"]["low"] > 0 and ahead["difference"]["p"] < 0.05
    twin = evaluate.kappa_paired(keys, truth, good, good, 4, seed=3, resamples=300)
    assert twin["difference"]["value"] == 0 and twin["difference"]["low"] == 0 == twin["difference"]["high"]


def test_the_clustered_ece_is_the_plain_one_at_its_point() -> None:
    rng = np.random.default_rng(2)
    confidence = rng.uniform(0.3, 1.0, 1500)
    correct = (rng.random(1500) < confidence * 0.9).astype(float)
    keys = [f"f{i % 30}" for i in range(1500)]
    result = evaluate.ece_clustered(keys, confidence, correct, seed=4, resamples=300)
    assert result["value"] == pytest.approx(calibrate.ece(confidence, correct))
    assert result["low"] <= result["value"] <= result["high"]


def test_recall_against_epss_names_a_tie() -> None:
    rng = np.random.default_rng(5)
    truth = (rng.random(4000) < 0.02).astype(np.int8)
    model = truth * 2.0 + rng.random(4000)
    result = evaluate.recall_paired(
        truth,
        {"model": model, "same": model.copy(), "noise": rng.random(4000)},
        seed=6,
        reference="model",
        resamples=200,
    )
    assert result["model_minus_same"]["reading"] == "tie"
    assert result["model_minus_noise"]["reading"] == "ahead"
    assert result["top"] == 200


def test_slices_correct_within_a_family() -> None:
    _keys, truth, good, poor = bands(1200, 7)
    groups = [f"g{i % 3}" for i in range(1200)] + ["tiny"] * 5
    t = [int(v) for v in truth] + [0, 1, 0, 1, 0]
    a = [int(v) for v in good] + [0, 1, 0, 1, 0]
    b = [int(v) for v in poor] + [0, 1, 0, 1, 0]

    def accuracy(tt: list[int], gg: list[int]) -> float:
        return float(np.mean([x == y for x, y in zip(tt, gg, strict=True)]))

    rows = evaluate.slice_differences(
        groups, ["g0", "g1", "g2", "tiny"], accuracy, a, b, t, seed=8, min_rows=30, resamples=200
    )
    tested = [r for r in rows if r["tested"]]
    assert len(tested) == 3 and all(r["significant"] for r in tested)
    assert rows[-1] == {"slice": "tiny", "rows": 5, "tested": False}


def test_the_scorer_refuses_before_the_freeze_and_after_one_run(tmp_path: Path) -> None:
    (tmp_path / "evaluation").mkdir()
    (tmp_path / "evaluation" / "registration.json").write_text(
        json.dumps({"stages": [{"stage": "models"}]}), encoding="utf-8"
    )
    (tmp_path / "results" / "models").mkdir(parents=True)
    with pytest.raises(SystemExit, match="not hashed"):
        score_test.main([], root=tmp_path)
    (tmp_path / "results" / "models" / "test_scoring.json").write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit, match="scored already"):
        score_test.main([], root=tmp_path)
