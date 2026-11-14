"""Calibration and conformal sets, held to scikit-learn and MAPIE on fixtures."""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.isotonic import IsotonicRegression
from unscheduled_models import calibrate, conformal


def test_isotonic_matches_scikit_learn() -> None:
    rng = np.random.default_rng(1)
    scores = np.round(rng.random(2000), 2)  # ties on purpose
    truth = (rng.random(2000) < scores**2).astype(float)
    ours = calibrate.fit_isotonic(scores, truth)
    reference = IsotonicRegression(out_of_bounds="clip").fit(scores, truth)
    probe = np.linspace(-0.1, 1.1, 301)
    assert np.allclose(ours.predict(probe), reference.predict(probe), atol=1e-12)
    assert np.all(np.diff(ours.predict(np.sort(scores))) >= 0)


def test_temperature_cools_an_overconfident_head() -> None:
    rng = np.random.default_rng(2)
    n, k = 4000, 4
    truth = rng.integers(0, k, n)
    z = rng.normal(size=(n, k))
    z[np.arange(n), truth] += 1.0
    honest = calibrate.softmax(z)
    loud = calibrate.softmax(z * 3.0)
    t_loud = calibrate.fit_temperature(loud, truth)
    assert t_loud == pytest.approx(3.0, rel=0.15)
    assert calibrate.nll(calibrate.scale(loud, t_loud), truth) < calibrate.nll(loud, truth)
    assert calibrate.fit_temperature(honest, truth) == pytest.approx(1.0, rel=0.15)
    assert np.allclose(calibrate.scale(honest, 1.0), honest, atol=1e-9)


def test_the_ece_of_a_known_case() -> None:
    confidence = np.array([0.95, 0.95, 0.95, 0.95, 0.55, 0.55])
    correct = np.array([1, 1, 1, 0, 1, 0])
    # Bin of 0.95: 4 rows, accuracy 0.75, gap 0.2; bin of 0.55: 2 rows, accuracy 0.5, gap 0.05.
    assert calibrate.ece(confidence, correct) == pytest.approx(4 / 6 * 0.2 + 2 / 6 * 0.05)
    point, low, high = calibrate.ece_interval(confidence, correct, seed=3, resamples=200)
    assert low <= point <= high


class Passthrough(ClassifierMixin, BaseEstimator):
    """A fitted classifier whose features are already its probabilities, for MAPIE's prefit mode."""

    def fit(self, x: np.ndarray, y: np.ndarray) -> Passthrough:
        self.classes_ = np.unique(y)
        return self

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        return np.asarray(x)

    def predict(self, x: np.ndarray) -> np.ndarray:
        return self.classes_[np.argmax(x, axis=1)]


def fixture(n: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    z = rng.normal(size=(n, 4))
    truth = rng.integers(0, 4, n)
    z[np.arange(n), truth] += 1.2
    return calibrate.softmax(z), truth


def test_aps_matches_mapie() -> None:
    from mapie.classification import SplitConformalClassifier

    cal_p, cal_y = fixture(1500, 4)
    test_p, test_y = fixture(800, 5)
    ours = conformal.fit(cal_p, cal_y, seed=11)
    estimator = Passthrough().fit(cal_p, np.arange(4).repeat(1))
    mapie = SplitConformalClassifier(
        estimator=estimator, confidence_level=0.9, conformity_score="aps", prefit=True, random_state=11
    )
    mapie.conformalize(cal_p, cal_y)
    _, mapie_sets = mapie.predict_set(test_p, conformity_score_params={"include_last_label": True})
    assert np.array_equal(ours.predict(test_p), mapie_sets[:, :, 0])
    result = conformal.coverage(ours.predict(test_p), test_y)
    # Including the class that crosses the threshold covers a little more than the target.
    assert 0.88 <= result["coverage"] <= 0.98 and 1.0 <= result["mean_size"] <= 4.0


def test_the_threshold_and_the_sets_on_a_hand_case() -> None:
    assert conformal.threshold(np.array([0.1, 0.2, 0.3, 0.4]), 0.5) == 0.3
    assert conformal.threshold(np.array([0.1, 0.2]), 0.9) == 0.2
    member = conformal.sets(np.array([[0.6, 0.3, 0.1], [0.2, 0.5, 0.3]]), 0.7)
    assert member.tolist() == [[True, True, False], [False, True, True]]
