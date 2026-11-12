"""The statistics of the backlog questions, held to the libraries that define them."""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.metrics import cohen_kappa_score, roc_auc_score
from statsmodels.stats.multitest import multipletests
from unscheduled_analysis import stats

RNG = np.random.default_rng(20261112)


@pytest.mark.parametrize("weights", [None, "linear", "quadratic"])
def test_kappa_matches_scikit_learn(weights: stats.Weights) -> None:
    for _ in range(25):
        a = RNG.integers(0, 4, size=200)
        b = np.where(RNG.random(200) < 0.6, a, RNG.integers(0, 4, size=200))
        expected = cohen_kappa_score(a, b, labels=[0, 1, 2, 3], weights=weights)
        assert stats.cohen_kappa(a, b, k=4, weights=weights) == pytest.approx(expected, abs=1e-12)


def test_kappa_of_a_stack_matches_kappa_of_each() -> None:
    mats = np.stack([stats.confusion(RNG.integers(0, 3, 50), RNG.integers(0, 3, 50), 3) for _ in range(10)])
    batch = stats.kappa_batch(mats, "quadratic")
    each = [stats.kappa_from_confusion(m, "quadratic") for m in mats]
    assert np.allclose(batch, each)


def test_kappa_by_hand_and_at_the_edges() -> None:
    # 20 and 15 agreements of 50, marginals 25 and 25 against 30 and 20: (0.7 - 0.5) / 0.5.
    m = np.array([[20.0, 5.0], [10.0, 15.0]])
    assert stats.kappa_from_confusion(m) == pytest.approx(0.4)
    assert stats.cohen_kappa([0, 1, 2], [0, 1, 2], k=3) == pytest.approx(1.0)
    assert np.isnan(stats.kappa_from_confusion(np.zeros((3, 3))))
    with pytest.raises(ValueError, match="outside"):
        stats.confusion([0, 3], [0, 1], 3)


def test_benjamini_hochberg_matches_statsmodels() -> None:
    for _ in range(25):
        p = RNG.random(RNG.integers(1, 30)) ** 2
        reject, adjusted = stats.benjamini_hochberg(list(p), alpha=0.05)
        sm_reject, sm_adjusted, _, _ = multipletests(p, alpha=0.05, method="fdr_bh")
        assert reject == [bool(x) for x in sm_reject]
        assert np.allclose(adjusted, sm_adjusted)
    assert stats.benjamini_hochberg([]) == ([], [])
    with pytest.raises(ValueError):
        stats.benjamini_hochberg([0.2, 1.5])


def test_auc_matches_scikit_learn_with_ties() -> None:
    for _ in range(25):
        y = RNG.integers(0, 2, size=120)
        s = np.round(RNG.random(120) + 0.3 * y, 1)
        if y.min() == y.max():
            continue
        assert stats.auc(y, s) == pytest.approx(roc_auc_score(y, s), abs=1e-12)
    assert np.isnan(stats.auc([1, 1], [0.2, 0.4]))


def test_auc_refuses_a_missing_label() -> None:
    with pytest.raises(ValueError, match="missing"):
        stats.auc(np.array([1.0, np.nan, 0.0]), [0.2, 0.4, 0.1])
    with pytest.raises(ValueError, match="0 or 1"):
        stats.auc([2, 0], [0.2, 0.4])


def test_kaplan_meier_median() -> None:
    # Nothing censored: the median is the middle event time.
    assert stats.km_median([1, 2, 3, 4, 5], [True] * 5) == 3.0
    # Censoring at 2 and 3 lifts the curve: S(1) = 4/5, S(4) = 4/5 * 1/2 = 0.4, so the median is 4.
    assert stats.km_median([1, 2, 3, 4, 5], [True, False, False, True, True]) == 4.0
    # When the curve never falls to one half there is no median.
    assert stats.km_median([5, 6, 7], [True, False, False]) is None
    assert stats.km_median([], []) is None
