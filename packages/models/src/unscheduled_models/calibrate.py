"""Calibration of Phase 2, written here and tested against the libraries (evaluation/phase2_plan.yaml,
calibration).

Temperature scaling for a fill head: one temperature T per head, the logits divided by T before the
softmax, T chosen on development to minimize the negative log likelihood. A head here gives
probabilities, so its logits are their logarithms, which the softmax maps back to the same
probabilities at T = 1. Isotonic regression for exploitation: the pool adjacent violators fit of the
labels on the scores, a non decreasing step function, evaluated by interpolating between the fitted
points as scikit-learn's IsotonicRegression does. The expected calibration error is taken over 15
equal width bins of the top label probability, with a bootstrap interval.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.optimize import minimize_scalar

EPSILON = 1e-12
ECE_BINS = 15


def logits(proba: np.ndarray) -> np.ndarray:
    out: np.ndarray = np.log(np.clip(proba, EPSILON, 1.0))
    return out


def softmax(z: np.ndarray) -> np.ndarray:
    shifted = z - z.max(axis=1, keepdims=True)
    e = np.exp(shifted)
    out: np.ndarray = e / e.sum(axis=1, keepdims=True)
    return out


def nll(proba: np.ndarray, truth: np.ndarray) -> float:
    """The mean negative log likelihood of the true class; truth holds class positions."""
    return float(-np.mean(np.log(np.clip(proba[np.arange(len(truth)), truth], EPSILON, 1.0))))


def scale(proba: np.ndarray, temperature: float) -> np.ndarray:
    return softmax(logits(proba) / temperature)


def fit_temperature(
    proba: np.ndarray, truth: np.ndarray, bounds: tuple[float, float] = (0.05, 20.0)
) -> float:
    """The temperature that minimizes the development negative log likelihood, searched on the log
    scale between the bounds."""
    z = logits(proba)

    def loss(log_t: float) -> float:
        return nll(softmax(z / np.exp(log_t)), truth)

    result = minimize_scalar(
        loss, bounds=(np.log(bounds[0]), np.log(bounds[1])), method="bounded", options={"xatol": 1e-6}
    )
    return float(np.exp(result.x))


@dataclass
class Isotonic:
    """A fitted non decreasing step function from scores to probabilities."""

    x: np.ndarray
    y: np.ndarray

    def predict(self, scores: np.ndarray) -> np.ndarray:
        out: np.ndarray = np.interp(scores, self.x, self.y, left=self.y[0], right=self.y[-1])
        return out


def fit_isotonic(scores: np.ndarray, truth: np.ndarray, weights: np.ndarray | None = None) -> Isotonic:
    """Pool adjacent violators on the labels ordered by score. Equal scores are pooled first, so the
    fit is a function of the score; the fitted points are the distinct scores with their block values."""
    w = np.ones(len(scores)) if weights is None else np.asarray(weights, dtype=np.float64)
    order = np.argsort(scores, kind="mergesort")
    s, t, w = (
        np.asarray(scores, dtype=np.float64)[order],
        np.asarray(truth, dtype=np.float64)[order],
        w[order],
    )
    xs: list[list[float]] = []
    sums: list[float] = []
    totals: list[float] = []
    for value, label, weight in zip(s, t, w, strict=True):
        if xs and value == xs[-1][-1]:
            sums[-1] += label * weight
            totals[-1] += weight
            continue
        xs.append([value])
        sums.append(label * weight)
        totals.append(weight)
    blocks_x: list[list[float]] = []
    blocks_sum: list[float] = []
    blocks_total: list[float] = []
    for xv, sv, tv in zip(xs, sums, totals, strict=True):
        blocks_x.append(list(xv))
        blocks_sum.append(sv)
        blocks_total.append(tv)
        while len(blocks_sum) > 1 and blocks_sum[-2] / blocks_total[-2] > blocks_sum[-1] / blocks_total[-1]:
            last_sum, last_total, last_x = blocks_sum.pop(), blocks_total.pop(), blocks_x.pop()
            blocks_sum[-1] += last_sum
            blocks_total[-1] += last_total
            blocks_x[-1].extend(last_x)
    x_points, y_points = [], []
    for bx, bs, bt in zip(blocks_x, blocks_sum, blocks_total, strict=True):
        for value in bx:
            x_points.append(value)
            y_points.append(bs / bt)
    return Isotonic(np.asarray(x_points), np.asarray(y_points))


def ece(confidence: np.ndarray, correct: np.ndarray, bins: int = ECE_BINS) -> float:
    """The expected calibration error over equal width bins of the confidence: the share of rows in
    each bin times the gap between its mean confidence and its accuracy, summed."""
    confidence = np.asarray(confidence, dtype=np.float64)
    correct = np.asarray(correct, dtype=np.float64)
    edges = np.linspace(0.0, 1.0, bins + 1)
    index = np.clip(np.digitize(confidence, edges[1:-1], right=True), 0, bins - 1)
    total = 0.0
    for b in range(bins):
        mask = index == b
        if mask.any():
            total += mask.mean() * abs(confidence[mask].mean() - correct[mask].mean())
    return float(total)


def ece_interval(
    confidence: np.ndarray,
    correct: np.ndarray,
    seed: int,
    resamples: int = 2000,
    clusters: np.ndarray | None = None,
) -> tuple[float, float, float]:
    """The ECE and its 95 percent bootstrap interval, resampling rows or, when given, whole clusters."""
    rng = np.random.default_rng(seed)
    point = ece(confidence, correct)
    if clusters is None:
        draws = [rng.integers(0, len(confidence), len(confidence)) for _ in range(resamples)]
    else:
        groups: dict[object, list[int]] = {}
        for i, c in enumerate(clusters):
            groups.setdefault(c, []).append(i)
        members = [np.asarray(v) for v in groups.values()]
        draws = [
            np.concatenate([members[j] for j in rng.integers(0, len(members), len(members))])
            for _ in range(resamples)
        ]
    values = np.array([ece(confidence[d], correct[d]) for d in draws])
    return point, float(np.quantile(values, 0.025)), float(np.quantile(values, 0.975))


def top_label(proba: np.ndarray, truth: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """The confidence of the top label and whether it is right, for the ECE of a fill head."""
    return proba.max(axis=1), (proba.argmax(axis=1) == truth).astype(np.float64)
