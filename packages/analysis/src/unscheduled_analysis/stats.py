"""The statistics the backlog questions use, written here and tested against the libraries.

Cohen's kappa (unweighted, linear and quadratic weights) is computed from a confusion matrix, so a
bootstrap can add matrices instead of recounting labels; tests/analysis holds it to scikit-learn's
cohen_kappa_score. Benjamini-Hochberg is held to statsmodels' fdr_bh, the area under the ROC curve
to scikit-learn's roc_auc_score, and the Kaplan-Meier median to a direct count where nothing is
censored.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

import numpy as np
from numpy.typing import NDArray

Weights = Literal["linear", "quadratic"] | None


def confusion(
    a: Sequence[int] | NDArray[np.int64], b: Sequence[int] | NDArray[np.int64], k: int
) -> NDArray[np.float64]:
    """Counts of each pair of categories 0..k-1, rows from a, columns from b."""
    x = np.asarray(a, dtype=np.int64)
    y = np.asarray(b, dtype=np.int64)
    if x.shape != y.shape:
        raise ValueError("the two ratings differ in length")
    if x.size and (x.min() < 0 or y.min() < 0 or x.max() >= k or y.max() >= k):
        raise ValueError("a rating is outside 0 to k-1")
    out = np.zeros((k, k), dtype=np.float64)
    np.add.at(out, (x, y), 1.0)
    return out


def weight_matrix(k: int, weights: Weights) -> NDArray[np.float64]:
    i, j = np.indices((k, k))
    out: NDArray[np.float64]
    if weights is None:
        out = (i != j).astype(np.float64)
    elif weights == "linear":
        out = np.abs(i - j).astype(np.float64)
    elif weights == "quadratic":
        out = ((i - j) ** 2).astype(np.float64)
    else:
        raise ValueError(f"unknown weights {weights!r}")
    return out


def kappa_from_confusion(matrix: NDArray[np.float64], weights: Weights = None) -> float:
    """Cohen's kappa of one confusion matrix: 1 minus observed over expected weighted disagreement."""
    m = np.asarray(matrix, dtype=np.float64)
    n = m.sum()
    if n == 0:
        return float("nan")
    w = weight_matrix(m.shape[0], weights)
    expected = np.outer(m.sum(axis=1), m.sum(axis=0)) / n
    denominator = float((w * expected).sum())
    if denominator == 0:
        return float("nan")
    return 1.0 - float((w * m).sum()) / denominator


def kappa_batch(matrices: NDArray[np.float64], weights: Weights = None) -> NDArray[np.float64]:
    """Kappa of each matrix in a stack of shape (r, k, k), for bootstrap replicates."""
    m = np.asarray(matrices, dtype=np.float64)
    n = m.sum(axis=(1, 2))
    w = weight_matrix(m.shape[1], weights)
    rows = m.sum(axis=2)
    cols = m.sum(axis=1)
    with np.errstate(divide="ignore", invalid="ignore"):
        expected = rows[:, :, None] * cols[:, None, :] / n[:, None, None]
        observed = (w[None] * m).sum(axis=(1, 2))
        denominator = (w[None] * expected).sum(axis=(1, 2))
        out = 1.0 - observed / denominator
    out[(n == 0) | (denominator == 0)] = np.nan
    return out


def cohen_kappa(
    a: Sequence[int] | NDArray[np.int64],
    b: Sequence[int] | NDArray[np.int64],
    k: int | None = None,
    weights: Weights = None,
) -> float:
    x = np.asarray(a, dtype=np.int64)
    y = np.asarray(b, dtype=np.int64)
    size = int(k if k is not None else max(int(x.max(initial=0)), int(y.max(initial=0))) + 1)
    return kappa_from_confusion(confusion(x, y, size), weights)


def benjamini_hochberg(pvalues: Sequence[float], alpha: float = 0.05) -> tuple[list[bool], list[float]]:
    """Which hypotheses to reject at false discovery rate alpha, and the adjusted p-values."""
    p = np.asarray(pvalues, dtype=np.float64)
    m = p.size
    if m == 0:
        return [], []
    if np.any((p < 0) | (p > 1) | np.isnan(p)):
        raise ValueError("p-values lie in 0 to 1")
    order = np.argsort(p, kind="mergesort")
    ranked = p[order] * m / np.arange(1, m + 1)
    adjusted_sorted = np.minimum.accumulate(ranked[::-1])[::-1]
    adjusted = np.empty(m)
    adjusted[order] = np.minimum(adjusted_sorted, 1.0)
    return [bool(x) for x in adjusted <= alpha], [float(x) for x in adjusted]


def auc(labels: Sequence[int] | NDArray[np.int64], scores: Sequence[float] | NDArray[np.float64]) -> float:
    """The area under the ROC curve: the chance a positive outscores a negative, ties counting half."""
    raw = np.asarray(labels)
    if raw.dtype.kind == "f" and np.isnan(raw).any():
        raise ValueError("a label is missing; every unit needs a 0 or a 1")
    y = raw.astype(np.int64)
    if y.size and (y.min() < 0 or y.max() > 1):
        raise ValueError("labels are 0 or 1")
    s = np.asarray(scores, dtype=np.float64)
    n_pos = int(y.sum())
    n_neg = int(y.size - n_pos)
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    ranks = _average_ranks(s)
    return float((ranks[y == 1].sum() - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))


def _average_ranks(values: NDArray[np.float64]) -> NDArray[np.float64]:
    """Ranks from 1, ties sharing the mean of the ranks they span."""
    order = np.argsort(values, kind="mergesort")
    _, inverse, counts = np.unique(values[order], return_inverse=True, return_counts=True)
    ends = np.cumsum(counts).astype(np.float64)
    mean_rank = ends - (counts - 1) / 2.0
    ranks = np.empty(values.size, dtype=np.float64)
    ranks[order] = mean_rank[inverse]
    return ranks


def km_median(
    durations: Sequence[float] | NDArray[np.float64], observed: Sequence[bool] | NDArray[np.bool_]
) -> float | None:
    """The Kaplan-Meier median time to the event, or None when the curve never falls to one half.

    A unit whose event has not happened by the end of its follow-up is censored at that time.
    """
    t = np.asarray(durations, dtype=np.float64)
    e = np.asarray(observed, dtype=bool)
    if t.size == 0:
        return None
    times = np.unique(t[e])
    survival = 1.0
    for time in times:
        at_risk = int((t >= time).sum())
        events = int(((t == time) & e).sum())
        if at_risk == 0:
            continue
        survival *= 1.0 - events / at_risk
        if survival <= 0.5:
            return float(time)
    return None


def quantile(values: Sequence[float] | NDArray[np.float64], q: float) -> float | None:
    v = np.asarray(values, dtype=np.float64)
    v = v[~np.isnan(v)]
    if v.size == 0:
        return None
    return float(np.quantile(v, q))
