"""The cluster bootstrap by filer, 2,000 resamples, 95 percent percentile intervals.

CVEs from one filer share a scoring practice, a template and an editor, so they are not independent
draws; the filer is the unit that is resampled. Each replicate draws as many filers as there are,
with replacement, and takes every CVE of each filer drawn. Filers are sorted by name before the
draw and the generator is seeded, so an interval is the same on every machine and under every
PYTHONHASHSEED.

Most statistics here are sums over filers (a share is a sum of hits over a sum of units; a kappa
is computed from a sum of confusion matrices), so a replicate is a matrix product of the draw
counts with the per filer sums, which is exact and fast. Anything else goes through generic(),
which rebuilds each replicate's units.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

RESAMPLES = 2000
LEVEL = 0.95
SEED = 20261108


@dataclass(frozen=True)
class Interval:
    estimate: float
    low: float
    high: float
    resamples: int
    clusters: int
    units: int

    def as_dict(self) -> dict[str, float | int]:
        return {
            "value": self.estimate,
            "low": self.low,
            "high": self.high,
            "resamples": self.resamples,
            "clusters": self.clusters,
            "n": self.units,
        }


def clusters_of(keys: Sequence[str]) -> tuple[list[str], NDArray[np.int64]]:
    """The sorted distinct clusters and each unit's index into them."""
    names = sorted(set(keys))
    index = {k: i for i, k in enumerate(names)}
    return names, np.fromiter((index[k] for k in keys), dtype=np.int64, count=len(keys))


def draws(n_clusters: int, resamples: int = RESAMPLES, seed: int = SEED) -> NDArray[np.float64]:
    """How many times each cluster is drawn in each replicate, shape (resamples, clusters)."""
    if n_clusters == 0:
        return np.zeros((resamples, 0))
    rng = np.random.Generator(np.random.PCG64(seed))
    picks = rng.integers(0, n_clusters, size=(resamples, n_clusters))
    counts = np.zeros((resamples, n_clusters), dtype=np.float64)
    np.add.at(counts, (np.repeat(np.arange(resamples), n_clusters), picks.ravel()), 1.0)
    return counts


def percentile(replicates: NDArray[np.float64], level: float = LEVEL) -> tuple[float, float]:
    finite = replicates[np.isfinite(replicates)]
    if finite.size == 0:
        return float("nan"), float("nan")
    tail = (1.0 - level) / 2.0
    return float(np.quantile(finite, tail)), float(np.quantile(finite, 1.0 - tail))


def sum_by_cluster(
    cluster: NDArray[np.int64], values: NDArray[np.float64], n_clusters: int
) -> NDArray[np.float64]:
    out = np.zeros(n_clusters, dtype=np.float64)
    np.add.at(out, cluster, values)
    return out


def ratio(
    keys: Sequence[str],
    numerator: Sequence[float] | NDArray[np.float64],
    denominator: Sequence[float] | NDArray[np.float64] | None = None,
    resamples: int = RESAMPLES,
    seed: int = SEED,
) -> Interval:
    """A share (or any ratio of sums): sum of numerator over sum of denominator, by filer clusters."""
    names, cluster = clusters_of(keys)
    num = np.asarray(numerator, dtype=np.float64)
    den = np.ones_like(num) if denominator is None else np.asarray(denominator, dtype=np.float64)
    c = len(names)
    num_c = sum_by_cluster(cluster, num, c)
    den_c = sum_by_cluster(cluster, den, c)
    estimate = float(num_c.sum() / den_c.sum()) if den_c.sum() else float("nan")
    w = draws(c, resamples, seed)
    with np.errstate(divide="ignore", invalid="ignore"):
        reps = (w @ num_c) / (w @ den_c)
    low, high = percentile(reps)
    return Interval(estimate, low, high, resamples, c, int(num.size))


def ratio_replicates(
    keys: Sequence[str],
    numerator: Sequence[float] | NDArray[np.float64],
    denominator: Sequence[float] | NDArray[np.float64] | None,
    names: list[str],
    w: NDArray[np.float64],
) -> tuple[float, NDArray[np.float64]]:
    """A ratio and its replicates on a draw shared with other statistics, for paired comparisons."""
    index = {k: i for i, k in enumerate(names)}
    cluster = np.fromiter((index[k] for k in keys), dtype=np.int64, count=len(keys))
    num = np.asarray(numerator, dtype=np.float64)
    den = np.ones_like(num) if denominator is None else np.asarray(denominator, dtype=np.float64)
    num_c = sum_by_cluster(cluster, num, len(names))
    den_c = sum_by_cluster(cluster, den, len(names))
    estimate = float(num_c.sum() / den_c.sum()) if den_c.sum() else float("nan")
    with np.errstate(divide="ignore", invalid="ignore"):
        reps = (w @ num_c) / (w @ den_c)
    return estimate, reps


def matrices(
    keys: Sequence[str],
    a: NDArray[np.int64],
    b: NDArray[np.int64],
    k: int,
    statistic: Callable[[NDArray[np.float64]], NDArray[np.float64]],
    resamples: int = RESAMPLES,
    seed: int = SEED,
) -> Interval:
    """A statistic of a confusion matrix (a kappa), by filer clusters, from per filer matrices."""
    names, cluster = clusters_of(keys)
    c = len(names)
    per = np.zeros((c, k * k), dtype=np.float64)
    np.add.at(per, (cluster, np.asarray(a) * k + np.asarray(b)), 1.0)
    total = per.sum(axis=0).reshape(1, k, k)
    estimate = float(statistic(total)[0])
    w = draws(c, resamples, seed)
    reps = statistic((w @ per).reshape(resamples, k, k))
    low, high = percentile(reps)
    return Interval(estimate, low, high, resamples, c, len(keys))


def generic(
    keys: Sequence[str],
    statistic: Callable[[NDArray[np.int64]], float],
    resamples: int = RESAMPLES,
    seed: int = SEED,
) -> tuple[Interval, NDArray[np.float64]]:
    """Any statistic of a set of units, given as the indices of the units in the replicate."""
    names, cluster = clusters_of(keys)
    c = len(names)
    members = [np.flatnonzero(cluster == i) for i in range(c)]
    estimate = float(statistic(np.arange(len(keys), dtype=np.int64)))
    rng = np.random.Generator(np.random.PCG64(seed))
    reps = np.empty(resamples, dtype=np.float64)
    for r in range(resamples):
        picks = rng.integers(0, c, size=c)
        reps[r] = statistic(np.concatenate([members[i] for i in picks]) if c else np.zeros(0, dtype=np.int64))
    low, high = percentile(reps)
    return Interval(estimate, low, high, resamples, c, len(keys)), reps


def two_sided_p(replicates: NDArray[np.float64], null: float = 0.0) -> float:
    """A bootstrap p-value for a difference: twice the share of replicates on the far side of the null."""
    finite = replicates[np.isfinite(replicates)]
    if finite.size == 0:
        return 1.0
    below = (np.sum(finite <= null) + 1.0) / (finite.size + 1.0)
    above = (np.sum(finite >= null) + 1.0) / (finite.size + 1.0)
    return float(min(1.0, 2.0 * min(below, above)))


def quantile(
    keys: Sequence[str],
    values: Sequence[float] | NDArray[np.float64],
    q: float = 0.5,
    resamples: int = RESAMPLES,
    seed: int = SEED,
    chunk: int = 25,
) -> Interval:
    """A quantile (the median by default), by filer clusters.

    The quantile is the lower one, the first value at which the cumulative weight reaches q of the
    total, for the estimate (every weight one) and for each replicate (each unit weighted by how
    often its filer was drawn) alike.
    """
    names, cluster = clusters_of(keys)
    v = np.asarray(values, dtype=np.float64)
    if v.size == 0:
        return Interval(float("nan"), float("nan"), float("nan"), resamples, 0, 0)
    order = np.argsort(v, kind="mergesort")
    v_sorted = v[order]
    c_sorted = cluster[order]
    first = int(np.argmax(np.arange(1, v.size + 1) >= q * v.size))
    estimate = float(v_sorted[first])
    w = draws(len(names), resamples, seed)
    reps = np.empty(resamples, dtype=np.float64)
    for start in range(0, resamples, chunk):
        weights = w[start : start + chunk][:, c_sorted]
        cumulative = np.cumsum(weights, axis=1)
        index = (cumulative >= q * cumulative[:, -1:]).argmax(axis=1)
        reps[start : start + chunk] = v_sorted[index]
    low, high = percentile(reps)
    return Interval(estimate, low, high, resamples, len(names), int(v.size))
