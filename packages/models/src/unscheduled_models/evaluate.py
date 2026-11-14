"""The measures of Phase 2's test scoring, on arrays: no file is opened here
(evaluation/phase2_plan.yaml: evaluation; config/criteria.yaml: C1 and C2).

C1's kappa, its paired difference with the floor and the ECE are taken by the cluster bootstrap by
filer of Phase 1 (unscheduled_analysis.bootstrap): each replicate draws as many filers as there are,
with replacement, and the kappas of both models and the ECE come from the same draw, so a difference
is paired. The kappa and the ECE are sums over filers (confusion matrices; per bin sums of confidence
and correctness), so a replicate is exact. C2's recall at the top 5 percent and its differences with
EPSS come from a row bootstrap, every model ranked again inside each replicate on the same rows. A
difference whose interval holds zero is a tie.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any, Literal

import numpy as np
from unscheduled_analysis import bootstrap, stats

from unscheduled_models import rank

RESAMPLES = bootstrap.RESAMPLES
ECE_BINS = 15


def _per_cluster_matrices(
    cluster: np.ndarray, truth: np.ndarray, guess: np.ndarray, c: int, k: int
) -> np.ndarray:
    per = np.zeros((c, k * k), dtype=np.float64)
    np.add.at(per, (cluster, truth * k + guess), 1.0)
    return per


def kappa_paired(
    keys: Sequence[str],
    truth: np.ndarray,
    model: np.ndarray,
    floor: np.ndarray,
    k: int,
    seed: int,
    weights: Literal["linear", "quadratic"] | None = "quadratic",
    resamples: int = RESAMPLES,
) -> dict[str, Any]:
    """The weighted kappa of a model and of its floor against the truth, each with its interval, and
    their difference with its interval and two sided p value, on one cluster draw."""
    names, cluster = bootstrap.clusters_of(keys)
    c = len(names)
    w = bootstrap.draws(c, resamples, seed)
    out: dict[str, Any] = {"rows": len(truth), "clusters": c, "resamples": resamples}
    reps = {}
    for name, guess in (("model", model), ("floor", floor)):
        per = _per_cluster_matrices(cluster, truth, guess, c, k)
        estimate = float(stats.kappa_batch(per.sum(axis=0).reshape(1, k, k), weights)[0])
        reps[name] = stats.kappa_batch((w @ per).reshape(resamples, k, k), weights)
        low, high = bootstrap.percentile(reps[name])
        out[name] = {"value": estimate, "low": low, "high": high}
    diff = reps["model"] - reps["floor"]
    low, high = bootstrap.percentile(diff)
    out["difference"] = {
        "value": out["model"]["value"] - out["floor"]["value"],
        "low": low,
        "high": high,
        "p": bootstrap.two_sided_p(diff),
    }
    return out


def ece_clustered(
    keys: Sequence[str], confidence: np.ndarray, correct: np.ndarray, seed: int, resamples: int = RESAMPLES
) -> dict[str, Any]:
    """The ECE over 15 equal width bins of the top label probability, with its cluster interval."""
    names, cluster = bootstrap.clusters_of(keys)
    c = len(names)
    edges = np.linspace(0.0, 1.0, ECE_BINS + 1)
    index = np.clip(np.digitize(confidence, edges[1:-1], right=True), 0, ECE_BINS - 1)
    conf = np.zeros((c, ECE_BINS))
    corr = np.zeros((c, ECE_BINS))
    count = np.zeros((c, ECE_BINS))
    np.add.at(conf, (cluster, index), confidence)
    np.add.at(corr, (cluster, index), correct)
    np.add.at(count, (cluster, index), 1.0)

    def value(cf: np.ndarray, cr: np.ndarray, n: np.ndarray) -> np.ndarray:
        total = n.sum(axis=-1)
        out: np.ndarray = np.abs(cf - cr).sum(axis=-1) / np.where(total > 0, total, np.nan)
        return out

    estimate = float(value(conf.sum(axis=0), corr.sum(axis=0), count.sum(axis=0)))
    w = bootstrap.draws(c, resamples, seed)
    reps = value(w @ conf, w @ corr, w @ count)
    low, high = bootstrap.percentile(reps)
    return {
        "value": estimate,
        "low": low,
        "high": high,
        "bins": ECE_BINS,
        "rows": len(confidence),
        "clusters": c,
    }


def recall_paired(
    truth: np.ndarray, scores: dict[str, np.ndarray], seed: int, reference: str, resamples: int = RESAMPLES
) -> dict[str, Any]:
    """Recall at the top 5 percent for each score, and each one's difference with the reference, on
    the same row resamples; a difference whose interval holds zero is named a tie."""
    n = len(truth)
    rng = np.random.Generator(np.random.PCG64(seed))
    reps = {name: np.empty(resamples) for name in scores}
    for r in range(resamples):
        rows = np.sort(rng.integers(0, n, size=n))
        for name, s in scores.items():
            reps[name][r] = rank.recall_at_top(truth[rows], s[rows])
    out: dict[str, Any] = {"rows": n, "positives": int(truth.sum()), "top": math.ceil(rank.TOP_SHARE * n)}
    for name, s in scores.items():
        low, high = bootstrap.percentile(reps[name])
        out[name] = {"value": rank.recall_at_top(truth, s), "low": low, "high": high}
    for name in scores:
        if name == reference:
            continue
        diff = reps[reference] - reps[name]
        low, high = bootstrap.percentile(diff)
        out[f"{reference}_minus_{name}"] = {
            "value": out[reference]["value"] - out[name]["value"],
            "low": low,
            "high": high,
            "p": bootstrap.two_sided_p(diff),
            "reading": "tie" if low <= 0 <= high else ("ahead" if low > 0 else "behind"),
        }
    return out


def slice_differences(
    groups: Sequence[str],
    family: Sequence[str],
    metric: Any,
    a: Sequence[Any],
    b: Sequence[Any],
    truth: Sequence[Any],
    seed: int,
    min_rows: int,
    resamples: int = RESAMPLES,
) -> list[dict[str, Any]]:
    """Per slice of a family, the metric of a and of b and their difference by a row bootstrap, with a
    two sided p value; Benjamini-Hochberg at 0.05 over the slices tested in the family."""
    rows_out: list[dict[str, Any]] = []
    tested: list[int] = []
    pvalues: list[float] = []
    for name in family:
        idx = [int(i) for i in np.flatnonzero(np.asarray(groups) == name)]
        entry: dict[str, Any] = {"slice": name, "rows": len(idx)}
        t = [truth[i] for i in idx]
        if len(idx) < min_rows or len(set(t)) < 2:
            entry["tested"] = False
            rows_out.append(entry)
            continue
        av, bv = [a[i] for i in idx], [b[i] for i in idx]
        entry["a"], entry["b"] = metric(t, av), metric(t, bv)
        rng = np.random.Generator(np.random.PCG64(seed))
        diffs = np.empty(resamples)
        for r in range(resamples):
            pick = rng.integers(0, len(idx), size=len(idx)).tolist()
            tt = [t[i] for i in pick]
            diffs[r] = metric(tt, [av[i] for i in pick]) - metric(tt, [bv[i] for i in pick])
        low, high = bootstrap.percentile(diffs)
        entry.update(
            {
                "difference": entry["a"] - entry["b"],
                "low": low,
                "high": high,
                "p": bootstrap.two_sided_p(diffs),
                "tested": True,
            }
        )
        tested.append(len(rows_out))
        pvalues.append(entry["p"])
        rows_out.append(entry)
    rejected, adjusted = stats.benjamini_hochberg(pvalues)
    for position, rej, adj in zip(tested, rejected, adjusted, strict=True):
        rows_out[position]["p_adjusted"] = adj
        rows_out[position]["significant"] = rej
    return rows_out
