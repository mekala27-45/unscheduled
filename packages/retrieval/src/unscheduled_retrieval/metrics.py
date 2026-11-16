"""The retrieval metrics of the plan, their bootstrap intervals and the choice rule.

Relevance is binary at the grain of documents: a ranked list of chunks is read as the list of its
documents in order of first appearance and cut at k documents. nDCG gives a relevant document a gain
of 1 and discounts it by log2 of its rank plus one. The intervals resample CVEs, 2000 times from a
seeded generator, percentile 95 percent, and every configuration is paired with the floor on the
same resamples.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np

METRICS = ("recall_at_5", "recall_at_10", "mrr_at_10", "ndcg_at_10", "advisory_recall_at_10")
RESAMPLES = 2000
SEED = 20261116
# The plan's order of simplicity, for a tie at three decimals.
SIMPLER = ("floor", "dense", "hybrid", "rerank")


def recall_at(ranked: Sequence[str], relevant: Sequence[str], k: int) -> float:
    wanted = set(relevant)
    return len(wanted & set(ranked[:k])) / len(wanted) if wanted else 0.0


def mrr_at(ranked: Sequence[str], relevant: Sequence[str], k: int) -> float:
    wanted = set(relevant)
    for rank, doc in enumerate(ranked[:k], start=1):
        if doc in wanted:
            return 1.0 / rank
    return 0.0


def ndcg_at(ranked: Sequence[str], relevant: Sequence[str], k: int) -> float:
    wanted = set(relevant)
    dcg = sum(1.0 / math.log2(rank + 1) for rank, doc in enumerate(ranked[:k], start=1) if doc in wanted)
    ideal = sum(1.0 / math.log2(rank + 1) for rank in range(1, min(k, len(wanted)) + 1))
    return dcg / ideal if ideal else 0.0


def per_query(ranked: Sequence[str], relevant: Sequence[str], advisories: Sequence[str]) -> dict[str, float]:
    return {
        "recall_at_5": recall_at(ranked, relevant, 5),
        "recall_at_10": recall_at(ranked, relevant, 10),
        "mrr_at_10": mrr_at(ranked, relevant, 10),
        "ndcg_at_10": ndcg_at(ranked, relevant, 10),
        "advisory_recall_at_10": recall_at(ranked, advisories, 10) if advisories else float("nan"),
    }


def resamples(n: int, count: int = RESAMPLES, seed: int = SEED) -> np.ndarray:
    """The resampled query positions, one row per resample, the same for every configuration."""
    return np.random.default_rng(seed).integers(0, n, size=(count, n))


def interval(values: np.ndarray, draws: np.ndarray) -> dict[str, float]:
    """The mean of the per query values and its percentile interval over the draws, ignoring the
    queries a metric does not apply to (advisory recall where a CVE has no advisory)."""
    keep = ~np.isnan(values)
    if not keep.any():
        return {"mean": float("nan"), "low": float("nan"), "high": float("nan"), "n": 0}
    sums = np.where(keep, values, 0.0)[draws].sum(axis=1)
    counts = keep[draws].sum(axis=1)
    means = np.divide(sums, counts, out=np.full(len(draws), np.nan), where=counts > 0)
    low, high = np.nanpercentile(means, [2.5, 97.5])
    return {"mean": float(values[keep].mean()), "low": float(low), "high": float(high), "n": int(keep.sum())}


def summarize(
    by_config: Mapping[str, Sequence[Mapping[str, float]]], draws: np.ndarray, floor: str = "floor"
) -> dict[str, Any]:
    """Every metric of every configuration with its interval, and its paired difference with the floor."""
    out: dict[str, Any] = {}
    base = {m: np.asarray([q[m] for q in by_config[floor]], dtype=float) for m in METRICS}
    for name, rows in by_config.items():
        values = {m: np.asarray([q[m] for q in rows], dtype=float) for m in METRICS}
        entry: dict[str, Any] = {m: interval(values[m], draws) for m in METRICS}
        if name != floor:
            entry["minus_floor"] = {m: interval(values[m] - base[m], draws) for m in METRICS}
        out[name] = entry
    return out


def choose(summary: Mapping[str, Any]) -> dict[str, Any]:
    """The plan's rule: the configuration with the highest development recall at 10 whose paired
    difference with the floor has a lower bound above zero, else the floor; the reranker only if it
    beats hybrid the same way; a tie at three decimals goes to the simpler configuration."""
    candidates = ["floor"]
    reasons: dict[str, str] = {}
    for name in ("dense", "hybrid"):
        if name not in summary:
            continue
        low = summary[name]["minus_floor"]["recall_at_10"]["low"]
        if low > 0:
            candidates.append(name)
        reasons[name] = f"paired recall at 10 minus the floor, lower bound {low:.3f}"
    if "rerank" in summary and "hybrid" in summary:
        over_floor = summary["rerank"]["minus_floor"]["recall_at_10"]["low"]
        over_hybrid = (
            summary["rerank"].get("minus_hybrid", {}).get("recall_at_10", {}).get("low", float("nan"))
        )
        if over_floor > 0 and over_hybrid > 0:
            candidates.append("rerank")
        reasons["rerank"] = f"lower bounds {over_floor:.3f} over the floor and {over_hybrid:.3f} over hybrid"

    def key(name: str) -> tuple[float, int]:
        return (-round(float(summary[name]["recall_at_10"]["mean"]), 3), SIMPLER.index(name))

    chosen = sorted(candidates, key=key)[0]
    return {"chosen": chosen, "candidates": candidates, "reasons": reasons}


def paired(
    rows: Sequence[Mapping[str, float]], other: Sequence[Mapping[str, float]], draws: np.ndarray
) -> dict[str, Any]:
    """The paired difference of one configuration with another on the same resamples."""
    return {
        m: interval(
            np.asarray([q[m] for q in rows], dtype=float) - np.asarray([q[m] for q in other], dtype=float),
            draws,
        )
        for m in METRICS
    }
