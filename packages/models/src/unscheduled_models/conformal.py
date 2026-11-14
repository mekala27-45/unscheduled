"""Split conformal prediction sets with adaptive sets (APS), written here and checked against MAPIE
(evaluation/phase2_plan.yaml, conformal).

On development, each CVE's score is the probability mass of the classes ranked at or above its true
class, less a uniform share of the true class's own probability (the randomized APS score of Romano,
Sesia and Candes, 2020, drawn from a seeded generator). The threshold is the ceil((n + 1)(1 - alpha))
smallest score. A new CVE's set is the smallest run of its classes, most probable first, whose
probabilities sum to the threshold or more, the class that crosses it included, as MAPIE builds it
with include_last_label set. Coverage is guaranteed on average over exchangeable rows; a test window
later in time than development is not exchangeable with it, which is why test coverage is measured
and not assumed.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

TARGET = 0.90


def scores(proba: np.ndarray, truth: np.ndarray, seed: int) -> np.ndarray:
    """The randomized APS scores; truth holds class positions."""
    order = np.argsort(-proba, axis=1, kind="stable")
    sorted_p = np.take_along_axis(proba, order, axis=1)
    cumulative = np.cumsum(sorted_p, axis=1)
    rank = np.argmax(order == truth[:, None], axis=1)
    reached = cumulative[np.arange(len(truth)), rank]
    u = np.random.RandomState(seed).uniform(size=len(truth))
    out: np.ndarray = reached - u * proba[np.arange(len(truth)), truth]
    return out


def threshold(conformity: np.ndarray, target: float = TARGET) -> float:
    """The ceil((n + 1) target) smallest score, the largest when that index passes n."""
    n = len(conformity)
    k = min(n, math.ceil((n + 1) * target))
    return float(np.sort(conformity)[k - 1])


def sets(proba: np.ndarray, cutoff: float) -> np.ndarray:
    """A boolean matrix: whether each class is in each CVE's set."""
    order = np.argsort(-proba, axis=1, kind="stable")
    sorted_p = np.take_along_axis(proba, order, axis=1)
    cumulative = np.cumsum(sorted_p, axis=1)
    before = cumulative - sorted_p
    keep_sorted = before < cutoff
    keep_sorted[:, 0] = True
    out = np.zeros_like(proba, dtype=bool)
    np.put_along_axis(out, order, keep_sorted, axis=1)
    return out


@dataclass
class Conformal:
    cutoff: float
    target: float
    calibration_rows: int

    def predict(self, proba: np.ndarray) -> np.ndarray:
        return sets(proba, self.cutoff)


def fit(proba: np.ndarray, truth: np.ndarray, seed: int, target: float = TARGET) -> Conformal:
    return Conformal(threshold(scores(proba, truth, seed), target), target, len(truth))


def coverage(member: np.ndarray, truth: np.ndarray) -> dict[str, float]:
    """The share of rows whose set holds the true class, and the mean set size."""
    hit = member[np.arange(len(truth)), truth]
    return {"coverage": float(hit.mean()), "mean_size": float(member.sum(axis=1).mean()), "rows": len(truth)}
