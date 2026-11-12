"""The cluster bootstrap: the same seed gives the same interval, the interval holds the estimate,
and resampling filers rather than CVEs widens it when CVEs of one filer move together."""

from __future__ import annotations

import numpy as np
from unscheduled_analysis import bootstrap


def _filers(n_filers: int, per: int, rng: np.random.Generator) -> tuple[list[str], np.ndarray]:
    keys: list[str] = []
    values: list[float] = []
    for f in range(n_filers):
        rate = rng.uniform(0.1, 0.9)  # each filer has its own rate, so its CVEs move together
        keys += [f"filer-{f}"] * per
        values += list((rng.random(per) < rate).astype(float))
    return keys, np.asarray(values)


def test_the_same_seed_gives_the_same_interval() -> None:
    keys, values = _filers(30, 40, np.random.default_rng(1))
    a = bootstrap.ratio(keys, values, resamples=500)
    b = bootstrap.ratio(keys, values, resamples=500)
    assert a == b
    assert a.low <= a.estimate <= a.high
    assert a.clusters == 30 and a.units == 1200


def test_clusters_widen_the_interval_when_units_move_together() -> None:
    keys, values = _filers(30, 40, np.random.default_rng(2))
    by_filer = bootstrap.ratio(keys, values, resamples=1000)
    by_cve = bootstrap.ratio([str(i) for i in range(len(keys))], values, resamples=1000)
    assert (by_filer.high - by_filer.low) > (by_cve.high - by_cve.low)
    assert by_filer.estimate == by_cve.estimate == float(values.mean())


def test_each_draw_takes_as_many_clusters_as_there_are() -> None:
    w = bootstrap.draws(12, resamples=200, seed=5)
    assert w.shape == (200, 12)
    assert np.all(w.sum(axis=1) == 12)
    assert bootstrap.draws(0, resamples=3).shape == (3, 0)
