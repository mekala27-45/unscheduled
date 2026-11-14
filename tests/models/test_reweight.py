"""The selection bias weights: out of half odds, the clip, Kish's size, plain beside weighted."""

from __future__ import annotations

from datetime import date

import numpy as np
import polars as pl
import pytest
from unscheduled_models import reweight


def mart(n: int, seed: int) -> pl.DataFrame:
    """A shadow window where the NVD analyzes vendor filed CVEs far more often."""
    rng = np.random.default_rng(seed)
    vendor = rng.random(n) < 0.5
    analyzed = np.where(vendor, rng.random(n) < 0.8, rng.random(n) < 0.2)
    words = ["overflow in the parser", "cross site scripting", "sql injection", "path traversal"]
    return pl.DataFrame(
        {
            "cve_id": [f"CVE-2026-{i:05d}" for i in range(n)],
            "nvd_analyzed": analyzed,
            "filer": ["acme" if v else "globex" for v in vendor],
            "filer_type": ["vendor" if v else "open source project" for v in vendor],
            "filer_cwes": [["CWE-79"] if i % 3 == 0 else None for i in range(n)],
            "published": [date(2026, 5, 1)] * n,
            "published_month": [date(2026, 4 + (i * 6) // n, 1) for i in range(n)],
            "has_filer_cvss3": vendor,
            "has_filer_cvss40": rng.random(n) < 0.3,
            "description": [words[i % 4] for i in range(n)],
            "half": ["fit" if i < n // 2 else "score" for i in range(n)],
            "position": list(range(n)),
        }
    )


def test_every_cve_gets_odds_from_the_other_half() -> None:
    odds = reweight.cross_fitted_odds(mart(600, 1))
    assert odds.height == 600 and odds.get_column("cve_id").n_unique() == 600
    assert odds.get_column("p_analyzed").is_between(0, 1).all()
    by_type = odds.join(mart(600, 1).select("cve_id", "filer_type"), on="cve_id")
    mean_odds = by_type.group_by("filer_type").agg(pl.col("odds_skipped").mean()).sort("filer_type")
    # The skipped are mostly open source filed, so their look alikes carry the larger weights.
    values = dict(mean_odds.iter_rows())
    assert values["open source project"] > values["vendor"]


def test_kish_and_the_clip() -> None:
    assert reweight.kish(np.ones(10)) == pytest.approx(10)
    assert reweight.kish(np.array([1.0, 0.0, 0.0])) == pytest.approx(1)
    frame = pl.DataFrame(
        {
            "band": ["LOW", "MEDIUM", "HIGH", "CRITICAL"] * 5,
            "predicted_band": ["LOW", "MEDIUM", "HIGH", "HIGH"] * 5,
            "odds_skipped": [1.0, 1.0, 1.0, 100.0] * 5,
        }
    )
    result = reweight.plain_and_weighted(frame, clip=20)
    assert result["clipped"] == 5 and result["weight_max"] == 20
    assert result["weighted_qwk"] < result["plain_qwk"]
    same = frame.with_columns(pl.lit(1.0).alias("odds_skipped"))
    equal = reweight.plain_and_weighted(same)
    assert equal["weighted_qwk"] == pytest.approx(equal["plain_qwk"])
