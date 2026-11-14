"""Selection bias of Phase 2: how the band model would do on the CVEs the NVD skipped
(evaluation/phase2_plan.yaml, reweighting).

The shadow CVEs the NVD analyzed carry labels; the ones it skipped do not. Each analyzed CVE is
weighted by the odds that a shadow CVE like it is one the NVD skipped, from the Q8 domain classifier
of Phase 1 (unscheduled_analysis.domain, the same features and fit). Q8 fit it on the earlier half of
the shadow window and scored the later half; here each half is scored by the classifier fit on the
other half, so every weight comes from a fit that did not see the CVE (DECISIONS.md, 14 November
2026). The weights are clipped at the plan's value, the effective sample size is Kish's, and the
plain and weighted results are reported side by side, never one without the other.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import polars as pl
from sklearn.metrics import cohen_kappa_score
from unscheduled_analysis import domain

from unscheduled_models.sets import BANDS

CLIP = 20.0


def cross_fitted_odds(units: pl.DataFrame) -> pl.DataFrame:
    """Per shadow CVE, the probability the NVD analyzed it and the odds it was skipped, each half
    scored by the domain classifier fit on the other half."""
    out = []
    for fit_half, score_half in (("fit", "score"), ("score", "fit")):
        fitted = domain.fit(units.filter(pl.col("half") == fit_half))
        part = units.filter(pl.col("half") == score_half)
        p = np.clip(domain.score(fitted, part), 1e-6, 1 - 1e-6)
        out.append(
            part.select("cve_id", "nvd_analyzed").with_columns(
                pl.Series("p_analyzed", p), pl.Series("odds_skipped", (1 - p) / p)
            )
        )
    return pl.concat(out).sort("cve_id")


def kish(weights: np.ndarray) -> float:
    return float(weights.sum() ** 2 / np.sum(weights**2)) if len(weights) else 0.0


def band_kappa(truth: list[str], predicted: list[str], weights: np.ndarray | None = None) -> float:
    order = {b: i for i, b in enumerate(BANDS)}
    return float(
        cohen_kappa_score(
            [order[t] for t in truth],
            [order[p] for p in predicted],
            weights="quadratic",
            sample_weight=weights,
        )
    )


def plain_and_weighted(frame: pl.DataFrame, clip: float = CLIP) -> dict[str, Any]:
    """frame: the analyzed shadow CVEs with an NVD band, their predicted band and their odds."""
    truth = frame.get_column("band").to_list()
    predicted = frame.get_column("predicted_band").to_list()
    raw = frame.get_column("odds_skipped").to_numpy()
    weights = np.minimum(raw, clip)
    return {
        "rows": frame.height,
        "plain_qwk": band_kappa(truth, predicted),
        "weighted_qwk": band_kappa(truth, predicted, weights),
        "clip": clip,
        "clipped": int(np.sum(raw > clip)),
        "effective_sample_size": kish(weights),
        "weight_mean": float(weights.mean()) if len(weights) else 0.0,
        "weight_max": float(weights.max()) if len(weights) else 0.0,
    }
