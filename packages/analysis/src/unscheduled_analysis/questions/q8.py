"""Q8, how different the skipped CVEs are.

Plan: CVEs published in the shadow window, a held out half for scoring; a logistic regression
domain classifier on filer, filer type, CWE, month, vector presence and description TF-IDF; the AUC
with its interval; the top features. Prediction: the classifier separates them well, so NVD labels
alone would bias a model.

The held out half is the later half by publication time (ties by CVE id), never a random half.
"""

from __future__ import annotations

from typing import Any

import duckdb
import numpy as np
import polars as pl

from unscheduled_analysis import bootstrap, domain
from unscheduled_analysis.lake import frame
from unscheduled_analysis.result import Result
from unscheduled_analysis.stats import auc

SEED = bootstrap.SEED + 8

SQL = """-- Q8: the shadow window, the registered features and the label, split by time into the half
-- the classifier is fitted on and the half it is scored on.
select
    half,
    count(*) as cves,
    avg(cast(nvd_analyzed as integer)) as share_analyzed,
    min(published) as first_published,
    max(published) as last_published
from gold.mart_domain_shift
group by half
order by min(position)"""


def run(con: duckdb.DuckDBPyConnection, plan: dict[str, Any], cut: str) -> Result:
    r = Result(
        qid="Q8",
        title="How different the skipped CVEs are",
        subtitle="How well a logistic regression tells the CVEs the NVD analyzed from the ones it skipped, shadow window",
        plan=plan,
        population="CVEs published in the shadow window (from 2026-04-15), rejected excluded",
        window="shadow only; fitted on the earlier half by publication time, scored on the later half",
        data_cut=cut,
        sql=SQL,
        method=(
            "A logistic regression (liblinear, C = 1) on one hot filer and filer type (a filer seen fewer than three "
            "times is pooled), the filer's CWE ids, the published month as months since April 2026, whether the filer "
            "gave a CVSS 3.x and a CVSS 4.0 vector, and a TF-IDF of the description (words and word pairs seen at least "
            "five times, at most 30,000). The label is whether the NVD analyzed the CVE by the cut. The AUC is computed "
            "on the later half only, with a cluster bootstrap by filer over that half, 2,000 resamples, 95 percent. "
            "The later half has had less time to be analyzed, which the month feature carries; the AUC measures how "
            "separable the groups are, not a model to apply."
        ),
        seed=SEED,
    )
    units = frame(con, "select * from gold.mart_domain_shift order by position")
    r.value("cves", units.height, "int", r.population, "CVEs")
    halves = frame(con, SQL)
    r.table(
        "halves",
        ["Half", "CVEs", "Share analyzed", "First published", "Last published"],
        ["text", "int", "pct1", "text", "text"],
        [[row[0], row[1], row[2], str(row[3]), str(row[4])] for row in halves.iter_rows()],
        "the two halves of the shadow window, split by publication time",
    )
    r.depart(
        "rejected CVEs",
        "Rejected CVEs are left out of the population: the NVD never analyzes a rejected CVE, so keeping them would "
        "measure rejection, not the NVD's choice of what to analyze.",
    )
    train = units.filter(pl.col("half") == "fit")
    test = units.filter(pl.col("half") == "score")
    for name, part in (("fit", train), ("score", test)):
        r.value(f"cves_{name}", part.height, "int", f"CVEs in the {name} half", "CVEs")
        r.value(
            f"analyzed_{name}",
            int(part.get_column("nvd_analyzed").sum()),
            "int",
            f"CVEs in the {name} half the NVD analyzed",
            "CVEs",
        )
    labels_fit = set(train.get_column("nvd_analyzed").to_list())
    labels_score = set(test.get_column("nvd_analyzed").to_list())
    if len(labels_fit) < 2 or len(labels_score) < 2:
        r.depart(
            "the classifier",
            "One half holds a single label, so no classifier can be fitted or scored; no AUC is reported.",
        )
        r.prediction_check = "not measurable: one half has a single label"
        return r
    fitted = domain.fit(train)
    scores = domain.score(fitted, test)
    y = test.get_column("nvd_analyzed").cast(pl.Int64).to_numpy()
    keys = test.get_column("filer").to_list()

    def statistic(index: np.ndarray) -> float:
        return auc(y[index], scores[index])

    iv, _ = bootstrap.generic(keys, statistic, seed=SEED)
    r.interval("auc", iv, "float3", "CVEs in the later half of the shadow window", "area under the ROC curve")
    toward, away = domain.top_features(fitted)
    r.table(
        "features_toward_analyzed",
        ["Feature", "Group", "Coefficient"],
        ["text", "text", "float3"],
        [list(x) for x in toward],
        "the fifteen features that most raise the odds the NVD analyzed a CVE",
    )
    r.table(
        "features_toward_skipped",
        ["Feature", "Group", "Coefficient"],
        ["text", "text", "float3"],
        [list(x) for x in away],
        "the fifteen features that most lower the odds the NVD analyzed a CVE",
    )
    r.value("features", len(fitted.names), "int", "features the classifier was fitted on", "features")
    a = iv.estimate
    r.prediction_check = (
        f"AUC {a:.3f} on the later half (95 percent interval {iv.low:.3f} to {iv.high:.3f}); "
        + (
            "the groups separate well, so NVD labels alone would bias a model toward the CVEs the NVD chose."
            if iv.low > 0.75
            else "the separation is moderate or weak."
        )
    )
    return r
