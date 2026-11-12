"""Q6, who files the flood.

Plan: CVEs published since 2020-01-01; the monthly share by filer and by filer type; the filers
behind the growth. Prediction: a few filers account for most of the growth.

Growth is the change from the twelve months of 2020 to the last twelve complete months before the
data cut. Each filer's part of it is its own change; the concentration is the share of the net
growth the ten filers with the largest increases carry, and the smallest number of filers whose
increases together pass half of it. Both are recomputed in every bootstrap replicate, which draws
filers with replacement, so the interval says how much the concentration rests on a few filers.
"""

from __future__ import annotations

from datetime import date
from typing import Any

import duckdb
import numpy as np
import polars as pl

from unscheduled_analysis import bootstrap
from unscheduled_analysis.lake import frame
from unscheduled_analysis.result import Result

SEED = bootstrap.SEED + 6
TOP = 10

SQL = """-- Q6: CVEs published since 2020 by month and filer type, with each type's share of the month.
select
    published_month,
    filer_type,
    sum(cves) as cves,
    sum(cves) / any_value(month_total) as share_of_month
from gold.mart_backlog_q6
group by published_month, filer_type
order by published_month, filer_type"""


def _months_back(cut: date, n: int) -> tuple[date, date]:
    """The n complete months before the month of the cut: [start, end)."""
    end = date(cut.year, cut.month, 1)
    y, m = end.year, end.month - n
    while m <= 0:
        y, m = y - 1, m + 12
    return date(y, m, 1), end


def concentration(delta: np.ndarray, weights: np.ndarray, top: int = TOP) -> tuple[np.ndarray, np.ndarray]:
    """Per replicate: the top filers' share of the net growth, and the filers needed for half of it.

    delta is each filer's change, sorted largest first; weights is (replicates, filers), how often
    each filer was drawn.
    """
    net = weights @ delta
    cum_units = np.cumsum(weights, axis=1)
    taken = np.clip(top - (cum_units - weights), 0, weights)
    top_share = (taken @ delta) / net
    cum_growth = np.cumsum(weights * delta[None, :], axis=1)
    half = np.argmax(cum_growth >= 0.5 * net[:, None], axis=1)
    needed = np.take_along_axis(cum_units, half[:, None], axis=1)[:, 0]
    return top_share, needed


def run(con: duckdb.DuckDBPyConnection, plan: dict[str, Any], cut: str) -> Result:
    cut_day = date.fromisoformat(cut[:10])
    recent_start, recent_end = _months_back(cut_day, 12)
    r = Result(
        qid="Q6",
        title="Who files the flood",
        subtitle="Monthly CVE volume by filer and filer type since 2020, and the filers behind the growth",
        plan=plan,
        population="CVEs published since 2020-01-01",
        window=f"every window; growth from 2020 to the twelve months {recent_start} to {recent_end} (end excluded)",
        data_cut=cut,
        sql=SQL,
        method=(
            "Volume counts every CVE published in a month, rejected ones included as the plan states (their number is "
            "given). Growth compares calendar 2020 with the last twelve complete months before the data cut; each "
            "filer's part is its own change. The top ten share and the number of filers that carry half of the net "
            "growth are recomputed in each of 2,000 cluster bootstrap replicates over filers, 95 percent intervals."
        ),
        seed=SEED,
    )
    monthly = frame(con, "select * from gold.mart_backlog_q6 order by published_month, filer")
    r.value("cves", int(monthly.get_column("cves").sum()), "int", r.population, "CVEs")
    r.value(
        "rejected",
        int(monthly.get_column("rejected").sum()),
        "int",
        "CVEs published since 2020-01-01 and since rejected",
        "CVEs",
    )
    by_type = frame(con, SQL)
    r.table(
        "monthly_by_filer_type",
        ["Month", "Filer type", "CVEs", "Share of the month"],
        ["text", "text", "int", "pct1"],
        [[str(row[0]), row[1], row[2], row[3]] for row in by_type.iter_rows()],
        "CVEs published each month since 2020-01, by the type of their filer",
    )
    per_filer = (
        monthly.with_columns(
            pl.when(pl.col("published_month") < date(2021, 1, 1))
            .then(pl.col("cves"))
            .otherwise(0)
            .alias("base"),
            pl.when((pl.col("published_month") >= recent_start) & (pl.col("published_month") < recent_end))
            .then(pl.col("cves"))
            .otherwise(0)
            .alias("recent"),
        )
        .group_by("filer")
        .agg(pl.col("filer_type").first(), pl.col("base").sum(), pl.col("recent").sum())
        .with_columns((pl.col("recent") - pl.col("base")).alias("delta"))
        .sort(["delta", "filer"], descending=[True, False])
    )
    base = int(per_filer.get_column("base").sum())
    recent = int(per_filer.get_column("recent").sum())
    r.value("cves_2020", base, "int", "CVEs published in 2020", "CVEs")
    r.value(
        "cves_last_12_months",
        recent,
        "int",
        f"CVEs published {recent_start} to {recent_end}, end excluded",
        "CVEs",
    )
    r.value("net_growth", recent - base, "int", "the change from 2020 to the last twelve months", "CVEs")
    delta = per_filer.get_column("delta").cast(pl.Float64).to_numpy()
    ones = np.ones((1, delta.size))
    top_share, needed = concentration(delta, ones)
    w = bootstrap.draws(delta.size, bootstrap.RESAMPLES, SEED)
    rep_share, rep_needed = concentration(delta, w)
    low, high = bootstrap.percentile(rep_share)
    r.interval(
        "top10_share_of_growth",
        bootstrap.Interval(
            float(top_share[0]), low, high, bootstrap.RESAMPLES, int(delta.size), int(delta.size)
        ),
        "pct1",
        "filers with CVEs published since 2020",
        "share of the net growth carried by the ten filers with the largest increases",
    )
    nlow, nhigh = bootstrap.percentile(rep_needed.astype(float))
    r.interval(
        "filers_for_half_of_growth",
        bootstrap.Interval(
            float(needed[0]), nlow, nhigh, bootstrap.RESAMPLES, int(delta.size), int(delta.size)
        ),
        "int",
        "filers with CVEs published since 2020",
        "the fewest filers whose increases together pass half of the net growth",
    )
    r.value("filers", int(delta.size), "int", "filers with CVEs published since 2020", "filers")
    top = per_filer.head(20)
    r.table(
        "growth_by_filer",
        [
            "Filer",
            "Filer type",
            "CVEs in 2020",
            "CVEs in the last 12 months",
            "Change",
            "Share of net growth",
        ],
        ["text", "text", "int", "int", "int", "pct1"],
        [
            [
                row["filer"],
                row["filer_type"],
                row["base"],
                row["recent"],
                row["delta"],
                row["delta"] / (recent - base) if recent != base else None,
            ]
            for row in top.iter_rows(named=True)
        ],
        "the twenty filers with the largest increase from 2020 to the last twelve months",
    )
    share = r.values["top10_share_of_growth"]["value"]
    n_half = r.values["filers_for_half_of_growth"]["value"]
    r.prediction_check = f"The ten filers with the largest increases carry {share} of the net growth; {n_half} filers carry half of it."
    return r
