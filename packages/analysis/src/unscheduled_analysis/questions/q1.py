"""Q1, the analysis delay.

Plan: CVEs published since 2020-01-01, rejected CVEs excluded; the share reaching NVD Analyzed
within 7, 30 and 90 days, by month; the median days to analysis. Prediction: the 30 day share falls
after 2024 and again after 2026-04-15.

A CVE is judged at k days only when k days have passed by the data cut, so a recent month is never
read as a month the NVD skipped. The three periods the prediction names are compared on the same
bootstrap draw of filers, so each difference has a paired interval, and the six differences (three
horizons, two steps) are one Benjamini-Hochberg family.
"""

from __future__ import annotations

from typing import Any

import duckdb
import numpy as np
import polars as pl

from unscheduled_analysis import bootstrap
from unscheduled_analysis.lake import frame
from unscheduled_analysis.result import Result
from unscheduled_analysis.stats import benjamini_hochberg, km_median

SEED = bootstrap.SEED + 1
HORIZONS = (7, 30, 90)
PERIODS = (
    ("before_2025", "published 2020-01-01 to 2024-12-31", "2020-01-01", "2025-01-01"),
    ("2025_to_change", "published 2025-01-01 to 2026-04-14", "2025-01-01", "2026-04-15"),
    ("since_change", "published from 2026-04-15", "2026-04-15", "2100-01-01"),
)

SQL = """-- Q1: CVEs published per month since January 2020, rejected excluded, and the share the NVD
-- analyzed within 7, 30 and 90 days among those old enough to be judged at each horizon.
select
    published_month,
    count(*) as cves,
    count(analyzed_7d) as judged_7d,
    avg(cast(analyzed_7d as integer)) as share_7d,
    count(analyzed_30d) as judged_30d,
    avg(cast(analyzed_30d as integer)) as share_30d,
    count(analyzed_90d) as judged_90d,
    avg(cast(analyzed_90d as integer)) as share_90d,
    count(first_analysis_at) as analyzed,
    median(days_to_analysis) as median_days_if_analyzed,
    count(*) filter (where analysis_undated) as analysis_undated
from gold.mart_backlog_q1
group by published_month
order by published_month"""


def run(con: duckdb.DuckDBPyConnection, plan: dict[str, Any], cut: str) -> Result:
    r = Result(
        qid="Q1",
        title="The analysis delay",
        subtitle="Share of new CVEs the NVD analyzed within 7, 30 and 90 days of publication, by month, since January 2020",
        plan=plan,
        population="CVEs published since 2020-01-01, rejected CVEs excluded",
        window="every window (a descriptive count); a CVE is judged at k days only once k days have passed",
        data_cut=cut,
        sql=SQL,
        method=(
            "The first NVD analysis is the first Initial Analysis, Reanalysis or Modified Analysis event in the "
            "NVD change history. The share within k days counts, among the CVEs published at least k days before "
            "the data cut, those whose first analysis came within k days. Intervals are a cluster bootstrap by "
            "filer, 2,000 resamples, 95 percent percentile intervals; the period differences use one shared draw "
            "and are corrected as one Benjamini-Hochberg family at 0.05. The median days to analysis is given two "
            "ways: among the CVEs the NVD did analyze, and as a Kaplan-Meier median that counts a CVE not analyzed "
            "by the cut as censored at its follow-up, which is the honest median when many are never analyzed."
        ),
        seed=SEED,
    )
    units = frame(
        con,
        "select cve_id, filer, published, published_month, days_to_analysis, analysis_undated, followup_days, "
        "analyzed_7d, analyzed_30d, analyzed_90d from gold.mart_backlog_q1 order by cve_id",
    )
    r.value("cves", units.height, "int", r.population, "CVEs")
    undated = int(units.get_column("analysis_undated").sum())
    r.value(
        "analysis_undated",
        undated,
        "int",
        "CVEs the NVD calls analyzed whose analysis the history does not date",
        "CVEs",
    )
    if undated:
        r.depart(
            "CVEs whose analysis the change history does not date",
            f"{undated} CVEs carry an NVD status of Analyzed or Modified with no analysis event in the history "
            "fetched; they are left out of the k day shares (neither counted as analyzed nor as skipped) until "
            "the history is complete.",
        )
    monthly = frame(con, SQL)
    r.table(
        "monthly",
        [
            "Month",
            "CVEs",
            "Judged at 7 days",
            "Within 7 days",
            "Judged at 30 days",
            "Within 30 days",
            "Judged at 90 days",
            "Within 90 days",
            "Analyzed",
            "Median days if analyzed",
            "Analysis undated",
        ],
        ["text", "int", "int", "pct1", "int", "pct1", "int", "pct1", "int", "days1", "int"],
        [[str(row[0]), *row[1:]] for row in monthly.iter_rows()],
        "CVEs published each month since 2020-01, rejected excluded",
    )

    names, _ = bootstrap.clusters_of(units.get_column("filer").to_list())
    w = bootstrap.draws(len(names), bootstrap.RESAMPLES, SEED)
    replicates: dict[tuple[str, int], np.ndarray] = {}
    estimates: dict[tuple[str, int], float] = {}
    for key, label, start, end in PERIODS:
        period = units.filter(
            (pl.col("published") >= pl.lit(start).str.to_datetime(time_zone="UTC"))
            & (pl.col("published") < pl.lit(end).str.to_datetime(time_zone="UTC"))
        )
        for k in HORIZONS:
            judged = period.filter(pl.col(f"analyzed_{k}d").is_not_null())
            keys = judged.get_column("filer").to_list()
            hits = judged.get_column(f"analyzed_{k}d").cast(pl.Float64).to_numpy()
            if not keys:
                r.value(
                    f"share_{k}d_{key}",
                    None,
                    "pct1",
                    f"CVEs {label} judged at {k} days: none yet",
                    f"share of CVEs judged at {k} days",
                )
                continue
            est, reps = bootstrap.ratio_replicates(keys, hits, None, names, w)
            low, high = bootstrap.percentile(reps)
            iv = bootstrap.Interval(est, low, high, bootstrap.RESAMPLES, len(set(keys)), len(keys))
            r.interval(
                f"share_{k}d_{key}",
                iv,
                "pct1",
                f"CVEs {label}, rejected excluded, at least {k} days old at the cut",
                f"share of CVEs judged at {k} days analyzed within {k} days",
            )
            replicates[(key, k)] = reps
            estimates[(key, k)] = est
        analyzed = period.filter(pl.col("days_to_analysis").is_not_null())
        if analyzed.height:
            iv = bootstrap.quantile(
                analyzed.get_column("filer").to_list(),
                analyzed.get_column("days_to_analysis").to_numpy(),
                0.5,
                seed=SEED,
            )
            r.interval(
                f"median_days_analyzed_{key}",
                iv,
                "days1",
                f"CVEs {label} the NVD analyzed",
                "days from publication to the first analysis",
            )
        dated = period.filter(~pl.col("analysis_undated"))
        durations = np.where(
            dated.get_column("days_to_analysis").is_not_null().to_numpy(),
            dated.get_column("days_to_analysis").fill_null(0.0).to_numpy(),
            dated.get_column("followup_days").to_numpy(),
        )
        observed = dated.get_column("days_to_analysis").is_not_null().to_numpy()
        km = km_median(durations, observed)
        r.value(
            f"km_median_days_{key}",
            km,
            "days1",
            f"CVEs {label}; a CVE not analyzed by the cut is censored at its follow-up; null when the median is not reached",
            "days from publication to the first analysis",
        )
        r.value(f"cves_{key}", period.height, "int", f"CVEs {label}, rejected excluded", "CVEs")

    family: list[dict[str, Any]] = []
    for k in HORIZONS:
        for a, b in (("before_2025", "2025_to_change"), ("2025_to_change", "since_change")):
            if (a, k) in replicates and (b, k) in replicates:
                diff = replicates[(b, k)] - replicates[(a, k)]
                est = estimates[(b, k)] - estimates[(a, k)]
                low, high = bootstrap.percentile(diff)
                p = bootstrap.two_sided_p(diff)
                name = f"change_{k}d_{a}_to_{b}"
                r.value(name, est, "pts1", f"the {k} day share, {b} less {a}", "percentage points")
                r.values[name].update({"low": low, "high": high, "p": p})
                family.append({"name": name, "estimate": est, "low": low, "high": high, "p": p})
    reject, adjusted = benjamini_hochberg([f["p"] for f in family], 0.05)
    for f, rej, adj in zip(family, reject, adjusted, strict=True):
        f["p_adjusted"] = adj
        f["reject_at_0_05"] = rej
        r.values[f["name"]]["p_adjusted"] = adj
    r.family = family
    share_a = estimates.get(("before_2025", 30))
    share_b = estimates.get(("2025_to_change", 30))
    share_c = estimates.get(("since_change", 30))
    first = next((f for f in family if f["name"] == "change_30d_before_2025_to_2025_to_change"), None)
    second = next((f for f in family if f["name"] == "change_30d_2025_to_change_to_since_change"), None)
    parts = []
    if first is not None:
        parts.append(
            "after 2024 the 30 day share "
            + (
                "fell"
                if first["high"] < 0
                else "rose"
                if first["low"] > 0
                else "did not move outside its interval"
            )
        )
    if second is not None:
        parts.append(
            "after 2026-04-15 it "
            + (
                "fell again"
                if second["high"] < 0
                else "rose"
                if second["low"] > 0
                else "did not move outside its interval"
            )
        )
    r.prediction_check = (
        "; ".join(parts) + f" (30 day shares {share_a}, {share_b}, {share_c} for the three periods)."
        if parts
        else "not enough data"
    )
    return r
