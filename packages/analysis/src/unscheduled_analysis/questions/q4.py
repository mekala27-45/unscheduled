"""Q4, can a filer score stand in for the NVD.

Plan: CVEs scored by both the filer and the NVD, train, development and shadow windows only; Cohen
kappa per CVSS 3.1 base metric; quadratic weighted kappa on the severity band; by filer type; the
direction of disagreement. Prediction: substantial agreement on attack vector, weaker on privileges
and scope.

Each metric's values are ordered by severity (a network attack vector is worse than a local one), so
a disagreement has a direction: the filer rated it worse than the NVD did, or milder. The direction
is the share rated worse less the share rated milder; its interval comes from the same filer draws
as the kappa, and every direction test, overall and by filer type, is one Benjamini-Hochberg family.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import duckdb
import numpy as np
import polars as pl

from unscheduled_analysis import bootstrap
from unscheduled_analysis.lake import frame
from unscheduled_analysis.result import Result
from unscheduled_analysis.stats import benjamini_hochberg, kappa_batch

SEED = bootstrap.SEED + 4
# Severity order, mildest first.
ORDER: dict[str, tuple[str, ...]] = {
    "av": ("P", "L", "A", "N"),
    "ac": ("H", "L"),
    "pr": ("H", "L", "N"),
    "ui": ("R", "N"),
    "s": ("U", "C"),
    "c": ("N", "L", "H"),
    "i": ("N", "L", "H"),
    "a": ("N", "L", "H"),
}
NAMES = {
    "av": "attack vector",
    "ac": "attack complexity",
    "pr": "privileges required",
    "ui": "user interaction",
    "s": "scope",
    "c": "confidentiality",
    "i": "integrity",
    "a": "availability",
    "band": "severity band",
}
BANDS = ("None", "Low", "Medium", "High", "Critical")

SQL = """-- Q4: CVEs both the filer and the NVD scored with CVSS 3.1 (train, development and shadow
-- windows), how often each base metric and the band agree, by filer type.
select
    filer_type,
    count(*) as cves,
    {checks}
from gold.mart_filer_vs_nvd
group by filer_type
order by cves desc"""


def _sql() -> str:
    checks = ",\n    ".join(
        [f"avg(cast(nvd_{m} = filer_{m} as integer)) as agree_{m}" for m in ORDER]
        + ["avg(cast(nvd_band = filer_band as integer)) as agree_band"]
    )
    return SQL.format(checks=checks)


def _ranks(values: Sequence[str | None], order: tuple[str, ...]) -> np.ndarray:
    index = {v: i for i, v in enumerate(order)}
    return np.fromiter(
        (index.get(v, -1) if v is not None else -1 for v in values), dtype=np.int64, count=len(values)
    )


def _measure(
    r: Result,
    prefix: str,
    population: str,
    sub: pl.DataFrame,
    names: list[str],
    w: np.ndarray,
    family: list[dict[str, Any]],
) -> None:
    keys = sub.get_column("filer").to_list()
    index = {k: i for i, k in enumerate(names)}
    cluster = np.fromiter((index[k] for k in keys), dtype=np.int64, count=len(keys))
    metrics = [*ORDER, "band"]
    for m in metrics:
        if m == "band":
            a = sub.get_column("nvd_band_rank").to_numpy().astype(np.int64)
            b = sub.get_column("filer_band_rank").to_numpy().astype(np.int64)
            k = len(BANDS)
            weights: str | None = "quadratic"
        else:
            a = _ranks(sub.get_column(f"nvd_{m}").to_list(), ORDER[m])
            b = _ranks(sub.get_column(f"filer_{m}").to_list(), ORDER[m])
            k = len(ORDER[m])
            weights = None
        ok = (a >= 0) & (b >= 0)
        a, b, c = a[ok], b[ok], cluster[ok]
        per = np.zeros((len(names), k * k), dtype=np.float64)
        np.add.at(per, (c, a * k + b), 1.0)
        total = per.sum(axis=0).reshape(1, k, k)
        estimate = float(kappa_batch(total, weights)[0])  # type: ignore[arg-type]
        reps = kappa_batch((w @ per).reshape(w.shape[0], k, k), weights)  # type: ignore[arg-type]
        low, high = bootstrap.percentile(reps)
        label = (
            "quadratic weighted kappa on the severity band" if m == "band" else f"Cohen kappa on {NAMES[m]}"
        )
        r.interval(
            f"{prefix}kappa_{m}",
            bootstrap.Interval(estimate, low, high, w.shape[0], len(set(c.tolist())), int(a.size)),
            "float2",
            population,
            label,
        )
        sign = np.sign(b - a).astype(np.float64)
        num_c = np.zeros(len(names))
        np.add.at(num_c, c, sign)
        den_c = np.zeros(len(names))
        np.add.at(den_c, c, 1.0)
        est = float(num_c.sum() / den_c.sum()) if den_c.sum() else float("nan")
        with np.errstate(divide="ignore", invalid="ignore"):
            dreps = (w @ num_c) / (w @ den_c)
        dlow, dhigh = bootstrap.percentile(dreps)
        p = bootstrap.two_sided_p(dreps)
        worse = float((sign > 0).mean()) if sign.size else float("nan")
        milder = float((sign < 0).mean()) if sign.size else float("nan")
        name = f"{prefix}direction_{m}"
        r.value(
            name,
            est,
            "pts1",
            population,
            f"share the filer rated {NAMES[m]} worse less the share it rated milder",
        )
        r.values[name].update(
            {"low": dlow, "high": dhigh, "p": p, "worse": worse, "milder": milder, "n": int(a.size)}
        )
        family.append({"name": name, "estimate": est, "low": dlow, "high": dhigh, "p": p})


def run(con: duckdb.DuckDBPyConnection, plan: dict[str, Any], cut: str) -> Result:
    r = Result(
        qid="Q4",
        title="Can a filer score stand in for the NVD",
        subtitle="Agreement between the filer's CVSS 3.1 vector and the NVD's, metric by metric and on the band",
        plan=plan,
        population="CVEs scored with CVSS 3.1 by both their filer and the NVD, rejected excluded",
        window="train, development and shadow only (never test, never the gap)",
        data_cut=cut,
        sql=_sql(),
        method=(
            "Both vectors are the ones current at the data cut. Each base metric is compared as a category (Cohen "
            "kappa, unweighted); the band (None, Low, Medium, High, Critical, from the cvss library's base score) as "
            "an ordered scale (quadratic weighted kappa). The direction of disagreement is the share the filer rated "
            "worse less the share it rated milder, in severity order. Intervals are a cluster bootstrap by filer, "
            "2,000 resamples, 95 percent, every statistic on the same draws; the direction tests form one "
            "Benjamini-Hochberg family at 0.05."
        ),
        seed=SEED,
    )
    units = frame(con, "select * from gold.mart_filer_vs_nvd order by cve_id")
    r.value("cves", units.height, "int", r.population, "CVEs")
    windows = frame(
        con, "select split_window, count(*) as n from gold.mart_filer_vs_nvd group by 1 order by 1"
    )
    r.table(
        "by_window",
        ["Window", "CVEs"],
        ["text", "int"],
        [list(x) for x in windows.iter_rows()],
        "CVEs scored by both, by window",
    )
    names, _ = bootstrap.clusters_of(units.get_column("filer").to_list())
    w = bootstrap.draws(len(names), bootstrap.RESAMPLES, SEED)
    family: list[dict[str, Any]] = []
    _measure(r, "", r.population, units, names, w, family)
    types = sorted(t for t in units.get_column("filer_type").unique().to_list() if t is not None)
    registered = [t for t in types if t != "unregistered"]
    if not registered:
        r.depart(
            "by filer type",
            "config/filers.yaml was not in the repository when the lake was built, so every filer has the type "
            "unregistered and the by filer type breakdown is a single group; it is computed again once the file exists.",
        )
    rows = []
    for t in types:
        sub = units.filter(pl.col("filer_type") == t)
        if sub.height < 30:
            continue
        slug = t.lower().replace(" ", "_").replace("/", "_")
        _measure(r, f"type_{slug}_", f"{r.population}, filer type {t}", sub, names, w, family)
        rows.append(
            [t, sub.height, len(set(sub.get_column("filer").to_list()))]
            + [r.values[f"type_{slug}_kappa_{m}"]["value"] for m in [*ORDER, "band"]]
        )
    r.table(
        "by_filer_type",
        ["Filer type", "CVEs", "Filers", *[f"Kappa {m.upper()}" for m in ORDER], "Weighted kappa, band"],
        ["text", "int", "int", *["float2"] * (len(ORDER) + 1)],
        rows,
        "CVEs scored by both, by the type of their filer (groups of at least 30 CVEs)",
    )
    agreement = frame(con, _sql())
    r.table(
        "agreement_by_filer_type",
        ["Filer type", "CVEs", *[f"Same {m.upper()}" for m in ORDER], "Same band"],
        ["text", "int", *["pct1"] * (len(ORDER) + 1)],
        [list(x) for x in agreement.iter_rows()],
        "the share of CVEs on which filer and NVD give the same value",
    )
    reject, adjusted = benjamini_hochberg([f["p"] for f in family], 0.05)
    for f, rej, adj in zip(family, reject, adjusted, strict=True):
        f["p_adjusted"] = adj
        f["reject_at_0_05"] = rej
        r.values[f["name"]]["p_adjusted"] = adj
    r.family = family
    av = r.values["kappa_av"]["value"]
    pr = r.values["kappa_pr"]["value"]
    sc = r.values["kappa_s"]["value"]
    r.prediction_check = (
        f"Kappa on attack vector {av}, on privileges required {pr}, on scope {sc}: "
        + (
            "attack vector agrees more than both"
            if av is not None and pr is not None and sc is not None and av > max(pr, sc)
            else "attack vector does not agree more than both"
        )
        + "."
    )
    return r
