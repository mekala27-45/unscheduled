"""Write and run the Phase 2 notebooks, the dead ends of the models kept as records.

    python scripts/make_model_notebooks.py 04 05 06    # notebooks/04_..., 05_..., 06_...

04_the_random_split fits the band floor on a random split of the same CVEs and measures how much it
inflates the kappa against the registered split by time. 05_reading_the_misses shows the 100
development misses as they were coded (results/models/misses.json and taxonomy.json).
06_epss_on_day_30 compares the exploitation model with EPSS read 30 days after publication, on
development, and says why that comparison is wrong. Each runs here the way scripts/make_notebooks.py
runs 01 to 03, cell by cell in one namespace, against the committed sets and records; no notebook
reads a test label. pandas and NumPy are named in each, as the prompt asks.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from scripts.make_notebooks import Cell, write

SETUP = """import json

import numpy as np
import pandas as pd
import polars as pl

pl.Config.set_tbl_rows(12)
pl.Config.set_tbl_width_chars(110)
SEED = 20261114  # evaluation/phase2_plan.yaml, defaults.seed
print("numpy", np.__version__, "pandas", pd.__version__, "polars", pl.__version__)"""

NB04: list[Cell] = [
    (
        "markdown",
        "# 04, the random split\n\n"
        "A random split is the first evaluation many projects reach for: shuffle every labelled CVE, "
        "hold a share out, score the model on it. The plan forbids it (config/splits.yaml splits by "
        "publication date, and the floor is chosen on 2024 and judged on 2025 and later), because a "
        "random holdout puts CVEs from the same months, the same filers and the same bursts of "
        "near identical advisories on both sides. This notebook fits the same band floor both ways, "
        "on the same number of rows, compares the two scores, and then scores both models on the same "
        "2024 CVEs, to separate what the split changes from what the population changes.",
    ),
    ("code", SETUP),
    (
        "code",
        """from unscheduled_models import floors
from unscheduled_models.features import Features

record = json.load(open("results/models/floors.json"))
chosen = record["chosen"]["band"]
variant, c = record["representation"]["chosen"], chosen["C"]
print(f"the band floor as chosen: {variant} grams, C {c}, development kappa {chosen['dev']['qwk']:.3f}")

def labelled(split):
    inputs = pl.read_parquet(f"data/sets/{split}_inputs.parquet")
    labels = pl.read_parquet(f"data/sets/{split}_labels.parquet").select("cve_id", "band")
    return inputs.join(labels, on="cve_id").filter(pl.col("band").is_not_null())

train, dev = labelled("train"), labelled("development")
print(f"{train.height:,} train and {dev.height:,} development CVEs with an NVD band")""",
    ),
    (
        "markdown",
        "Both arms fit on 50,000 CVEs and score on as many CVEs as development holds. The time arm "
        "draws its 50,000 from train (published before 2024) and scores on development (2024). The "
        "random arm pools train and development, holds out a random set the size of development, "
        "and draws its 50,000 from the rest.",
    ),
    (
        "code",
        """N = 50_000

def fit(rows):
    features = Features(variant)
    model, _ = floors.fit(features.fit_transform(rows), rows["band"].to_list(), c, SEED)
    return features, model

def kappa(fitted, rows):
    features, model = fitted
    guess = model.classes_[np.argmax(model.predict_proba(features.transform(rows)), axis=1)]
    return floors.score("qwk", rows["band"].to_list(), [str(g) for g in guess])

time_model = fit(train.sample(n=N, seed=SEED))
time_kappa = kappa(time_model, dev)

pool = pl.concat([train.select(dev.columns), dev]).sample(fraction=1.0, shuffle=True, seed=SEED)
held, rest = pool.head(dev.height), pool.tail(pool.height - dev.height)
random_model = fit(rest.sample(n=N, seed=SEED))
random_kappa = kappa(random_model, held)
print(f"split by time, scored on development: kappa {time_kappa:.3f}")
print(f"random split, scored on its holdout:  kappa {random_kappa:.3f}")
print(f"difference, random less time:         {random_kappa - time_kappa:+.3f}")""",
    ),
    (
        "markdown",
        "The two holdouts are different CVEs. Where the random holdout's CVEs come from, by publication "
        "year, against development, which is all 2024, and how often each year's CVEs carried a filer "
        "band on the day they were published. pandas does the counting.",
    ),
    (
        "code",
        """held_pd = held.select("published_year", "filer_band").to_pandas()
years = pd.DataFrame(
    {
        "random holdout": held_pd["published_year"].value_counts(normalize=True).sort_index() * 100,
        "development": dev["published_year"].to_pandas().value_counts(normalize=True).sort_index() * 100,
        "filer band at day 0": held_pd.groupby("published_year")["filer_band"].apply(lambda s: s.notna().mean() * 100),
    }
).fillna(0.0)
years.tail(8).round(1)""",
    ),
    (
        "markdown",
        "The same rows for both: the 2024 CVEs inside the random holdout. The time arm's model saw no "
        "2024 CVE. The random arm's model saw the other 2024 CVEs of the pool, from the same months, "
        "the same filers and the same bursts.",
    ),
    (
        "code",
        """same = held.filter(pl.col("published_year") == 2024)
on_same = {"time split": kappa(time_model, same), "random split": kappa(random_model, same)}
print(f"{same.height:,} CVEs from 2024 in the random holdout")
for name, value in on_same.items():
    print(f"{name:>12}: kappa {value:.3f}")
print(f"  difference: {on_same['random split'] - on_same['time split']:+.3f}")""",
    ),
    (
        "markdown",
        "Read together, the three results show what the random split hides. Scored on its own holdout "
        "it looks no better than the split by time, even a little worse, because that holdout is a "
        "different population: mostly CVEs from years when a filer seldom gave a band on the day of "
        "publication, which leaves the floor the text alone. Scored on the same 2024 CVEs, the random "
        "split's model is ahead, because it was fit on other CVEs from 2024, from the same months and "
        "filers, and from the first year in which most CVEs carried a filer band at publication. That "
        "lead is credit a random split hands the model and no deployment pays out: on the day a new "
        "CVE is scored, the CVEs published around it are not labelled yet. The build chooses every "
        "model on development and judges it once on test, both later than everything it was fit on "
        "(evaluation/phase2_plan.yaml, windows).",
    ),
]

NB05: list[Cell] = [
    (
        "markdown",
        "# 05, reading the misses\n\n"
        "The failure taxonomy of the plan: 100 band misses drawn with the default seed from "
        "development, never test, read one by one and coded into categories named while reading "
        "(scripts/draw_misses.py draws them, results/models/taxonomy.json holds the codes). This "
        "notebook shows the misses as they were read and the counts the manifest carries.",
    ),
    ("code", SETUP),
    (
        "code",
        """misses = json.load(open("results/models/misses.json"))
taxonomy = json.load(open("results/models/taxonomy.json"))
print(f"{misses['drawn']} drawn from {misses['development_misses']:,} development misses of "
      f"{misses['development_rows_with_band']:,} CVEs with an NVD band, model {misses['model']}")
frame = pd.DataFrame(misses["misses"])
frame["code"] = frame["cve_id"].map(taxonomy["codes"])
frame[["cve_id", "filer", "filer_band", "predicted_band", "nvd_band", "code"]].head(12)""",
    ),
    (
        "code",
        """order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
step = frame.apply(lambda r: order.index(r["predicted_band"]) - order.index(r["nvd_band"]), axis=1)
values, counts = np.unique(np.abs(step), return_counts=True)
print("bands away from the NVD:", {int(v): int(n) for v, n in zip(values, counts)})
print("too high:", int((step > 0).sum()), "too low:", int((step < 0).sum()))""",
    ),
    (
        "code",
        """pd.DataFrame(taxonomy["categories"])[["name", "count", "meaning"]]""",
    ),
    (
        "markdown",
        "Each category was named while reading, not before; the meaning column is the sentence written "
        "for it then. The counts are in the manifest as models.taxonomy, and the console shows them on "
        "/app/models.",
    ),
]

NB06: list[Cell] = [
    (
        "markdown",
        "# 06, EPSS on day 30\n\n"
        "The exploitation model scores a CVE on the day it is published. EPSS can be read on any day "
        "after, and by day 30 it has seen a month of exploitation activity, scanning and write ups "
        "that the model never saw. Ranking development CVEs by EPSS at day 30 against the model at day "
        "0 is the comparison a hurried report would make; this notebook makes it, on development, and "
        "shows where its advantage comes from.",
    ),
    ("code", SETUP),
    (
        "code",
        """from unscheduled_models import rank

labels = pl.read_parquet("data/sets/development_labels.parquet")
inputs = pl.read_parquet("data/sets/development_inputs.parquet").select("cve_id", "published")
population = rank.population(labels.join(inputs, on="cve_id"))
scores = population.join(pl.read_parquet("data/models/rank/development_scores.parquet"), on="cve_id", how="left")
offsets = pl.read_parquet("data/bronze/epss_offsets/**/*.parquet", hive_partitioning=False)
truth = rank.truth(scores)
print(f"{scores.height:,} development CVEs in the rank population, {int(truth.sum())} listed in KEV within 180 days")
by = {"model at day 0": scores["exploit_lgbm"].to_numpy()}
for day in (1, 7, 30):
    one = offsets.filter(pl.col("offset_days") == day).select("cve_id", "epss").unique("cve_id")
    by[f"EPSS at day {day}"] = scores.select("cve_id").join(one, on="cve_id", how="left")["epss"].fill_null(-1.0).to_numpy()
table = pd.DataFrame({name: [rank.recall_at_top(truth, s)] for name, s in by.items()}, index=["recall in the top 5 percent"])
(table.T * 100).round(1)""",
    ),
    (
        "code",
        """days = scores.filter(pl.col("kev_180"))["days_to_kev"].to_numpy()
print("listed CVEs listed within 30 days of publication:", int((days <= 30).sum()), "of", len(days))
print("median days to listing:", float(np.median(days)))""",
    ),
    (
        "markdown",
        "On development, 90 of the 127 listings came within 30 days of publication and the median "
        "came after five days, so EPSS read on day 30, and on day 7 for most of them, was read after "
        "the listing it is scored against. Its lead over the model there is the label arriving early, "
        "not a better ranking on the day of publication. EPSS at day 1 is the nearest to a fair "
        "comparison, and on development it is ahead of the model too. The registered C2 reports EPSS "
        "at days 1, 7 and 30 beside the model, calls a difference whose interval holds zero a tie, "
        "and says which days have seen more than the model; it never ranks the model against day 30 "
        "as if the two had seen the same days.",
    ),
]

NOTEBOOKS = {
    "04": ("04_the_random_split", NB04),
    "05": ("05_reading_the_misses", NB05),
    "06": ("06_epss_on_day_30", NB06),
}


def main(argv: list[str] | None = None) -> int:
    os.chdir(ROOT)
    wanted = (argv if argv is not None else sys.argv[1:]) or list(NOTEBOOKS)
    for key in wanted:
        name, cells = NOTEBOOKS[key]
        print(f"notebooks: wrote {write(name, cells).relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
