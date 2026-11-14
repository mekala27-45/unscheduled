# Model card: the time to KEV

unscheduled-survival estimates when a CVE will be listed in KEV, as the probability of a listing
within 30 days, within 90 days and within 180 days of publication, from what was public at the end of
the publication day. Two models are fit, a Cox proportional hazards model and a random survival
forest, and development chooses between them by concordance. The R check refits the Cox model in R and compares.

## What it is for, and not for

It is for saying how soon a CVE the exploitation score ranks high is likely to reach KEV, so a
reviewer can tell an urgent listing from a slow one. It is not a forecast of exploitation itself, and
not a probability for any one CVE to bet on: KEV listings are rare and the curves are averages over
CVEs like it. C1 and C2 do not judge it.

## The data and its window

The windows are cut by publication date (config/splits.yaml). Train, everything published before
2024, fits the model; development, all of 2024, chooses it; test, from 2025 to the end of March 2026,
judges it once; and the shadow window, from 15 April 2026 on, is where it predicts. The first two weeks
of April 2026 are a gap no model uses. Every input is the value known at the end of the publication
day (day 0), and the labels are what the NVD and KEV say at the lake cut.

The population is the exploitation population: CVEs published from 7 May 2021, Q03 left out. The time
is the days from publication to the listing, censored at the lake cut for a CVE not listed by then.
The models read the day 0 features without the text (DECISIONS.md, the survival models, as built).
Train holds 393 listings, and the design keeps
21 columns.

## The metrics, with intervals

On development the Cox model's concordance is 0.778, at a
penalty of 0.01, and the forest's
0.774, with leaves of at least
100 CVEs. Development chooses by concordance, a tie
going to the floor (DECISIONS.md, the registry).
Test has not been scored yet.

## Against the floor

The Cox model is the floor and the forest the model, both on the same rows and the same columns, so
the forest has to earn its place by concordance on development.

## The R check

R's survival::coxph fits the same design matrix without a penalty, and the plan's tolerance is
coefficients within 0.001 absolute and concordance within 0.002 of lifelines unpenalized.
The largest coefficient difference is 7.2e-08
and the concordance difference 0.0000; the recorded
result is pass.

## The calibration

The survival probabilities are not recalibrated; the curves are the models' own. The console draws
them as estimates, labeled with the model and version.

## The slices

The plan does not slice the survival models.

## The selection bias note

KEV is a lower bound on exploitation, and a listing date is the day CISA added the CVE to the
catalog, after exploitation was seen, so the time measured is the time to a listing, not to the first
attack. Censoring at the lake cut means the latest CVEs have had the least time to be listed.

## The limits

- The listings in train number in the hundreds, so the hazard of any one column rests on few events.
- The Cox model assumes the effect of each column is constant over time; the forest does not, and
  development compares the two.
- Each model was fit once, the forest with one seed, and neither reads anything after day 0.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
