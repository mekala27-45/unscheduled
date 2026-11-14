# Model card: the affected product

unscheduled-product names the vendor and product a CVE most likely affects, as a ranked list of
names from the NVD CPE dictionary, from what was public at the end of the publication day. The floor
normalizes the filer's own vendor and product strings and matches them to the dictionary, exactly
and then by a token set ratio; the retrieval ranks every dictionary vendor and product by the cosine
of its name's embedding to the CVE's joined text. Development chooses between them by recall in the
first ten candidates.

## What it is for, and not for

It is for pointing a reader at the likely product while the NVD has written no configuration, and
for joining a CVE to an inventory when the filer's strings do not match a CPE name exactly. It is not
a CPE match: it names a vendor and product pair, never a version range, and it says nothing about
whether a given installation is affected.

## The data and its window

The windows are cut by publication date (config/splits.yaml). Train, everything published before
2024, fits the model; development, all of 2024, chooses it; test, from 2025 to the end of March 2026,
judges it once; and the shadow window, from 15 April 2026 on, is where it predicts. The first two weeks
of April 2026 are a gap no model uses. Every input is the value known at the end of the publication
day (day 0), and the labels are what the NVD and KEV say at the lake cut.

The labels are the vendor and product pairs in the NVD's configurations, so only analyzed CVEs have
them. A CVE is offered only the pairs the NVD had created a CPE name for by the end of its
publication day, since the NVD often creates the name while it analyzes the CVE, which would put the
answer among the candidates (DECISIONS.md, the change request on the product floor's threshold).
The dictionary holds 153,543 vendor and product pairs at the lake
cut.

## The metrics, with intervals

Recall at a depth is, per CVE with a label, the share of its labeled pairs among that many first
candidates, averaged over the CVEs.

| On development | First candidate | First five | First ten |
|---|---:|---:|---:|
| The floor | 19.8% | 42.1% | 43.9% |
| The floor at its threshold | 19.1% | 40.6% | 42.1% |
| The retrieval | 19.2% | 30.8% | 34.5% |

These are over the 32,161 development CVEs with a labeled product.

| On test, scored once | First candidate | First five | First ten |
|---|---:|---:|---:|
| The floor | 0.251 | 0.469 | 0.491 |
| The floor at its threshold | 0.244 | 0.455 | 0.473 |
| The retrieval | 0.224 | 0.339 | 0.372 |

These are point values; the plan sets no criterion on the affected product.

## Against the floor

The string floor is the comparator the retrieval has to beat, on the same CVEs and the same
dictionary as of each CVE's day 0.
The floor's threshold on the token set ratio is 90, chosen on
development by the F1 of each CVE's first candidate.
At ten candidates, the depth the registry chooses by, the retrieval is behind the floor with its
threshold: the filer's own strings, normalized, name the product more often than the embedding of the
description finds it.

## The calibration

The candidates are ranked, not given probabilities, so there is nothing to calibrate. The console
lists them in order, as candidates to check and not as a match.

## The slices

The plan does not slice the affected product.

## The selection bias note

Only the CVEs the NVD analyzed have a labeled product, and since 15 April 2026 it analyzes a chosen
part of the new ones, so the recall above is measured on the CVEs it chose to analyze.

## The limits

- A filer that writes no vendor or product gives the floor nothing to match, and the retrieval reads
  the description alone.
- The dictionary names a product as the NVD spells it; a product the NVD has never named cannot be a
  candidate.
- It reads nothing after day 0: a product that the filer or an advisory names later does not change
  the candidates.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
