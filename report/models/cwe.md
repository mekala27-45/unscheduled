# Model card: the weakness

unscheduled-cwe predicts the CWE the NVD would assign a CVE, from what was public at the end of the
day it was published. It is a head of the primary fill model, the CPU fallback of the plan, over the
most common CWEs of train and a class for every other one, scored by macro F1 so a rare weakness
counts as much as a common one. Every value is labeled as a prediction with its model and version.

## What it is for, and not for

It is for suggesting the likely weakness while the NVD field is empty, with the next candidates
beside the first. It is not for filing a CWE in anyone's name, not for a weakness outside the classes
it was fit on, which it can only call other, and not for a CVE published before 2024.

## The data and its window

The windows are cut by publication date (config/splits.yaml). Train, everything published before
2024, fits the model; development, all of 2024, chooses it; test, from 2025 to the end of March 2026,
judges it once; and the shadow window, from 15 April 2026 on, is where it predicts. The first two weeks
of April 2026 are a gap no model uses. Every input is the value known at the end of the publication
day (day 0), and the labels are what the NVD and KEV say at the lake cut.

It learns from the train CVEs with an NVD CWE, over 51 classes,
counting the class for every other CWE.

## The metrics, with intervals

On development the macro F1 is 0.437.
Test has not been scored yet.

## Against the floor

The floor reads the same text as TF-IDF beside the same filer and CISA values, including the
filer's own CWE set, on the same rows.
On development the floor's macro F1 is 0.527, its first candidate is right
for 71.0% of the CVEs and its first five hold the NVD's CWE for
94.1%.

## The calibration

The CWE head is scaled by its own temperature, fit on development by negative log likelihood like
the other heads. Conformal sets are fit for the band and the eight metrics only; for the CWE the
console shows the five most likely candidates and the probability of the first.

## The slices

The plan slices the fill models by the band kappa, so the slices are in the band card.

## The selection bias note

The NVD's labels are not a random sample of CVEs. Since 15 April 2026 it analyzes a chosen part of
the new ones, so a score on the CVEs it analyzed says less about the ones it skipped. The shadow CVEs
the NVD did analyze are weighted by the odds that a CVE like them was skipped, from the Phase 1 domain
classifier, and the band kappa is shown plain and weighted, never one without the other.
For the primary model's band: 0.379 plain and
0.399 weighted, on an effective sample of
933 CVEs, against 0.594 on development; for the floor,
0.453 and 0.442.
The filer's own values are features, and they are missing for many CVEs.
On development the floor's band agrees with the NVD at 0.719
on the CVEs whose filer gave a band and at 0.574 on
the rest.
The slices by filer and filer type in the band card show where the model stands on each.

## The limits

- The filer's CWE set at day 0 is a feature, so the head can repeat a filer's CWE the NVD would
  change, and where the filer named none it reads the text alone.
- A miss can be a near miss, a parent or a child of the NVD's CWE in the CWE tree, and the metrics
  count it as wrong.
- One seed, one draw, and nothing after day 0.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
