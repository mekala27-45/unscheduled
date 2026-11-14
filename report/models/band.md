# Model card: the severity band

unscheduled-band predicts the band the NVD would give a CVE under CVSS 3.1, one of LOW, MEDIUM, HIGH
and CRITICAL, from what was public at the end of the day the CVE was published. It is the band head
of the primary fill model, the CPU fallback the plan names for when ModernBERT cannot run: embeddings
of the joined text beside the floor's filer and CISA block, and a logistic regression. Every value it
gives is labeled as a prediction with its model and version, never as an NVD value.

## What it is for, and not for

It is for ordering the CVEs the NVD has not analyzed by likely severity, and for showing a band with
its probability and its conformal set where the NVD field is empty. It is not for replacing the
NVD's analysis, not for a compliance, legal or regulatory decision, and not for a CVE published
before 2024: every model was fit on those, so the API serves them no prediction.

## The data and its window

The windows are cut by publication date (config/splits.yaml). Train, everything published before
2024, fits the model; development, all of 2024, chooses it; test, from 2025 to the end of March 2026,
judges it once; and the shadow window, from 15 April 2026 on, is where it predicts. The first two weeks
of April 2026 are a gap no model uses. Every input is the value known at the end of the publication
day (day 0), and the labels are what the NVD and KEV say at the lake cut.

It learns from the train CVEs with an NVD band and is chosen on the development CVEs with one.

| Window | CVEs | NVD band | KEV within 180 days | Filer band at day 0 | Description |
|---|---:|---:|---:|---:|---:|
| train | 220,803 | 101,427 | 278 | 1.3% | 100.0% |
| development | 39,924 | 23,272 | 127 | 60.6% | 100.0% |
| test | 63,304 | 22,453 | 211 | 58.0% | 100.0% |
| shadow | 78,676 | 7,782 | 155 | 61.7% | 100.0% |

## The metrics, with intervals

On development the band reaches a quadratic weighted kappa of 0.594.

Test has not been scored yet. C1 is judged once, by scripts/score_test.py, after the operating points
are frozen.

## Against the floor

The floor is TF-IDF over the same joined text beside the same filer and CISA values, and a logistic
regression, fit on the same rows.
On development the floor reaches 0.669, the model 0.594 and the
embedding without the structured block 0.462.
The model is behind its floor before test is read: the TF-IDF grams of the joined text carry more of
the NVD band than the frozen embedding does, with the same structured block on both sides.

## The calibration

The band head is scaled by one temperature fit on development by negative log likelihood, and its
conformal sets are fit on the scaled development probabilities.

## The slices

The band kappa of the model against the floor in each slice, with Benjamini-Hochberg at the plan's
level within each family.

The slices are computed in the single test scoring, which has not run yet.

## The selection bias note

The NVD's labels are not a random sample of CVEs. Since 15 April 2026 it analyzes a chosen part of
the new ones, so a score on the CVEs it analyzed says less about the ones it skipped. The shadow CVEs
the NVD did analyze are weighted by the odds that a CVE like them was skipped, from the Phase 1 domain
classifier, and the band kappa is shown plain and weighted, never one without the other.
The weighted view is not in the manifest yet.
The filer's own values are features, and they are missing for many CVEs.
On development the floor's band agrees with the NVD at 0.719
on the CVEs whose filer gave a band and at 0.574 on
the rest.
The slices by filer and filer type in the band card show where the model stands on each.

## The limits

- The NVD band is the label, and the NVD is one analyst team with its own habits; agreement with it
  is agreement with those habits.
- A CVE with a short description and no filer vector gives the model little to read; its
  probabilities and the width of its set are where that shows.
- The model was chosen once and scored once with one seed; one seed is one draw.
- It never sees anything after day 0, so a later fact that changes the severity, such as a public
  exploit, does not move its band.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
