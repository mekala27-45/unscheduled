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

On the 22,453 test CVEs with an NVD band, scored once, the kappa is
0.591 (0.364 to 0.693) and
the expected calibration error 0.053 (0.044 to
0.066). The intervals are a cluster bootstrap by filer, 2000 resamples, 95 percent, over
274 filers. The band computed from the eight predicted base metrics
reaches 0.530, reported beside the band head and
never in its place. C1 is not met.

## Against the floor

The floor is TF-IDF over the same joined text beside the same filer and CISA values, and a logistic
regression, fit on the same rows.
On development the floor reaches 0.669, the model 0.594 and the
embedding without the structured block 0.462.
The model is behind its floor before test is read: the TF-IDF grams of the joined text carry more of
the NVD band than the frozen embedding does, with the same structured block on both sides.
On test the floor's kappa is 0.649 (0.467
to 0.729), and the paired difference, model less floor, is
-0.057 (-0.108 to
-0.019).

## The calibration

The band head is scaled by one temperature fit on development by negative log likelihood, and its
conformal sets are fit on the scaled development probabilities.
The temperature is 1.16. The development calibration error
is 0.048 before scaling and
0.019 after, and the mean development set holds
2.14 bands.
On test the sets cover 96.1% of the bands with a mean size of
2.29. Test is later than development, so the coverage a set
promises holds only for CVEs like the ones it was fit on; by filer type:

| Filer type | CVEs | Coverage | Mean set size |
|---|---:|---:|---:|
| MITRE | 793 | 91.9% | 2.39 |
| national CERT | 739 | 96.6% | 2.07 |
| open source project | 9,751 | 97.3% | 2.51 |
| other | 399 | 93.2% | 2.47 |
| research or bug bounty platform | 7,054 | 96.4% | 2.03 |
| vendor | 3,717 | 93.7% | 2.19 |

## The slices

Each slice compares the model's band kappa with the floor's, with Benjamini-Hochberg at the plan's
level within each family.

### By filer type

| Slice | CVEs | Model | Comparator | Difference | Adjusted p | Significant |
|---|---:|---:|---:|---:|---:|---|
| open source project | 9,751 | 0.321 | 0.430 | -0.109 | 0.003 | yes |
| research or bug bounty platform | 7,054 | 0.702 | 0.737 | -0.035 | 0.003 | yes |
| vendor | 3,717 | 0.498 | 0.527 | -0.029 | 0.027 | yes |
| MITRE | 793 | 0.475 | 0.518 | -0.043 | 0.055 | no |
| national CERT | 739 | 0.611 | 0.675 | -0.065 | 0.020 | yes |
| other | 399 | 0.437 | 0.459 | -0.022 | 0.584 | no |

### By year of publication

| Slice | CVEs | Model | Comparator | Difference | Adjusted p | Significant |
|---|---:|---:|---:|---:|---:|---|
| 2025 | 16,763 | 0.622 | 0.684 | -0.062 | 0.002 | yes |
| 2026 | 5,690 | 0.493 | 0.528 | -0.035 | 0.002 | yes |

### By filer, the twenty largest

| Slice | CVEs | Model | Comparator | Difference | Adjusted p | Significant |
|---|---:|---:|---:|---:|---:|---|
| VulDB | 5,070 | 0.714 | 0.741 | -0.027 | 0.003 | yes |
| Linux | 4,675 | 0.075 | 0.239 | -0.163 | 0.003 | yes |
| GitHub_M | 3,424 | 0.432 | 0.503 | -0.071 | 0.003 | yes |
| VulnCheck | 1,104 | 0.561 | 0.638 | -0.077 | 0.003 | yes |
| mitre | 793 | 0.475 | 0.518 | -0.043 | 0.102 | no |
| Wordfence | 585 | 0.749 | 0.782 | -0.033 | 0.234 | no |
| ibm | 371 | 0.442 | 0.458 | -0.015 | 0.735 | no |
| INCIBE | 346 | 0.669 | 0.759 | -0.091 | 0.009 | yes |
| Patchstack | 328 | 0.691 | 0.667 | +0.024 | 0.556 | no |
| huawei | 253 | 0.173 | 0.114 | +0.060 | 0.391 | no |
| qnap | 234 | 0.438 | 0.224 | +0.214 | 0.003 | yes |
| apple | 202 | 0.416 | 0.420 | -0.004 | 0.961 | no |
| SamsungMobile | 196 | 0.286 | 0.330 | -0.044 | 0.735 | no |
| microsoft | 165 | 0.411 | 0.534 | -0.123 | 0.057 | no |
| fortinet | 153 | 0.612 | 0.648 | -0.035 | 0.632 | no |
| dell | 147 | 0.626 | 0.614 | +0.011 | 0.819 | no |
| @huntr_ai | 146 | 0.554 | 0.583 | -0.029 | 0.715 | no |
| Liferay | 142 | 0.336 | 0.369 | -0.032 | 0.819 | no |
| GitLab | 140 | 0.178 | 0.151 | +0.027 | 0.784 | no |
| talos | 138 | 0.478 | 0.705 | -0.227 | 0.003 | yes |

### By CWE, the twenty largest

| Slice | CVEs | Model | Comparator | Difference | Adjusted p | Significant |
|---|---:|---:|---:|---:|---:|---|
| (none) | 12,034 | 0.575 | 0.623 | -0.048 | 0.007 | yes |
| NVD-CWE-NOINFO | 2,319 | 0.226 | 0.301 | -0.075 | 0.008 | yes |
| other | 1,574 | 0.159 | 0.238 | -0.079 | 0.007 | yes |
| CWE-89 | 1,481 | 0.218 | 0.256 | -0.038 | 0.238 | no |
| CWE-476 | 977 | 0.044 | 0.110 | -0.066 | 0.008 | yes |
| CWE-79 | 676 | 0.297 | 0.342 | -0.046 | 0.257 | no |
| CWE-787 | 591 | 0.427 | 0.472 | -0.045 | 0.238 | no |
| CWE-416 | 424 | 0.120 | -0.012 | +0.132 | 0.074 | no |
| NVD-CWE-OTHER | 410 | 0.220 | 0.604 | -0.384 | 0.007 | yes |
| CWE-125 | 362 | 0.156 | 0.154 | +0.002 | 0.922 | no |
| CWE-434 | 209 | 0.384 | 0.408 | -0.024 | 0.917 | no |
| CWE-362 | 192 | 0.095 | 0.103 | -0.008 | 0.922 | no |
| CWE-120 | 171 | 0.393 | 0.455 | -0.062 | 0.461 | no |
| CWE-77 | 156 | 0.453 | 0.438 | +0.016 | 0.917 | no |
| CWE-78 | 140 | 0.380 | 0.372 | +0.007 | 0.922 | no |
| CWE-22 | 96 | 0.378 | 0.490 | -0.113 | 0.212 | no |
| CWE-190 | 95 | 0.242 | 0.032 | +0.210 | 0.070 | no |
| CWE-94 | 65 | 0.391 | 0.522 | -0.131 | 0.238 | no |
| CWE-862 | 62 | 0.635 | 0.590 | +0.045 | 0.917 | no |
| CWE-352 | 57 | 0.107 | 0.064 | +0.043 | 0.917 | no |

### By vendor, the twenty largest

| Slice | CVEs | Model | Comparator | Difference | Adjusted p | Significant |
|---|---:|---:|---:|---:|---:|---|
| linux | 4,676 | 0.075 | 0.238 | -0.163 | 0.005 | yes |
| code-projects | 798 | 0.707 | 0.740 | -0.033 | 0.005 | yes |
| phpgurukul | 506 | 0.753 | 0.746 | +0.007 | 0.784 | no |
|  | 473 | 0.565 | 0.638 | -0.073 | 0.005 | yes |
| (none) | 473 | 0.491 | 0.547 | -0.055 | 0.171 | no |
| sourcecodester | 384 | 0.623 | 0.642 | -0.019 | 0.442 | no |
| ibm | 371 | 0.442 | 0.458 | -0.015 | 0.784 | no |
| itsourcecode | 327 | 0.787 | 0.776 | +0.010 | 0.819 | no |
| campcodes | 311 | 0.746 | 0.720 | +0.026 | 0.784 | no |
| huawei | 253 | 0.173 | 0.114 | +0.060 | 0.442 | no |
| qnap systems inc. | 234 | 0.438 | 0.224 | +0.214 | 0.005 | yes |
| apple | 202 | 0.416 | 0.420 | -0.004 | 0.961 | no |
| samsung mobile | 196 | 0.286 | 0.330 | -0.044 | 0.784 | no |
| d-link | 189 | 0.396 | 0.281 | +0.115 | 0.028 | yes |
| microsoft | 167 | 0.394 | 0.545 | -0.151 | 0.030 | yes |
| fortinet | 153 | 0.612 | 0.648 | -0.035 | 0.747 | no |
| openclaw | 151 | 0.399 | 0.421 | -0.022 | 0.819 | no |
| dell | 147 | 0.626 | 0.614 | +0.011 | 0.819 | no |
| labredescefetrj | 142 | 0.742 | 0.787 | -0.045 | 0.172 | no |
| liferay | 142 | 0.336 | 0.369 | -0.032 | 0.819 | no |


## The selection bias note

The NVD's labels are not a random sample of CVEs. Since 15 April 2026 it analyzes a chosen part of
the new ones, so a score on the CVEs it analyzed says less about the ones it skipped. The shadow CVEs
the NVD did analyze are weighted by the odds that a CVE like them was skipped, from the Phase 1 domain
classifier, and the band kappa is shown plain and weighted, never one without the other.
The primary model's band kappa is 0.379 plain and
0.399 weighted, on an effective sample of
933 CVEs, against 0.594 on development; the floor's is
0.453 plain and 0.442 weighted.
The filer's own values are features, and they are missing for many CVEs.
On development the floor's band agrees with the NVD at 0.719
on the CVEs whose filer gave a band and at 0.574 on
the rest.
The slices above, by filer and by filer type, show where the model stands on each.

## The limits

- The NVD band is the label, and the NVD is one analyst team with its own habits; agreement with it
  is agreement with those habits.
- A CVE with a short description and no filer vector gives the model little to read; its
  probabilities and the width of its set are where that shows.
- The model was fit once and scored once, so its intervals carry the sampling error of test and not
  the variation between training runs.
- It never sees anything after day 0, so a later fact that changes the severity, such as a public
  exploit, does not move its band.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
