# Model card: the base metrics

unscheduled-metrics predicts the eight CVSS 3.1 base metrics the NVD would set for a CVE, from what
was public at the end of the day it was published: attack vector, attack complexity, privileges
required, user interaction, scope, and the three impacts. Each metric is a head of the primary fill
model, the CPU fallback of the plan, and each is scored by Cohen's kappa against the NVD. Every value
is labeled as a prediction with its model and version.

## What it is for, and not for

It is for showing a reader which parts of a vector the text and the filer's values point to while
the NVD field is empty, each with its probability and its conformal set. It is not for writing a
CVSS vector or score in anyone's name, and not for a CVE published before 2024, which every model was
fit on. The band the eight metrics imply is computed and reported beside the band head, never in its
place.

## The data and its window

The windows are cut by publication date (config/splits.yaml). Train, everything published before
2024, fits the model; development, all of 2024, chooses it; test, from 2025 to the end of March 2026,
judges it once; and the shadow window, from 15 April 2026 on, is where it predicts. The first two weeks
of April 2026 are a gap no model uses. Every input is the value known at the end of the publication
day (day 0), and the labels are what the NVD and KEV say at the lake cut.

It learns from the train CVEs with an NVD CVSS 3.1 vector, and each head's C is chosen on development
by its kappa.

## The metrics, with intervals

| Metric | Development, model | Development, floor | Test, model | Test, floor |
|---|---:|---:|---:|---:|
| Attack vector | 0.788 | 0.849 | not yet | not yet |
| Attack complexity | 0.425 | 0.529 | not yet | not yet |
| Privileges required | 0.561 | 0.607 | not yet | not yet |
| User interaction | 0.853 | 0.913 | not yet | not yet |
| Scope | 0.871 | 0.913 | not yet | not yet |
| Confidentiality | 0.687 | 0.775 | not yet | not yet |
| Integrity | 0.702 | 0.793 | not yet | not yet |
| Availability | 0.760 | 0.817 | not yet | not yet |

The kappas are point values; no criterion is set on a single metric, and the band's interval is in
the band card.

## Against the floor

The floor reads the same text as TF-IDF beside the same filer and CISA values, one logistic
regression per metric, on the same rows.
The table above gives both on each window.
The floor's mean development kappa over the eight is 0.774.

## The calibration

Each head is scaled by its own temperature, fit on development by negative log likelihood, and its
conformal sets are fit on the scaled development probabilities.

## The slices

The plan slices the fill models by the band kappa, so the slices are in the band card.

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

- A filer's vector, when there is one, is a feature, so a head can repeat a filer's metric that the
  NVD would change.
- On development the floor agrees with the NVD least on attack complexity and privileges required,
  and those are the two heads to read with the most care.
- One seed, one draw, and nothing after day 0.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
