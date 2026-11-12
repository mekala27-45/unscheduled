# Method notes: the backlog questions

Each question was written into evaluation/phase1_plan.yaml with its population, its estimator and
a prediction, and the plan was hashed into evaluation/registration.json (hash
78bf9cdfad9d) before any result was computed. This page sets each registered prediction
beside what the build measured, so a reader can see where the data agreed with the plan and where
it did not. report/backlog.md has every question in full, with its intervals and its tables.

Unless a question says otherwise, an interval is a cluster bootstrap by filer, 2000 resamples, 95 percent, and a family of
comparisons is corrected by Benjamini-Hochberg at 0.05. Every count says of what and in
which window, and every share says of which base.

## Q1. The analysis delay

- Population: CVEs published since 2020-01-01, rejected CVEs excluded.
- Estimator: share reaching NVD Analyzed within 7, 30 and 90 days, by month; median days to analysis.
- Registered prediction: the 30 day share falls after 2024 and again after 2026-04-15.
- Measured: the share analyzed within 30 days was 80.2% before
  2025, 43.6% from 2025 to 15 April 2026 and
  40.4% since. The first change moved it
  -36.6 pts (adjusted p
  0.002); the second
  -3.2 pts (adjusted p
  0.981).

## Q2. After the change

- Population: CVEs published since 2026-04-15.
- Estimator: counts by NVD status; share analyzed; share of analyzed that are in KEV; hours from KEV listing to NVD analysis.
- Registered prediction: most analyzed CVEs since the change are KEV listed or critical software.
- Measured: 37.4% analyzed; KEV listed CVEs are
  0.5% of everything analyzed; KEV listings met the one
  business day goal 96.9% of the time. Which software
  NIST counts as critical is in no locked source, so that part of the prediction is not measured.

## Q3. What the filer gives instead

- Population: CVEs without NVD analysis, every window.
- Estimator: share with a filer CVSS 3.x, a filer CVSS 4.0, a CWE, affected versions, a CISA ADP value; top twenty filers.
- Registered prediction: most carry a filer CVSS score; fewer carry affected versions.
- Measured: a filer CVSS score on 83.9% and affected versions on
  94.3% of 80,094 CVEs.

## Q4. Can a filer score stand in for the NVD

- Population: CVEs scored by both the filer and the NVD, train, development and shadow windows only.
- Estimator: Cohen kappa per CVSS 3.1 base metric; quadratic weighted kappa on the severity band; by filer type; direction of disagreement.
- Registered prediction: substantial agreement on attack vector, weaker on privileges and scope.
- Measured: kappa 0.84 on the attack vector,
  0.68 on privileges required, 0.54 on scope and
  0.27 on attack complexity; weighted kappa 0.49
  on the band.

## Q5. Exploited, and when

- Population: KEV listed CVEs published since 2021-01-01.
- Estimator: days from publication to listing; share with no NVD analysis at listing, as of; share with exploit code before listing.
- Registered prediction: a large share is listed within weeks; exploit code often precedes listing.
- Measured: half were listed within 26.0 days,
  51.4% within 30 days, and
  26.7% had Metasploit or Nuclei code before the listing.

## Q6. Who files the flood

- Population: CVEs published since 2020-01-01.
- Estimator: monthly share by filer and filer type; filers behind the growth.
- Registered prediction: a few filers account for most of the growth.
- Measured: the ten filers that grew most carry 76.7% of the
  growth, and 5 filers carry half of it.

## Q7. The customer exposure

- Population: the six stand in SBOMs, as of the pin date and today.
- Estimator: findings by NVD status, KEV listed, fix available, what a CPE matcher misses.
- Registered prediction: a large share of findings has no NVD analysis.
- Measured: 47.6% of today's findings have no NVD
  analysis, and a triage reading only NVD analysis could act on
  33.0% of them.

## Q8. How different the skipped CVEs are

- Population: CVEs published in the shadow window, held out half for scoring.
- Estimator: logistic regression domain classifier on filer, filer type, CWE, month, vector presence and description TF-IDF; AUC with interval; top features.
- Registered prediction: the classifier separates them well, so NVD labels alone would bias a model.
- Measured: an AUC of 0.886 (0.827 to
  0.928) on the held out half.

## When the data disagreed with the plan

A prediction that did not hold stays as it was registered; the plan is not edited after a result.
Where a question had to depart from the plan (a population narrowed, a window cut), the departure
is written in the question's result file under results/backlog and in DECISIONS.md, with the
reason.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
