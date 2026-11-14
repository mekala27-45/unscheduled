# The models

Phase 2 fills in what the NVD no longer writes for most new CVEs and ranks them by the chance of
exploitation. Six registered models do it, each with a card in report/models/ that says what it is
for and not for, its data and window, its metrics with intervals, its floor, its calibration, its
slices, the selection bias it carries and its limits. Every number below is read from the manifest;
the method notes are in docs/models.md.

## The two criteria

C1: For test CVEs the NVD analyzed, the predicted severity band agrees with the NVD band at a quadratic weighted kappa of at least 0.60, beats the TF-IDF floor with the lower bound of the paired 95 percent interval above zero, and has an expected calibration error at or below 0.05.

Not scored yet: test is scored once, after the operating points are frozen.

C2: Scored on the day of publication, the top 5 percent by the exploitation score holds at least half of the test CVEs listed in KEV within 180 days. EPSS at days 1, 7 and 30 is reported beside it, and a difference inside the interval is a tie.

Not scored yet.

## The cards

| Card | Registered model | What it gives |
|---|---|---|
| report/models/band.md | unscheduled-band | The CVSS 3.1 severity band, with its probability and conformal set |
| report/models/metrics.md | unscheduled-metrics | The eight CVSS 3.1 base metrics, each with its set |
| report/models/cwe.md | unscheduled-cwe | The weakness, with the five most likely |
| report/models/exploit.md | unscheduled-exploit | The chance of a KEV listing within 180 days, ranked on day 0 |
| report/models/survival.md | unscheduled-survival | The chance of a listing within 30 days, 90 days and 180 days |
| report/models/product.md | unscheduled-product | Candidate vendor and product names from the CPE dictionary |


## What the plan said before any result

These were written into evaluation/phase2_plan.yaml and hashed before any model was fit. They are
kept as written, to be read against the cards.

- The band floor reaches a test kappa near the Phase 1 filer against NVD agreement, and the text model beats it by a few points.
- Calibration error is small on development and larger on test, because the vendor mix moves.
- Conformal coverage on test falls a little short of 90 percent for the same reason.
- The exploitation model holds more KEV listings in its top 5 percent than EPSS at day 1, and the gap to EPSS at day 30 is a tie or a loss.
- The reweighted band kappa is lower than the plain one.


> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
