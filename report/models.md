# The models

Phase 2 fills in what the NVD no longer writes for most new CVEs and ranks them by the chance of
exploitation. Six registered models do it, each with a card in report/models/ that says what it is
for and not for, its data and window, its metrics with intervals, its floor, its calibration, its
slices, the selection bias it carries and its limits. Every number below is read from the manifest;
the method notes are in docs/models.md.

## The two criteria

C1: For test CVEs the NVD analyzed, the predicted severity band agrees with the NVD band at a quadratic weighted kappa of at least 0.60, beats the TF-IDF floor with the lower bound of the paired 95 percent interval above zero, and has an expected calibration error at or below 0.05.

The band's test kappa is 0.591 (0.364 to
0.693), the floor's 0.649, the paired
difference -0.057 (-0.108 to
-0.019) and the calibration error 0.053.
**C1 is not met.**

C2: Scored on the day of publication, the top 5 percent by the exploitation score holds at least half of the test CVEs listed in KEV within 180 days. EPSS at days 1, 7 and 30 is reported beside it, and a difference inside the interval is a tie.

The model's top five percent holds 43.6% (36.6%
to 50.0%) of the 211 test CVEs listed
within 180 days. EPSS holds 41.7% at day 1
(tie), 66.8% at day 7
(behind) and 75.8% at day 30
(behind). **C2 is not met.**

## What the misses say

C1 judges the primary fill model, the CPU fallback the plan names for when ModernBERT cannot run, and
on test it is behind its own floor: the paired difference is -0.057, with the whole
interval below zero. The TF-IDF floor, on the same rows, reaches 0.649. So the miss
says that a frozen sentence embedding carries less of the NVD band than the word and character grams of
the same text; it says nothing yet about a model fine tuned on the task, since ModernBERT has not run
(ADR 0009), and a later run is judged against the same floor (ADR 0010).

C2 asks for half of the later KEV listings in the top five percent on the day a CVE is published, and
the model holds 43.6%. Against its logistic floor the reading is tie, against EPSS on day 1
tie, and EPSS on day 7 and day 30, which has seen a week and a month of exploitation
activity, holds 66.8% and 75.8%.
On these test CVEs, what is public on day 0 orders the later listings about as well as EPSS does on
day 1, and no better; the gain comes with the days after publication.

## The cards

| Card | Registered model | What it gives |
|---|---|---|
| report/models/band.md | unscheduled-band | The CVSS 3.1 severity band, with its probability and conformal set |
| report/models/metrics.md | unscheduled-metrics | The eight CVSS 3.1 base metrics, each with its set |
| report/models/cwe.md | unscheduled-cwe | The weakness, with the five most likely |
| report/models/exploit.md | unscheduled-exploit | The chance of a KEV listing within 180 days, ranked on day 0 |
| report/models/survival.md | unscheduled-survival | The chance of a listing within 30 days, 90 days and 180 days |
| report/models/product.md | unscheduled-product | Candidate vendor and product names from the CPE dictionary |

## The registry

The registry holds 15 versions over 6 registered
models; each is a candidate, chosen on development, or scored on test.

| Registered model | Version | Role | Stage | Run |
|---|---:|---|---|---|
| unscheduled-band | 1 | floor | scored | band floor |
| unscheduled-band | 2 | ablation | scored | band text alone |
| unscheduled-band | 3 | model | scored | band model |
| unscheduled-metrics | 1 | floor | scored | metrics floor |
| unscheduled-metrics | 2 | ablation | scored | metrics text alone |
| unscheduled-metrics | 3 | model | scored | metrics model |
| unscheduled-cwe | 1 | floor | scored | cwe floor |
| unscheduled-cwe | 2 | ablation | scored | cwe text alone |
| unscheduled-cwe | 3 | model | scored | cwe model |
| unscheduled-exploit | 1 | floor | scored | exploitation floor |
| unscheduled-exploit | 2 | model | scored | exploitation model |
| unscheduled-survival | 1 | floor | scored | survival Cox |
| unscheduled-survival | 2 | model | scored | survival forest |
| unscheduled-product | 1 | floor | scored | product floor |
| unscheduled-product | 2 | model | scored | product retrieval |

## What the plan said before any result

These were written into evaluation/phase2_plan.yaml and hashed before any model was fit. They are
kept as written, to be read against the cards.

- The band floor reaches a test kappa near the Phase 1 filer against NVD agreement, and the text model beats it by a few points.
- Calibration error is small on development and larger on test, because the vendor mix moves.
- Conformal coverage on test falls a little short of 90 percent for the same reason.
- The exploitation model holds more KEV listings in its top 5 percent than EPSS at day 1, and the gap to EPSS at day 30 is a tie or a loss.
- The reweighted band kappa is lower than the plain one.

## The misses, read

These 100 misses were drawn with the default seed from the
7,757 development band misses of the primary model, and coded by reading
into categories named while reading. None comes from test.

| Category | Misses | What it means |
|---|---:|---|
| A kernel or hypervisor fix that states no impact | 27 | a Linux or Xen commit message names the bug and its fix but not what an attacker gains; the NVD's band, mostly 5.5 or 7.8, rests on a reading the text does not give |
| The NVD rescored the filer's vector | 21 | the filer gave a CVSS 3 vector and its band, the NVD changed one or more metrics into another band, and the model stayed with the filer |
| A word's usual band, wrong for this CVE | 14 | the model followed a word in the text, a weakness class or VulDB's own rating of critical or problematic, to the band it usually means, while the NVD scored the details, such as an admin only page or an adjacent network |
| The model left a band that agreed with the NVD | 14 | the filer's band or the CISA ADP band matched the NVD's, and the model moved off it, often toward the band its weakness class usually takes |
| A short text with no score, scored severe by the NVD | 8 | a sentence or two and no filer vector; the NVD assumed the worst case the text allows, and the model spread its probability |
| The filer scored in CVSS 4.0 alone | 8 | a CVSS 4.0 vector gives no CVSS 3 band or base metrics, so the model had only the vector string to go on |
| The text states the impact and the model misread it | 8 | the description says what an attacker gets, often in a vendor's stock phrase, and the model's band does not follow it |

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
