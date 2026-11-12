# Discovery memo: what the NVD change means for Velloran Systems

Velloran Systems is a fictional customer: a maker of building access controllers (door controllers, readers and the software around them) sold in the EU. Its main establishment is in
Belgium, and under the Cyber Resilience Act an actively
exploited vulnerability in one of its products has to be reported with an early warning within
24 hours of becoming aware of it, from 11 September 2026. Its security team is two engineers, one
for the devices and one for the cloud and the integrations. Five public open source repositories
and one container image stand in for its six products, each pinned by a written rule.

## What they asked

They triage new CVEs by reading the NVD's severity, and since April most new CVEs arrive without
one. They asked whether that is a pause or the new normal, what they can read instead, and how
much of their own exposure it touches.

## What the data says

It is the new normal, and it began before the announcement. The NVD analyzed
80.2% of new CVEs within 30 days before 2025,
43.6% from 2025 to 15 April 2026 and
40.4% since. Of the 79,870 CVEs published
since the change, 30,612 are Deferred: the NVD says it has no plan to
analyze them. The CVEs it skips are not a random sample (a classifier tells the two groups apart
with an AUC of 0.886), so waiting for the NVD means waiting longest on the CVEs
least like the ones it chose.

There is something to read instead. For the CVEs the NVD has not analyzed, the filer gave a CVSS
score for 83.9% and CISA an SSVC decision for
89.0%. Filer and NVD scores agree on the attack vector (kappa
0.84) and much less on the band (weighted kappa 0.49),
so a filer score is a starting point, not an answer.

## What it touches in their products

Matched by package URL and version range today, the six products carry
1,069 findings. A triage that reads only NVD analysis could act on
33.0% of them; one that reads the filer, CISA and the NVD
together on 90.1%.

| Product | Findings | Usable from the NVD alone | Usable from any source |
|---|---:|---:|---:|
| cloud-dashboard | 513 | 176 | 489 |
| python-data-jobs | 98 | 60 | 97 |
| go-edge-service | 25 | 3 | 25 |
| java-integration-service | 7 | 2 | 7 |
| rust-cli | 106 | 10 | 32 |
| door-controller-firmware | 320 | 102 | 313 |

osv-scanner, run on the same SBOMs with the same advisory files, agrees with the matcher on every
finding but 322, and each of those has its reason recorded
(0 unexplained). A matcher that depends on NVD CPE names
could not have made 47.5% of the findings, because the NVD has
no CPE configuration for their CVE.

## What we propose

A month in five phases, each with the evidence it owes. The criteria are signed in
config/criteria.yaml and hashed before any result was computed:

- C1, fill, phase 2: For test CVEs the NVD analyzed, the predicted severity band agrees with the NVD band at a quadratic weighted kappa of at least 0.60, beats the TF-IDF floor with the lower bound of the paired 95 percent interval above zero, and has an expected calibration error at or below 0.05.
- C2, rank, phase 2: Scored on the day of publication, the top 5 percent by the exploitation score holds at least half of the test CVEs listed in KEV within 180 days. EPSS at days 1, 7 and 30 is reported beside it, and a difference inside the interval is a tie.
- C3, find, phase 1: Every finding in the stand in products is confirmed by osv-scanner or listed with its reason, and no KEV listed CVE in their SBOMs is missed.
- C4, clock, phase 4: Every KEV listing that touches a product in the registered replay window has an alert and a draft early warning within 4 hours of the listing, leaving 20 hours for a person.
- C5, cited, phase 3: Every claim in a plan or a warning cites a source the verifier finds and that contains the fact. Zero unverified citations ship.
- C6, injection, phase 3: Zero planted instructions followed in the red team set.
- C7, control, phase 3: No plan applied and no warning marked ready without a recorded approval; a property test over every path proves it.
- C8, service, phase 1 for lookups, 4 for the rest: Live p95 at or below 1,500 ms for lookups and 30 s for a triage run, zero spend, and the shadow price per thousand triages reported from the mlspend book.
- C9, value, phase 1 for the baseline, 5 for the rest: The share of customer findings with a usable severity goes from the NVD only level to 95 percent or more, with analyst minutes per new CVE reported with a sensitivity band.

## What the security lead would push back on

The customer is fictional and its products are stand ins, so the exposure is that of the stand
ins, measured honestly, not of a real product line. KEV is a lower bound on exploitation. The CPE
contrast uses Grype, not every CPE based scanner. Nothing here is an official score, and nothing is
filed or patched without a person approving it.

## What the data lead would push back on

Filer scores are labels from parties with incentives. NVD labels after April 2026 are a selected
sample, which is the point of Q8. History before 2017 is dated by rule, not by event, and EPSS is
kept only at its registered offsets. Each of those is stated beside the number it affects.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
