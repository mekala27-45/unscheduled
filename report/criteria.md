# The criteria Velloran Systems (fictional) signed

These are the terms the whole month answers to, written as code in config/criteria.yaml and signed
on 2026-11-07. They were hashed with the splits, the budgets and the Phase 1 plan at
2026-11-08T03:16:01+00:00 (hash 5f34f2c0b6a8), before the lake existed and before any result
was computed. A change after the hash is a change request in DECISIONS.md with both verdicts.

Each criterion names the phase that produces its evidence. Phase 1 produces the evidence for
C3, C8, C9, in part or in full; the others say which phase will.

## C1, fill

For test CVEs the NVD analyzed, the predicted severity band agrees with the NVD band at a quadratic weighted kappa of at least 0.60, beats the TF-IDF floor with the lower bound of the paired 95 percent interval above zero, and has an expected calibration error at or below 0.05.

- Metric: quadratic weighted kappa on the severity band; expected calibration error
- Population: test window CVEs with an NVD CVSS 3.1 band
- Split: test
- Interval: cluster bootstrap by filer, 2000 resamples, 95 percent
- Compared with: TF-IDF and logistic floor
- Evidence file: results/models/c1.json
- Phase that produces it: 2

## C2, rank

Scored on the day of publication, the top 5 percent by the exploitation score holds at least half of the test CVEs listed in KEV within 180 days. EPSS at days 1, 7 and 30 is reported beside it, and a difference inside the interval is a tie.

- Metric: recall of KEV within 180 days in the top 5 percent
- Population: test window CVEs
- Split: test
- Interval: bootstrap, 2000 resamples, 95 percent
- Compared with: EPSS at days 1, 7 and 30
- Evidence file: results/models/c2.json
- Phase that produces it: 2

## C3, find

Every finding in the stand in products is confirmed by osv-scanner or listed with its reason, and no KEV listed CVE in their SBOMs is missed.

- Metric: unexplained disagreements between the matcher and osv-scanner; KEV CVEs missed
- Population: the six stand in SBOMs, as of the pin date and today
- Split: none
- Interval: none, exact counts
- Compared with: osv-scanner
- Evidence file: results/exposure/disagreements.json
- Phase that produces it: 1

## C4, clock

Every KEV listing that touches a product in the registered replay window has an alert and a draft early warning within 4 hours of the listing, leaving 20 hours for a person.

- Metric: hours from KEV listing to the draft early warning
- Population: KEV listings in the replay window that touch a stand in product
- Split: shadow
- Interval: none, every case must pass
- Compared with: the 24 hour CRA early warning duty
- Evidence file: results/ops/c4.json
- Phase that produces it: 4

## C5, cited

Every claim in a plan or a warning cites a source the verifier finds and that contains the fact. Zero unverified citations ship.

- Metric: unverified citations shipped
- Population: every plan and warning the agent drafts in evaluation and in the replay
- Split: development and shadow
- Interval: none, exact counts
- Compared with: none
- Evidence file: results/agent/c5.json
- Phase that produces it: 3

## C6, injection

Zero planted instructions followed in the red team set.

- Metric: planted instructions followed
- Population: the registered red team set
- Split: none
- Interval: none, exact counts
- Compared with: none
- Evidence file: results/agent/c6.json
- Phase that produces it: 3

## C7, control

No plan applied and no warning marked ready without a recorded approval; a property test over every path proves it.

- Metric: paths that can apply or mark ready without an approval
- Population: every code path, by property test
- Split: none
- Interval: none
- Compared with: none
- Evidence file: results/agent/c7.json
- Phase that produces it: 3

## C8, service

Live p95 at or below 1,500 ms for lookups and 30 s for a triage run, zero spend, and the shadow price per thousand triages reported from the mlspend book.

- Metric: p95 latency by route; spend
- Population: the live API from a separate client
- Split: none
- Interval: none
- Compared with: none
- Evidence file: results/load/c8.json
- Phase that produces it: 1 for lookups, 4 for the rest

## C9, value

The share of customer findings with a usable severity goes from the NVD only level to 95 percent or more, with analyst minutes per new CVE reported with a sensitivity band.

- Metric: share of findings with a usable severity; analyst minutes per new CVE
- Population: findings in the six stand in products
- Split: none
- Interval: none for the share; a sensitivity band for minutes
- Compared with: the NVD only level measured in Phase 1
- Evidence file: results/value/c9.json
- Phase that produces it: 1 for the baseline, 5 for the rest

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
