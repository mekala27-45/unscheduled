# The backlog, in words and numbers

On 15 April 2026 NIST said the NVD would analyze the CVEs it sees as the highest priority first
and mark the rest Deferred. This report measures what that means, from the lake as it stood at
2026-11-12: 424,534 CVE records and 6,620,931 dated facts
about them, every one with its source and the time it became known. Each number below is read from
results/manifest.json when this page is rendered, so the page cannot drift from the data.

Shares come with a 95 percent interval from a bootstrap that resamples filers, not CVEs, because the
CVEs of one filer share a template, a scoring habit and an editor. A value from fewer than five
filers is given without an interval. Where a question tests several things at once, the p-values
are adjusted with Benjamini-Hochberg over that question's family.

## Q1, the analysis delay

Share of new CVEs the NVD analyzed within 7, 30 and 90 days of publication, by month, since January 2020.

The NVD analyzed 80.2% of new CVEs within 30 days before 2025
(72.7% to 85.5%),
43.6% from 2025 to the change
(29.5% to 58.3%),
and 40.4% since
(29.2% to 55.6%).
The fall came before the change: from the first period to the second the 30 day share moved
-36.6 pts
(adjusted p 0.002), and from the
second to the third -3.2 pts
(adjusted p 0.981). The
announcement in April named what had already been happening since 2024.

When the NVD does analyze a CVE it is quick: the median among those analyzed is
6.8 days before 2025 and
5.2 days since the change. The delay is not slow
work; it is work not done. A CVE is judged at k days only once k days have passed, so the newest
months count only the CVEs old enough to judge.

The data lead would push back: a month whose CVEs have not all had 90 days is judged on fewer of
them, and the history before 2017 is dated by rule, not by event. Both are in the method; the
monthly table behind the chart has the count judged at each horizon beside each share.

## Q2, after the change

New CVEs since 15 April 2026 by NVD status, and how fast the NVD analyzes the ones in KEV.

Of 79,870 CVEs published since 15 April 2026, the NVD has analyzed
37.4% (26.3% to
50.8%). 30,612 carry the Deferred
status, 11,113 are awaiting analysis and
6,136 have only been received.

| NVD status | CVEs | Analyzed | KEV listed | KEV analyzed before listing | Median hours, listing to analysis |
|---|---:|---:|---:|---:|---:|
| Deferred | 30,612 | 0 | 0 | 0 | not applicable |
| Analyzed | 22,382 | 22,382 | 105 | 37 | 15.3 h |
| Awaiting Analysis | 11,113 | 0 | 0 | 0 | not applicable |
| Modified | 7,223 | 7,223 | 52 | 17 | 1.9 h |
| Received | 6,136 | 0 | 0 | 0 | not applicable |
| Rejected | 1,627 | 45 | 0 | 0 | not applicable |
| Undergoing Analysis | 776 | 204 | 2 | 0 | not applicable |
| not available | 1 | 0 | 0 | 0 | not applicable |

The KEV promise holds. Of the 159 CVEs published since the change and
listed in KEV, 96.9% had an NVD analysis within one
business day of the listing or before it; the median from listing to analysis is
14.0 h and the 90th percentile
21.2 h. KEV listed CVEs are
0.5% of everything analyzed, so the promise covers a
small part of the work. The plan also named software NIST counts as critical; no locked source says
which software that is, so that part is not measured.

## Q3, what the filer gives instead

For CVEs the NVD has not analyzed: the share with a filer CVSS, a CWE, affected versions or a CISA ADP value.

For the 80,094 CVEs the NVD has not analyzed, the filer gave a CVSS score for
83.9% (66.7% to
95.5%), a CWE for 83.3% and
affected versions for 94.3%. CISA's ADP container adds an SSVC
decision to 89.0% of them, but its own CVSS to only
11.6%. So almost every skipped CVE still comes with a score; the
question is whose.

| Filer | Filer type | CVEs | Filer CVSS 3.x | Filer CVSS 4.0 | Filer CWE | Affected versions | CISA ADP value |
|---|---|---:|---:|---:|---:|---:|---:|
| Patchstack | research or bug bounty platform | 14,422 | 99.9% | 0.1% | 100.0% | 100.0% | 99.4% |
| VulnCheck | research or bug bounty platform | 7,906 | 93.6% | 99.8% | 100.0% | 99.0% | 94.7% |
| GitHub_M | open source project | 7,717 | 68.8% | 31.3% | 100.0% | 100.0% | 96.5% |
| Wordfence | vendor | 7,509 | 100.0% | 0.0% | 99.9% | 100.0% | 99.8% |
| Linux | open source project | 6,392 | 37.9% | 0.0% | 0.0% | 100.0% | 20.6% |
| VulDB | research or bug bounty platform | 5,871 | 100.0% | 99.0% | 100.0% | 99.7% | 98.4% |
| mitre | MITRE | 4,783 | 17.8% | 1.9% | 16.8% | 16.8% | 99.7% |
| WPScan | open source project | 2,336 | 9.9% | 0.0% | 100.0% | 100.0% | 99.9% |
| redhat | open source project | 1,317 | 99.5% | 0.1% | 99.7% | 66.5% | 95.1% |
| microsoft | vendor | 1,204 | 100.0% | 0.0% | 99.6% | 99.1% | 9.1% |
| oracle | open source project | 783 | 100.0% | 0.0% | 0.0% | 100.0% | 99.9% |
| icscert | national CERT | 684 | 89.3% | 93.4% | 100.0% | 99.9% | 99.7% |
| TR-CERT | national CERT | 585 | 96.6% | 3.4% | 99.8% | 100.0% | 98.5% |
| apache | open source project | 581 | 13.9% | 27.2% | 95.0% | 100.0% | 82.1% |
| jpcert | national CERT | 579 | 84.6% | 64.6% | 85.7% | 100.0% | 99.1% |
| intel | open source project | 564 | 75.4% | 89.5% | 100.0% | 100.0% | 81.7% |
| ibm | open source project | 436 | 97.0% | 0.0% | 98.6% | 100.0% | 79.1% |
| sap | open source project | 415 | 100.0% | 0.0% | 99.5% | 100.0% | 89.9% |
| CERT-PL | national CERT | 399 | 0.8% | 97.5% | 100.0% | 100.0% | 100.0% |
| INCIBE | national CERT | 386 | 18.9% | 81.3% | 98.7% | 100.0% | 97.9% |

## Q4, can a filer score stand in for the NVD

Agreement between the filer's CVSS 3.1 vector and the NVD's, metric by metric and on the band.

On 47,641 CVEs scored with CVSS 3.1 by both their filer and the NVD, the two agree
well on the attack vector (kappa 0.84, 0.79 to
0.88) and poorly on attack complexity (kappa
0.27). On the severity band the weighted kappa is
0.49, and filers sit lower than the NVD on average
(-18.5 pts on the band). A filer score is a usable stand in for the vector's
reach and a weak one for its difficulty and its impact.

| Filer type | CVEs | Filers | Kappa AV | Kappa AC | Kappa PR | Kappa UI | Kappa S | Kappa C | Kappa I | Kappa A | Weighted kappa, band |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| MITRE | 1,200 | 1 | 0.68 | 0.18 | 0.74 | 0.60 | 0.23 | 0.63 | 0.65 | 0.61 | 0.58 |
| national CERT | 2,694 | 14 | 0.75 | 0.25 | 0.71 | 0.76 | 0.50 | 0.67 | 0.69 | 0.64 | 0.68 |
| open source project | 14,821 | 65 | 0.85 | 0.25 | 0.71 | 0.71 | 0.48 | 0.66 | 0.67 | 0.67 | 0.51 |
| other | 1,925 | 46 | 0.84 | 0.14 | 0.43 | 0.61 | 0.40 | 0.58 | 0.58 | 0.47 | 0.59 |
| research or bug bounty platform | 11,626 | 25 | 0.60 | 0.32 | 0.57 | 0.94 | 0.57 | 0.22 | 0.34 | 0.20 | 0.30 |
| unregistered | 476 | 4 | 0.86 | 0.26 | 0.80 | 0.63 | 0.38 | 0.71 | 0.78 | 0.74 | 0.62 |
| vendor | 14,899 | 139 | 0.89 | 0.26 | 0.76 | 0.60 | 0.63 | 0.74 | 0.77 | 0.69 | 0.63 |

The data lead would push back: a filer has reasons to score its own product low, and the NVD's
score is itself a label made by people. The agreement is between two labels, never with a truth.

## Q5, exploited, and when

KEV listed CVEs published since 2021: days to listing, NVD analysis at the moment of listing, exploit code before it.

Of 1,025 KEV listed CVEs published since 2021, half were listed within
26.0 days of publication (13.0 days
to 48.0 days), 51.4%
within 30 days. 45.9% had no NVD analysis at the
moment CISA listed them, and 26.7% had Metasploit or
Nuclei code before the listing. 62 listings dated before their
CVE's publication are held back by quarantine rule Q03.

| Published | CVEs | Median days to listing | Listed within 30 days | No NVD analysis at listing | Exploit code before listing |
|---|---:|---:|---:|---:|---:|
| 2021 | 212 | 208.0 days | 7.1% | 1.4% | 30.7% |
| 2022 | 100 | 67.0 days | 37.0% | 21.0% | 36.0% |
| 2023 | 154 | 8.0 days | 61.7% | 51.3% | 23.4% |
| 2024 | 156 | 16.0 days | 57.7% | 64.1% | 28.2% |
| 2025 | 190 | 10.0 days | 62.6% | 69.5% | 25.8% |
| 2026 | 213 | 5.0 days | 80.3% | 63.4% | 20.7% |

The security lead would push back: KEV is a lower bound on exploitation. A CVE outside KEV is not
a CVE nobody exploits; it is one CISA has not confirmed.

## Q6, who files the flood

Monthly CVE volume by filer and filer type since 2020, and the filers behind the growth.

288,482 CVEs since 2020 came from 508 filers. The volume of
the last twelve months is 101,079 against 19,362
in 2020, and the ten filers that grew most carry 76.7% of that
growth (61.3% to 84.2%);
5 filers carry half of it.

| Filer | Filer type | CVEs in 2020 | CVEs in the last 12 months | Change | Share of net growth |
|---|---|---:|---:|---:|---:|
| GitHub_M | open source project | 600 | 13,176 | 12,576 | 15.4% |
| VulnCheck | research or bug bounty platform | 0 | 10,820 | 10,820 | 13.2% |
| Linux | open source project | 0 | 9,440 | 9,440 | 11.6% |
| VulDB | research or bug bounty platform | 0 | 6,867 | 6,867 | 8.4% |
| Patchstack | research or bug bounty platform | 0 | 6,243 | 6,243 | 7.6% |
| Wordfence | vendor | 0 | 4,670 | 4,670 | 5.7% |
| Chrome | open source project | 262 | 3,758 | 3,496 | 4.3% |
| oracle | open source project | 811 | 4,155 | 3,344 | 4.1% |
| microsoft | vendor | 1,406 | 4,574 | 3,168 | 3.9% |
| WPScan | open source project | 0 | 2,065 | 2,065 | 2.5% |
| apache | open source project | 161 | 1,294 | 1,133 | 1.4% |
| ibm | open source project | 565 | 1,592 | 1,027 | 1.3% |
| apple | vendor | 463 | 1,457 | 994 | 1.2% |
| adobe | vendor | 349 | 1,216 | 867 | 1.1% |
| mozilla | open source project | 212 | 1,058 | 846 | 1.0% |
| redhat | open source project | 805 | 1,374 | 569 | 0.7% |
| dell | vendor | 73 | 637 | 564 | 0.7% |
| GitLab | vendor | 116 | 612 | 496 | 0.6% |
| fortinet | vendor | 45 | 466 | 421 | 0.5% |
| TR-CERT | national CERT | 0 | 396 | 396 | 0.5% |

## Q7, the exposure

Q7 is the customer's own: the findings for the six stand in products, matched by package URL and
version range and checked by osv-scanner. Across them today, 1,069
findings; a triage that read only NVD analysis could act on 33.0%
of them, and one that reads every source on 90.1%. The
discovery memo, report/discovery.md, sets that out product by product.

## Q8, how different the skipped CVEs are

How well a logistic regression tells the CVEs the NVD analyzed from the ones it skipped, shadow window.

A logistic regression fitted on the earlier half of the shadow window and scored on the later half
tells the CVEs the NVD analyzed from the ones it skipped with an AUC of 0.886
(0.827 to 0.928), on 30,806
features. The skipped CVEs are not a random sample of the rest: they come from different filers and
describe different software. A model trained on NVD labels alone would learn the NVD's choice of
what to look at, which is the reason the later phases score against filer and CISA labels as well.

| Feature | Group | Coefficient |
|---|---|---:|
| filer or type: filer_microsoft | filer | 5.151 |
| filer or type: filer_Chrome | filer | 4.403 |
| word: n8n | description | 4.110 |
| word: flowise | description | 3.971 |
| filer or type: filer_adobe | filer | 3.913 |
| filer or type: filer_oracle | filer | 3.903 |
| word: openssl_encrypt | description | 3.802 |
| filer or type: filer_ibm | filer | 3.673 |
| filer or type: filer_elastic | filer | 3.550 |
| filer or type: filer_mongodb | filer | 3.538 |
| filer or type: filer_apple | filer | 3.259 |
| word: in link | description | 3.161 |
| word: openclaw | description | 3.148 |
| word: keycloak | description | 3.147 |
| word: before 2026 | description | 2.995 |

| Feature | Group | Coefficient |
|---|---|---:|
| published month (months since 2026-04) | month | -5.282 |
| filer or type: filer_Wordfence | filer | -5.050 |
| filer or type: filer_WPScan | filer | -4.213 |
| filer or type: filer_Patchstack | filer | -4.092 |
| filer or type: filer_AMD | filer | -3.517 |
| word: php | description | -3.514 |
| filer or type: filer_Gitea | filer | -3.389 |
| word: cms | description | -3.179 |
| filer or type: filer_TYPO3 | filer | -3.005 |
| filer or type: filer_CPANSec | filer | -2.669 |
| filer or type: filer_Ubiquiti | filer | -2.598 |
| word: iotdb | description | -2.498 |
| filer or type: filer_XEN | filer | -2.470 |
| word: apache iotdb | description | -2.273 |
| filer or type: filer_OpenHarmony | filer | -2.260 |

The data lead would push back: the later half has had less time to be analyzed, and the month
feature carries that. The AUC says the groups separate; it is not a model to apply.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
