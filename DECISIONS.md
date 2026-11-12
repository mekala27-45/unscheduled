# Decisions

Dated, newest last. Every entry that set a window, a rule, a threshold or a name cites what it rests
on, with the date read.

## 2026-11-07: the setup is done by the build, with no typed secret

Ajay asked on 7 November that Claude do all of the setup, with all permissions granted. Two limits
hold even then: Claude never types a password, key or token into any field, and never creates an
account. So the database connection reaches Vercel only through the Neon integration, GitHub Actions
holds no database credential, the API pulls its data from the public release (ADR 0007, to come at
step nine), and the NVD fetch runs keyless in resumable chunks.

## 2026-11-07: the look comes from a dealt theme, not from an earlier build

Ajay said the earlier sites read alike. The hallmark skill dealt three themes for this product
(Blueprint, Cobalt, Coral); Cobalt was taken because it is made for developer and infrastructure
tools. Its faces were already used in the series, so the voice is kept with unused faces: Rethink
Sans, Anek Latin and Mononoki, each confirmed on npm on 7 November.

## 2026-11-07: the web project is named unscheduled, served at unscheduled-triage.vercel.app

unscheduled.vercel.app already belongs to another Vercel account (it served a calendar app when
checked on 7 November), so Vercel gave the project unscheduled-sigma.vercel.app. The production
domain was changed to unscheduled-triage.vercel.app, a free vercel.app name, and the old name
redirects to it with a 307. The API project is unscheduled-api at unscheduled-api.vercel.app.

## 2026-11-07: Neon project in us-east-1, linked to Vercel by the existing account

The Neon project unscheduled was created in the existing Neon account in AWS US East 1 (N.
Virginia), next to the Vercel default function region, on the free plan (1 GB of storage per
project as the create dialog stated on 7 November). It is linked to unscheduled-api through the
Neon integration for Vercel with Link Existing Neon Account, scoped to that one Vercel project. The
other option, Create New Neon Account, was not taken: the build never creates an account.

## 2026-11-07: the windows are cut by publication date at the two dates that changed the work

config/splits.yaml cuts time, not chance: train to the end of 2023, development 2024, test from 1
January 2025 to 31 March 2026, a gap to 14 April that no model uses, and shadow from 15 April 2026.
The shadow start is the day NIST changed NVD enrichment to KEV listed CVEs, CVEs in software the
federal government uses and critical software first, labeling the rest lowest priority (NIST
announcement, https://www.nist.gov/node/1910421, read 7 November 2026). The CRA date in the same
file, 11 September 2026, is the day the reporting obligations of Article 14 of Regulation (EU)
2024/2847 apply, with the early warning due within 24 hours (EUR-Lex text of the regulation and
the Help Net Security report on the ENISA Single Reporting Platform,
https://helpnetsecurity.com/2026/09/14/enisa-cra-single-reporting-platform, both read 7 November
2026). Any comparison of labels uses train, development and shadow only; the test window is scored
once, in Phase 2.

## 2026-11-07: the thresholds of the nine criteria, and what each rests on

The month plan proposed the thresholds; week one records them with their reasons
(config/criteria.yaml).

- C1, kappa of at least 0.60 on the severity band: the lower edge of substantial agreement in
  Landis and Koch, The measurement of observer agreement for categorical data, Biometrics 33(1),
  1977. Expected calibration error at or below 0.05 and a floor beaten with the lower bound of the
  paired interval above zero are the customer's terms: a band it acts on must say how sure it is,
  and a model that cannot beat TF-IDF is not worth running.
- C2, half of the KEV listings within 180 days in the top 5 percent on the day of publication: the
  top 5 percent is what the customer's two security engineers said they can read on the day a CVE
  appears; EPSS at days 1, 7 and 30 is the public comparator, and a difference inside the interval
  is reported as a tie.
- C3, zero unexplained disagreements and zero KEV listed CVEs missed: a finding is right or wrong,
  so the matcher and osv-scanner must agree or every difference must carry a reason.
- C4, an alert and a draft within 4 hours of a KEV listing: leaves 20 of the 24 hours the CRA gives
  for the early warning (Article 14 of Regulation (EU) 2024/2847, read 7 November 2026) to a person.
- C5 to C7, zero: an unverified citation, a followed planted instruction or an unapproved action is
  each a failure of the product, not a rate to tune.
- C8, a live p95 of at most 1,500 ms for a lookup and 30 s for a triage run, and zero spend: the
  console is used while a person reads, and the series rule is free tiers with no card.
- C9, at least 95 percent of findings with a usable severity: the customer's target for its own
  findings; the NVD only level it is compared with is measured in Phase 1, not assumed.

## 2026-11-07: the budgets

config/budgets.yaml: 8 Kaggle GPU hours for the month, after the goodhart stages (the month plan);
a Neon storage ceiling of 800 MB, which is the 1 GB per project of the Neon free plan (the Neon
billing page, read 7 November 2026: 1 GB storage, autoscaling to 2 CU, 100 compute hours and 10
branches per project) less a 20 percent margin; 2,000 lookups and 50 SBOM matches per client per
day; an SBOM upload of at most 2 MB, small enough that a match stays well inside the Vercel Hobby
function limits recorded on 5 November (2 GB of memory, 1 vCPU, 300 s).

## 2026-11-08: the registration is hashed in two stages

The prompt asks for one hash over six files before any test CVE is scored. Two of the six cannot
exist before the data does: config/labels.yaml is the NVD status vocabulary read from the data, and
config/samples.yaml is drawn from development and shadow with a fixed seed. So the four files that
are pure commitments (the criteria, the splits, the budgets and the Phase 1 plan) were hashed first,
at 03:16 UTC on 8 November, with no lake file and no result on disk
(evaluation/registration_plan.json records the state at the hash and the commit that first added
each file, 91fd592, all unchanged since). The two data files are hashed in a second stage, before
any test CVE is scored, which writes evaluation/registration.json over all six. make gates fails on
an edit to any registered file. This is stricter than the prompt on the plan and equal to it on the
data files.

## 2026-11-08: gitleaks runs in CI, actions are pinned by commit

The sandbox the build runs in refuses to execute a binary it downloads, so gitleaks 8.30.1 is not
run locally: the secrets job in CI downloads it, checks its sha256 against the release checksums
(read 8 November 2026) and scans every commit, and the pre-push hook runs it where it is installed.
zizmor 1.32.0 audits every workflow in CI; to pass it, every action is pinned to the commit of its
current release (read with git ls-remote on 8 November 2026), no checkout keeps its token, the
release job restores no cache, and Dependabot waits two weeks after a release.

## 2026-11-07: Velloran Systems kept after the name check, with its main establishment in Belgium

scripts/check_name.py searched GLEIF for the first candidate and for its distinctive word, and found
no legal entity with a close name (results/name_check.json, read 7 November 2026; a control search
for a known company returned records, so the search works). SEC EDGAR refused the request with a 403
and its rate threshold page, because the client sends a User-Agent naming the project and no email;
the build never puts an email in a User-Agent, so the refusal is recorded and GLEIF decides alone,
as the rule in that file says. The fictional main establishment is Belgium, so under Article 14 of
the CRA its reports go to the CSIRT designated as coordinator there, the Centre for Cybersecurity
Belgium (National CSIRT charter, version 2.0, January 2026, read 7 November 2026; the citation is in
config/customer.yaml).

## 2026-11-07: the stand ins are picked by a written rule, not by taste

config/products.yaml states the rule before the search: per ecosystem, the most starred public
repository created before 2025, not a fork, not archived, with at least 1,000 stars, a licence on
the SPDX list marked OSI approved, a lockfile of its ecosystem at the root, pinned to its newest
commit before 1 January 2025, ties broken by name. Applied through the GitHub search API on 7
November 2026, it chose freeCodeCamp/freeCodeCamp (npm, BSD-3-Clause), TheAlgorithms/Python (PyPI,
MIT, a uv.lock), avelino/awesome-go (Go, MIT), macrozheng/mall (Maven, Apache-2.0, a root pom and no
lockfile) and rustdesk/rustdesk (crates.io, AGPL-3.0), each with its commit, stars and every
repository passed over in that file. Some picks look little like the product they play (the Go pick
is a curated list with a small site generator); that is the rule working as written, and the reason
it was written first. For the Maven stand in, versions that come from a parent BOM stay unresolved,
so two components carry no version and neither engine can match them; the exposure lists both.

## 2026-11-07: the firmware stand in is the Debian slim image for arm64

The door controllers run embedded Linux on ARM, so the firmware layer is played by the Docker
Official Image of Debian in its slim variant, the last dated tag before the cutoff
(bookworm-20241223-slim), pinned by the digest of its linux/arm64 manifest (in config/products.yaml,
read 7 November 2026). Debian because its advisories are in OSV, which the sources fetch, so both
engines can read them. osv-scanner reads the image as distro debian-12.8 and looks packages up by
binary name, where OSV keys Debian advisories by release 12 and source package; those 320 pairs are
the disagreements with a recorded reason in results/exposure/disagreements.json, and with only that
qualifier changed the two engines agree on every pair with the same name.

## 2026-11-12: Q02 accepts either reading of a CVSS 4.0 score with threat metrics

A CVSS 4.0 vector that carries a threat metric (E:P, say) scores two ways: the base metrics alone
(CVSS-B, what the FIRST JSON schema's baseScore names) and the vector as written (CVSS-BT). VulDB
stores the first and most other filers the second. Q02 compared the stored score with the vector as
written only, so it held back 10,240 rows, 9,425 of them stored base scores that were right by the
schema (9,355 from VulDB). Q02 now fires only when the stored score is more than 0.1 from both
readings: 815 rows on the lake of 12 November 2026, where CVSS 3.x scores dominate (a stored
environmental score in place of the base score, or a plain miscomputation). The facts never carried
a stored score, so no fact changed; the counts in results/lake/quarantine.json did.

## 2026-11-12: the filer groups are read from config/filers.yaml as the fetcher writes them

The lake read each filer's type from a `type` key while packages/sources writes the group under
`group`, so config.filer_types was empty and every CVE was typed unregistered. The loader reads
`group` now, with a test on the committed file; 1,834 CVEs remain unregistered (filers the CNA list
does not hold). Every question that breaks down by filer type (Q3, Q4, Q6, Q8) was run again after
the fix; nothing earlier was published.

## 2026-11-12: three repairs in the backlog analysis before its first results

`nvd_analyzed` in gold.cve_current was null for a CVE the NVD did not hold yet (one, published at
the cut), and the Q8 AUC cast that null to an integer, which numpy does without complaint; the flag
is false for such a CVE now, a not null test holds it, and the AUC refuses a missing label. DuckDB
sums integers into a decimal, which JSON could not hold; values are converted where results are
written. And a cluster bootstrap by filer over a group of one filer (MITRE) gave an interval of
zero width: a value from fewer than five filers is written without an interval and says why.

## 2026-11-12: the serving bundle speaks the API's field names, and is cut to fit the free plan

The first full bundle did not load: its columns and provenance keys were the lake's names, not the
API's contract (unscheduled_api.bundle.CVE_COLUMNS), and its events named no field they set.
scripts/build_serving_bundle.py now writes the contract exactly, events carry `sets` with the API's
field names (a vector sets its score and band too), and the build reads every file back through the
API's own readers before it is published. scripts/load_local.py then loads the bundle into a local
Postgres through the API's sync and measures it: the first contract bundle took 1,703 MB, against a
ceiling of 800 MB (budgets.yaml). The cut, in order of what it saved:

- the ruler keeps only the events the console draws or the as-of view reads: NVD statuses, the
  filer's, the NVD's and CISA's vectors, one SSVC event per change, the KEV listing, the first
  exploit code per source, EPSS at the registered offsets for KEV CVEs, rejection, and removals;
  the reserved date, CWE changes, CVSS 2.0 and 3.0 vectors, the CPE flag and affected versions are
  left in the lake (3,088,346 events to 1,284,295);
- the API dates the publication, state, filer, its type and the description from the published
  column, the last change from itself, EPSS from its own date, and every field an event sets by
  that event, so provenance is kept for the CWEs and the CPE flag only;
- an event key is 16 hex characters, an NVD status event does not repeat its time, and an event
  dated by the NVD's own change history does not say so (the API reads the absence as that rule).

The same population as section 12 asks for (every CVE published since 1 January 2021 and every
KEV listed CVE, 259,287) now loads in 35 sync calls; the size it takes is in results/live/local_load.json.
A Postgres storage parameter (toast_tuple_target) was tried first and changed nothing, because it
only applies to rows over 2 kB; it was not kept.

## 2026-11-12: the console reads the generated contract and adapts it

web/lib/api/schema.ts was written by hand before the API existed and had drifted from it on every
endpoint. web/lib/api/openapi.ts is now generated from openapi.json (openapi-typescript 7.13.0),
web/lib/api/view.ts holds the shapes the pages read, and web/lib/api/adapt.ts maps one to the other,
with unit tests and Playwright mocks in the API's own shape. The console home lists what is newest
in the loaded release, counted back from the day it was built, since the API filters by day
(kev_added_from and analyzed_from were added for it), and /v1/meta carries the quarantine counts
and the newest run ledger rows of the loaded bundle for the data page.
