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
