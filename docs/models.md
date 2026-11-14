# Method notes: the models

Phase 2 fills in what the NVD no longer writes for most new CVEs, and ranks them by the chance of
exploitation, with every value labeled as a prediction. These notes say how each model was built,
what it reads, how it was chosen and how it is judged. Every number here is read from the manifest,
and every choice made on the way is a dated entry in DECISIONS.md. The plan behind all of it,
evaluation/phase2_plan.yaml, was hashed into the registration as the models stage before any model
saw a test CVE.

## The training sets, as known at day 0

A model may read only what was public at the end of the day a CVE was published (day 0). The sets
are built from the as-of facts of the lake: the description the NVD change history held at day 0,
the filer's values from the CVE record as published, the CISA values only when known by then, the
affected entries, the exploit code signal and the days from reservation to publication. The labels
are what the NVD and KEV say at the lake cut. Never a feature: EPSS at any offset; any NVD value; KEV; anything known after day 0.

The four windows hold 220,803 train, 39,924
development, 63,304 test and 78,676 shadow CVEs.
A leakage test rebuilds every value from the facts known at day 0 and fails if any differs, and an
empty feature column fails the build. Each file is published by its content digest
(results/models/sets.json), and every training run checks the files it reads against those digests
before it fits. The test labels sit in a file of their own that only scripts/score_test.py opens,
and a gate in CI fails on any other reference to it.

| Window | CVEs | NVD band | KEV within 180 days | Filer band at day 0 | Description |
|---|---:|---:|---:|---:|---:|
| train | 220,803 | 101,427 | 278 | 1.3% | 100.0% |
| development | 39,924 | 23,272 | 127 | 60.6% | 100.0% |
| test | 63,304 | 22,453 | 211 | 58.0% | 100.0% |
| shadow | 78,676 | 7,782 | 155 | 61.7% | 100.0% |

## The floors

Every model has a floor trained on the same rows: TF-IDF over the joined text beside the filer and
CISA values one hot, and a logistic regression, one per class against the rest
(DECISIONS.md, the floor solver). The band floor's grid, from the plan:
C from 0.1, 0.3, 1, 3, 10, and word grams against word plus character 3 to 5 grams, by quadratic weighted kappa on development.

The representation chosen is word and character grams. The band floor reaches a
development kappa of 0.669 at C 0.3. On the
13,970 development CVEs with a filer band, the filer's own band
agrees with the NVD at 0.476, and the floor at
0.719; on the 9,302
without one, the floor reaches 0.574. The mean
kappa over the eight base metrics is 0.774, and the CWE floor
has a development macro F1 of 0.527.

| Task | Chosen by | C | Development score | Train rows | Development rows |
|---|---|---|---:|---:|---:|
| Severity band | quadratic weighted kappa | 0.3 | 0.669 | 101,427 | 23,272 |
| Attack vector | Cohen kappa | 1 | 0.849 | 101,427 | 23,272 |
| Attack complexity | Cohen kappa | 3 | 0.529 | 101,427 | 23,272 |
| Privileges required | Cohen kappa | 3 | 0.607 | 101,427 | 23,272 |
| User interaction | Cohen kappa | 3 | 0.913 | 101,427 | 23,272 |
| Scope | Cohen kappa | 3 | 0.913 | 101,427 | 23,272 |
| Confidentiality | Cohen kappa | 1 | 0.775 | 101,427 | 23,272 |
| Integrity | Cohen kappa | 1 | 0.793 | 101,427 | 23,272 |
| Availability | Cohen kappa | 3 | 0.817 | 101,427 | 23,272 |
| Weakness (CWE) | macro F1 | 1 | 0.527 | 206,430 | 19,350 |

## The text model

The plan runs ModernBERT on a Kaggle GPU and names a CPU fallback for when the Kaggle secrets are
absent (frozen embeddings from config/models.yaml embedding, a logistic head per task). The secrets were absent, so the fallback ran: the
joined text of every set row embedded once with the pinned bge-small weights, through onnxruntime,
and a logistic regression per task. A change request recorded before any fill model had a result
gives each head the floor's own filer and CISA block beside the embedding, so the comparison with
the floor measures the text representation alone; the embedding by itself is kept as an ablation.


## The exploitation models

The label is a KEV listing within 180 days of publication, and the population starts on
the day KEV could first list a CVE within that window (DECISIONS.md, the change request on the
exploitation population). The floor is a logistic regression with balanced class weights; LightGBM
reads the same day 0 features and the band floor's four probabilities, taken out of fold for the
CVEs the band floor was fit on. Its search, Optuna TPE, 50 trials, runs on the half
year folds of that change request.

On development, LightGBM's average precision is 0.027
against the floor's 0.049, and it holds
47.2% of the development listings in its top
five percent, against 40.9% for the floor.
So LightGBM is behind the floor at the very top of its ranking, where average precision weighs most,
and ahead across the top five percent, the depth C2 judges. Both are reported, and C2 is judged on
LightGBM, the exploitation model the operating points name.

## Time to KEV

A Cox model and a random survival forest model the days from publication to a KEV listing, censored
at the lake cut, on the day 0 features without the text. The Cox model's development concordance is
0.778 and the forest's 0.774.
R's coxph, fit on the same design matrix without a penalty, differs from lifelines by at most
7.2e-08 in a coefficient and by
0.0000 in concordance. The plan's tolerance is
coefficients within 0.001 absolute and concordance within 0.002 of lifelines unpenalized, and the recorded result is
pass.

## The affected product

The floor normalizes the filer's vendor and product strings and matches them to the CPE dictionary,
exactly and then by a token set ratio; the retrieval ranks every CPE vendor and product by cosine to
the CVE's joined text. A CVE is offered only the names the NVD had created by its day 0.


## Calibration and conformal sets

Each fill head is scaled by one temperature fit on development by negative log likelihood, and the
exploitation score is mapped by an isotonic regression fit on development. The calibration error is
taken over equal width bins of the top label probability, with a bootstrap interval. Split conformal
sets with adaptive sets are fit on development at a target coverage of 0.9,
and their coverage is measured on test, overall and by filer type, because test is later
than development and the coverage a set promises holds only for rows like the ones it was fit on.


## The CVEs the NVD skipped

The NVD's analyzed CVEs after April 2026 are a selected sample, so a score on them says little
about the CVEs it skipped. The shadow CVEs it did analyze are weighted by the odds that a CVE like
them was skipped, from the Phase 1 domain classifier fit out of half, clipped at
20, and the band kappa is shown plain and weighted, with Kish's effective
sample size, never one without the other.


## How test was judged

Test is scored once, by scripts/score_test.py, after the operating points are frozen and hashed into
the registration. C1 asks: For test CVEs the NVD analyzed, the predicted severity band agrees with the NVD band at a quadratic weighted kappa of at least 0.60, beats the TF-IDF floor with the lower bound of the paired 95 percent interval above zero, and has an expected calibration error at or below 0.05.

Not scored yet.

C2 asks: Scored on the day of publication, the top 5 percent by the exploitation score holds at least half of the test CVEs listed in KEV within 180 days. EPSS at days 1, 7 and 30 is reported beside it, and a difference inside the interval is a tie.

Not scored yet.

## The registry

Every training run is logged to MLflow with its parameters, its development metrics, the digests of
the sets it read, the commit, the Actions run and its model file's SHA-256. The store is MLflow's
SQLite backend, written by scripts/build_registry.py from the committed run records rather than from
inside the jobs, so the repository alone rebuilds it, and its --check flag fails when the committed
export no longer matches the records (DECISIONS.md, the registry).
A version is a candidate until development chooses it, and scored once test has been read. The API
and the console read the export, results/registry/registry.json, never a tracking server, and the
store is packed into an archive named by its digest and attached to the release.

## The GPU request

The plan runs ModernBERT on a Kaggle T4 under a monthly ceiling in config/budgets.yaml, and every run
declares its hours and the hours left in a committed file under requests/gpu/ before it starts. No
run was made in this phase: the Kaggle secrets are absent, so the request stands as written and the
named fallback ran on CPU instead (DECISIONS.md, step eight takes the fallback).
Hours used: 0.0 of 8.0 this month.


## What a data lead would push back on

The NVD's labels are a selected sample, so the shadow view is shown weighted beside plain. The
filer's score is a feature, which favors the filers who score, so the floor's kappa is shown with and
without a filer band and the slices by filer show the model's. KEV is a lower bound on exploitation,
and nothing here fixes that; the exploitation card says so. EPSS at day 7 and day 30 has seen more
days than the model, so C2 names those days and calls a difference whose interval holds zero a tie.
One seed is one draw: the intervals carry the sampling error of test, not the variation between
seeds, and each card's limits say so.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
