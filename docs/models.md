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
are what the NVD and KEV say at the lake cut. These are never features: EPSS at any offset; any NVD value; KEV; anything known after day 0.

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

On development, the band reaches 0.594 with the block and
0.462 from the embedding alone, against the floor's
0.669.
The text model is behind its floor on every one of the ten tasks: on these rows the frozen embedding,
even beside the floor's own structured block, carries less than the TF-IDF grams of the same text.

| Task | Design | Chosen by | C | Development score |
|---|---|---|---|---:|
| Severity band | joint | quadratic weighted kappa | 0.3 | 0.594 |
| Attack vector | joint | Cohen kappa | 1 | 0.788 |
| Attack complexity | joint | Cohen kappa | 0.3 | 0.425 |
| Privileges required | joint | Cohen kappa | 3 | 0.561 |
| User interaction | joint | Cohen kappa | 1 | 0.853 |
| Scope | joint | Cohen kappa | 0.3 | 0.871 |
| Confidentiality | joint | Cohen kappa | 0.3 | 0.687 |
| Integrity | joint | Cohen kappa | 3 | 0.702 |
| Availability | joint | Cohen kappa | 1 | 0.760 |
| Weakness (CWE) | joint | macro F1 | 0.3 | 0.437 |
| Severity band | text | quadratic weighted kappa | 0.3 | 0.462 |
| Attack vector | text | Cohen kappa | 0.1 | 0.688 |
| Attack complexity | text | Cohen kappa | 0.3 | 0.327 |
| Privileges required | text | Cohen kappa | 1 | 0.375 |
| User interaction | text | Cohen kappa | 1 | 0.748 |
| Scope | text | Cohen kappa | 0.3 | 0.819 |
| Confidentiality | text | Cohen kappa | 3 | 0.598 |
| Integrity | text | Cohen kappa | 0.3 | 0.611 |
| Availability | text | Cohen kappa | 0.1 | 0.668 |
| Weakness (CWE) | text | macro F1 | 0.1 | 0.428 |

## The exploitation models

The label is a KEV listing within 180 days of publication, and the population starts on
the day KEV could first list a CVE within that window (DECISIONS.md, the change request on the
exploitation population). The floor is a logistic regression with balanced class weights; LightGBM
reads the same day 0 features and the band floor's four probabilities, taken out of fold for the
CVEs the band floor was fit on and from the committed floor, the one the API serves, for the rest. Its search, Optuna TPE, 50 trials, runs on the half
year folds of that change request.

On development, LightGBM's average precision is 0.019
against the floor's 0.049, and it holds
27.6% of the development listings in its top
five percent, against 40.9% for the floor.
LightGBM is behind its floor on both measures in this run.
The first exploitation run, replaced because it projected with its own refit of the band floor
(DECISIONS.md, the exploitation run reads the committed band floor), chose other trees from the same
search: its LightGBM held 47.2% of the development listings in
its top five percent, with an average precision of 0.027, while
the floor held 40.9% in both runs. A search that moves this far on
so small a change in its inputs is choosing on noise: three folds with few listings each cannot rank
fifty trials (DECISIONS.md, the exploitation rerun). The rerun stands, as committed before it ran.

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
taken over equal width bins of the top label probability, with a bootstrap interval. Conformal sets,
split conformal with adaptive prediction sets, are fit on development at a target coverage of 0.9,
and their coverage is measured on test, overall and by filer type, because test is later
than development and the coverage a set promises holds only for rows like the ones it was fit on.

The band's temperature is 1.16; its development calibration
error is 0.048 before scaling and
0.019 after.

## The CVEs the NVD skipped

The NVD's analyzed CVEs after April 2026 are a selected sample, so a score on them says little
about the CVEs it skipped. The shadow CVEs it did analyze are weighted by the odds that a CVE like
them was skipped, from the Phase 1 domain classifier fit out of half, clipped at
20, and the band kappa is shown plain and weighted, with Kish's effective
sample size, never one without the other.

For the primary model the plain kappa is 0.379 and the
weighted one 0.399, on an effective sample of
933; for the floor they are 0.453 and
0.442.
Both sit well below their development kappas, 0.594 and 0.669: the
CVEs the NVD analyzes after its change are not like the ones it analyzed in 2024, weighted or not.

## How test was judged

Test is scored once, by scripts/score_test.py, after the operating points are frozen and hashed into
the registration. C1 asks: For test CVEs the NVD analyzed, the predicted severity band agrees with the NVD band at a quadratic weighted kappa of at least 0.60, beats the TF-IDF floor with the lower bound of the paired 95 percent interval above zero, and has an expected calibration error at or below 0.05.

Test has not been scored yet.

C2 asks: Scored on the day of publication, the top 5 percent by the exploitation score holds at least half of the test CVEs listed in KEV within 180 days. EPSS at days 1, 7 and 30 is reported beside it, and a difference inside the interval is a tie.

Test has not been scored yet.

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
The ledger counts 0.0 of this month's 8.0 GPU hours as used.

## The misses, read

100 band misses were drawn with the default seed from development, never
test, read one by one and coded into categories named while reading.

| Category | Misses | What it means |
|---|---:|---|
| A kernel or hypervisor fix that states no impact | 27 | a Linux or Xen commit message names the bug and its fix but not what an attacker gains; the NVD's band, mostly 5.5 or 7.8, rests on a reading the text does not give |
| The NVD rescored the filer's vector | 21 | the filer gave a CVSS 3 vector and its band, the NVD changed one or more metrics into another band, and the model stayed with the filer |
| A word's usual band, wrong for this CVE | 14 | the model followed a word in the text, a weakness class or VulDB's own rating of critical or problematic, to the band it usually means, while the NVD scored the details, such as an admin only page or an adjacent network |
| The model left a band that agreed with the NVD | 14 | the filer's band or the CISA ADP band matched the NVD's, and the model moved off it, often toward the band its weakness class usually takes |
| A short text with no score, scored severe by the NVD | 8 | a sentence or two and no filer vector; the NVD assumed the worst case the text allows, and the model spread its probability |
| The filer scored in CVSS 4.0 alone | 8 | a CVSS 4.0 vector gives no CVSS 3 band or base metrics, so the model had only the vector string to go on |
| The text states the impact and the model misread it | 8 | the description says what an attacker gets, often in a vendor's stock phrase, and the model's band does not follow it |

## What a data lead would push back on

The NVD's labels are a selected sample, so the shadow view is shown weighted beside plain. The
filer's score is a feature, which favors the filers who score, so the floor's kappa is shown with and
without a filer band and the slices by filer show the model's. KEV is a lower bound on exploitation,
and nothing here fixes that; the exploitation card says so. EPSS at day 7 and day 30 has seen more
days than the model, so C2 names those days and calls a difference whose interval holds zero a tie.
One seed is one draw: the intervals carry the sampling error of test, not the variation between
training runs, and each card's limits say so.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
