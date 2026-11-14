# 0008. Predictions come from a batch, and two small models score on request

Status: accepted, 14 November 2026

## Context

The Phase 2 predictions have to reach an API that runs as a Vercel container on the Hobby plan
(ADR 0005), beside a Neon database on the free plan, and that loads only what a published serving
bundle carries (ADR 0007). Three things decide how they get there: the size of what the image has to
carry, how long a fresh container takes before it answers, and how much room the database has. The
plan lets the deep text model score on a request only if this record measures its size and its cold
start inside what the platform allows; otherwise it is served from the batch.

## Decision

The batch comes from scripts/predict_serving.py, which scores every CVE of the development, test and
shadow windows with the chosen version of each registered model: the band, the eight base metrics and the
CWE with their probabilities and conformal sets, the exploitation score with its isotonic
probability and percentile, the chance of a KEV listing within 30 days, 90 days and 180 days, and the
likely products. A train window CVE gets none, since every model was fit on it, and the gap window
gets none, since no model uses it. The predictions travel in the serving bundle as an optional
table, and the sync loads them like every other table, measuring each chunk against the storage
ceiling before it writes; an API answer without a prediction says which of these reasons applies.

On a request, POST /v1/predict scores a submitted description, with the filer values a filer
would give, through the band floor and LightGBM, exported to ONNX and run by onnxruntime. Their inputs
are built without scikit-learn, from specs scripts/export_onnx.py checks against scikit-learn before
writing them, and LightGBM reads the band projection of the same floor it was trained on (DECISIONS.md,
the exploitation run reads the committed band floor).
On the same inputs the ONNX graphs differ from the native models by at most
2.7e-07 for the floor and
3.1e-07 for LightGBM, against a tolerance of
1e-4, so the parity check's result is pass.
On the same sample of development CVEs, the band projection the API computes differs from the one
the exploitation run used by at most 2.7e-07, and LightGBM's score by at most
2.9e-08.

The text model stays in the batch: it needs the embedding model and its tokenizer at request time,
and the batch already holds a prediction for every CVE the API serves; a request scores text that is
not a CVE yet, where the floor's answer is labeled as the floor's.

## What was measured
The serving measurements are taken once the batch is written.

Vercel's container registry allows a compressed layer of 2 GB and an image of 15 GB (its documentation,
read 14 November 2026), so size alone would not keep the text model off the request path. Its cost
is every cold start loading the embedding model before the first answer, for text the batch cannot
cover anyway, and a model that has to earn its place by its gain over the floor (ADR 0010).

## Consequences

- An API answer for a known CVE always comes from the batch, made on the day the batch names, and
  says so; a scored request comes from the floor and LightGBM and says that too.
- The batch is rebuilt when a model, an operating point or the windows change, and its batch id,
  the first characters of a digest over the operating points and the chosen versions, says which.
- The prediction table is typed and compact so it fits under the storage ceiling, and the sync
  refuses a chunk that would pass it.
