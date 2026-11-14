# 0010. The fill model earns its place by its measured gain over the floor

Status: accepted, 14 November 2026

## Context

The plan names ModernBERT, fine tuned on a GPU, as the deep fill model, and a CPU fallback for when
the Kaggle secrets are absent: frozen sentence embeddings of the joined text with a logistic head per
task. Either one costs more than the floor, a TF-IDF logistic regression on the same rows: a GPU or
hours of CPU to fit, a larger artifact, and an answer that cannot be computed inside the API on a
request. A deep model that does not beat the floor is cost without a result, and a reader cannot tell
from the model's name whether it did.

## Decision

Between ModernBERT and the fallback, the primary fill model, the one the API and the console serve,
is the one with the larger measured gain over the floor on development, and C1 judges it once on test
against the same floor, with the paired difference and its interval. ModernBERT replaces the
fallback only if its development gain is larger. The fallback was compared on equal terms: a change
request recorded before any fill result gave its heads the floor's own filer and CISA block, so the
gain measures the text representation alone, and the embedding without the block is reported beside
it.

## What happened in Phase 2

ModernBERT did not run (ADR 0009), so the fallback is the primary fill model, and the measure that
matters is its gain over the floor.
The fallback's development result is measured in its own run, and this record renders it once the
run's record is committed.

## Consequences

- The text model is served from the nightly batch only: its embedding weights do not fit the API's
  request path (ADR 0008), while the floor scores a submitted description on a request.
- A later ModernBERT run has a fixed bar: the fallback's development gain, on the same rows and the
  same floor.
- The comparison costs a second fit of every head, the embedding alone, which is kept because it is
  what says how much of the gain the text carries.
