# 0010. The fill model earns its place by its measured gain over the floor

Status: accepted, 14 November 2026

## Context

The plan names ModernBERT, fine tuned on a GPU, as the deep fill model, and a CPU fallback for when
the Kaggle secrets are absent: frozen sentence embeddings of the joined text with a logistic head per
task. Either one costs more than the floor, a TF-IDF logistic regression on the same rows: a GPU or
hours of CPU to fit, a larger artifact, and an answer that cannot be computed inside the API on a
request. A deep model that does not beat the floor adds those costs and no accuracy, and its name
does not tell a reader whether it beat the floor.

## Decision

Between ModernBERT and the fallback, the primary fill model, the one the API and the console serve,
is the one with the larger measured gain over the floor on development, and C1 judges it once on test
against the same floor, with the paired difference and its interval. ModernBERT replaces the
fallback only if its development gain is larger. The fallback was compared on equal terms: a change
request recorded before any fill result gave its heads the floor's own filer and CISA block, so the
gain measures the text representation alone, and the embedding without the block is reported beside
it.

## What happened in Phase 2

ModernBERT did not run (ADR 0009), so the fallback is the primary fill model, judged by its gain over
the floor.
On development the fallback's band reaches a quadratic weighted kappa of 0.594
against the floor's 0.669, and 0.462 from the
embedding alone.
The fallback does not beat the floor on development, and C1 says on test whether that gap holds.
On test the paired difference, model less floor, is -0.057
(-0.108 to -0.019), and C1 is
not met.

## Consequences

- The text model is served from the batch only (ADR 0008). A description submitted on a request is
  scored by the floor and LightGBM, which need no embedding model.
- A later ModernBERT run has a fixed bar: the fallback's development gain, on the same rows and the
  same floor.
- The comparison costs a second fit of every head, the embedding alone, which is kept because it is
  what says how much of the gain the text carries.
