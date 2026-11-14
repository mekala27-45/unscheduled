# 0009. The GPU is a committed request, declared before it is used

Status: accepted, 14 November 2026

## Context

The plan's deep fill model is ModernBERT, fine tuned on a GPU. The build spends no money, so the only
GPU it can use is a free notebook GPU on Kaggle, reached with a Kaggle username and key kept in the
repository secrets. A free GPU is a quota, not a machine: a run that overruns it, or several runs
nobody counted, would stop the build halfway through a phase with nothing to show for the hours.
A GPU run also happens outside GitHub Actions, so nothing in the repository would otherwise record
that it happened, what it cost, or what it produced.

## Decision

Every GPU run is a request committed before it starts: a file under requests/gpu/ that names the
run, the month, the hours it declares, the hours left in that month under the ceiling in
config/budgets.yaml, where it runs and its status. The file is updated with the hours used when the
run ends, and never deleted. scripts/gpu_hours.py sums the month's hours from those files, refuses a
month whose declared or used hours pass the ceiling, and writes the hours used and left into the
manifest, where the method notes read them.

A run's outputs come back as files with their digests, like every other model step, so the scores
the build reports never depend on a notebook nobody can open again.

## What happened in Phase 2

The probe of 14 November found the Kaggle secrets unset. The request for the ModernBERT run was
committed as written (requests/gpu/2026-11-14-modernbert.yaml), with three hours declared, and it
stands unused: step eight ran the CPU fallback the plan names instead (ADR 0010). The ledger reads no
GPU hour used this month.

## Consequences

- The GPU path is a rule and a ledger in this phase, not a measured run. ModernBERT's code is not
  part of the release, because code that has never run on the hardware it was written for would be
  a claim nobody tested.
- Adding KAGGLE_USERNAME and KAGGLE_KEY to the repository secrets is what opens the path; the run
  then starts by updating its request, and its result is compared with the fallback by the same
  rule (ADR 0010).
- A month can never overspend silently: the ledger fails the build first.
