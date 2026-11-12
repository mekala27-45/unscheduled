# 0005. Vercel containers now, Kubernetes in Phase 4

Status: accepted, 7 November 2026

## Context

The API must be live from the first week, on a free plan with no card. Fly asks for a card, and
Hugging Face Docker Spaces need a paid plan (both recorded on 23 October 2026). Vercel Hobby runs a
container function from a Dockerfile on port 80 with no card, and the series has run four APIs there
since October.

## Decision

The API ships as a Vercel container built from Dockerfile.vercel, which installs only the API and
what it imports, runs the migrations in process at start, and serves FastAPI with uvicorn. The web
app is a second Vercel project from web/. Phase 4 adds a Helm chart deployed to kind in Actions and
Terraform for a reference cloud stack, tested without an account.

## Consequences

- A push to main deploys both projects; a commit marked skip deploy builds nothing.
- Cold starts are visible in the probe (results/probe_platform.json) and in the load test.
- Hobby is for non commercial use, which a portfolio demonstration is.

## Alternatives

Render free sleeps after fifteen minutes and has half the memory. A Kubernetes cluster now would
cost money or an account; Phase 4 proves the chart on kind instead.
