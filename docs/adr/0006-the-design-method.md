# 0006. The design method: a dealt theme, tokens only, a validated palette

Status: accepted, 7 November 2026

## Context

The earlier builds in the series converged on one look. This one is meant to read as a new product,
built the way a design team would build it, and every color must stay legible in both themes and
for color vision deficiency.

## Decision

The theme was dealt by hallmark on 7 November (Cobalt, 2 of 3, seed 73696e8c; landing draw 98c863:
Map and Diagram, a settled hero, a banner over a retracting bar, a mast footer) and recorded in
.hallmark/log.json so the next build rotates away from it. Every color and face is a custom property
in web/styles/tokens.css; scripts/check_tokens.py fails on a literal anywhere else. The chart palette
is fixed in order and checked in CI by the series validator in both modes. The type is Rethink Sans,
Anek Latin and Mononoki from Fontsource, none of them used in days 1 to 23. sloplint, axe and
Lighthouse run on every change to the site (web.yml).

## Consequences

- A new color is a token change reviewed in one file, not a search through components.
- The look is checked by machines on every pull request and by a person at the look review.

## Alternatives

A component kit used as shipped would look like every other dashboard. A palette chosen by eye
would fail the deficiency checks it was never run against.
