# 0004. The matcher in code, checked by a second engine

Status: accepted, 7 November 2026

## Context

A finding names a package in a customer SBOM and an advisory that affects it. A wrong finding wastes
an engineer's day and a missed one is the whole risk. Version ranges are written in the scheme of
each ecosystem (semver, PEP 440, Maven, Debian and others), and comparing them as strings is the
classic mistake (notebooks/03 shows it).

## Decision

packages/match evaluates every OSV and GitHub advisory range in its ecosystem's own scheme through
univers, from package URLs, and records the range, the fixed versions and when that advisory version
was known. osv-scanner, pinned and checked by digest, runs offline on the same SBOMs and the same
files. Every pair one engine reports and the other does not is a disagreement that must carry a
named reason; an unexplained disagreement fails the run (criterion C3). Grype runs beside them as
the CPE based contrast, to show what a CPE matcher cannot see.

## Consequences

- Each finding can be explained range by range and dated, which a black box scanner cannot do.
- Two engines cost one more pinned tool and a disagreement report to read.

## Alternatives

Running osv-scanner alone would be quicker and would leave no way to date a finding as of a past
day or to explain it. Matching by CPE through the NVD would miss every CVE the NVD has not analyzed,
which is the gap this project exists for.
