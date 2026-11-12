# 0003. Facts dated by events, not by snapshots

Status: accepted, 7 November 2026

## Context

The question the whole month asks is what was known about a CVE at a given time: when the filer
scored it, when the NVD analyzed it or did not, when CISA listed it, when exploit code appeared. A
snapshot says what is true when it was taken and nothing about when a value appeared.

## Decision

The unit of the lake is a fact: a CVE, a field, a source, a value, and the interval in which it was
known, known_from to known_to. known_from comes from the strongest dated evidence available: the NVD
change history for what the NVD and the filers changed since 2017, the CVE List deltas from the
first fetch on, KEV and Vulnrichment and the exploit repositories for their own entries, EPSS for
its scores. A value with no dated event is dated by a named rule, and the row says which rule
(dated_by), so an answer can count how much of it rests on rules.

The as-of engine is one SQL predicate, known_from at or before t and known_to after t or empty,
written once as a dbt macro and once in Python. tests/lake requires the two to return the same
frames, and a property test plants a fact known after t and fails if it ever appears.

## Consequences

- Any question can be asked as of any time without leaking what was learned later.
- History before 2017 is dated by rule. The pages say so beside every number that leans on it.

## Alternatives

Type 2 slowly changing dimensions over daily snapshots would date a change only to the day the
snapshot noticed it, and would have nothing before the first snapshot.
