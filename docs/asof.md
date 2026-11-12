# The as-of model

Every value anyone published about a CVE is kept as a fact, with the moment it became known. The
state of a CVE on any day is read from the facts known by the end of that day, and from nothing
else, so no answer and no training set can see a value from its future.

## A fact

One row of silver.cve_fact: the CVE, the field, the source that published the value, the value,
known_from (when it became known), known_to (when it stopped being current, empty while it still
is), dated_by (the rule that set known_from) and pre_history (whether the value predates the NVD
change history). A field that holds a set, such as the CWEs or the exploit code paths, keeps each
member as its own fact with its own interval.

The fields, the source names and the rules are defined once, in
packages/lake/src/unscheduled_lake/fields.py; the SQL that builds the facts is in dbt/models.

## How a fact is dated

Each fact says which of these rules set its known_from:

| Rule | known_from is |
|---|---|
| nvd_history | the NVD change history event that carried the value |
| nvd_last_modified | the last modification of the NVD record that carried the value |
| record_updated | the last update of the CVE List record that carried the value |
| first_fetch | the first fetch by this build that saw the value |
| before_history | for an NVD value set before the change history began: the publication, and the row is flagged |
| kev_commit | the first kev-data commit that carried the listing, on or just after dateAdded |
| kev_date_added | the start of the KEV dateAdded day, in UTC |
| kev_catalog_version | the KEV catalog version that first stated the value |
| git_first_commit | the first commit of the file, module or template |
| git_commit | the commit of the version of the file that carried the value |
| epss_score_date | the EPSS score date |

The NVD change history begins on 1 January 2017. A value the NVD set before then has no event to
date it; it is dated from publication by the before_history rule and flagged, and the data card
says how many CVEs depend on that rule.

## The engine

The state at a time t is every fact with known_from at or before t that had not ended by t:

```
known_from <= t and (known_to is null or known_to > t)
```

A day means the end of that day in UTC. The rule is written twice, as SQL for Python in
packages/lake/src/unscheduled_lake/engine.py and as the dbt macro in dbt/macros/asof.sql, and the
parity test below holds them to the same answer.

## How it is tested

- Parity: tests/lake/test_asof_parity.py runs the Python engine and the dbt macro on the same facts
  and requires identical frames.
- The planted future fact: tests/lake/test_asof_property.py draws CVEs and times, plants a fact that
  became known after the time asked, and fails if the engine ever returns it, or if a fact known
  before that time is missing.
- The same checks run on the real facts each time the lake is built, and their counts are in the
  manifest (results/lake/asof_tests.json).

## Where it is used

The API answers GET /v1/cves/{id}?as_of=YYYY-MM-DD from the same rule over the events the serving
slice keeps, and says when a CVE was not yet published on the day asked. The backlog questions read
the NVD status as it stood at each moment they measure (Q5 asks what the NVD had done at the moment
of a KEV listing), and from Phase 2 every training row is built as of the moment it would have been
scored.
