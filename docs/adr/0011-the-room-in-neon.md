# 0011. The room in Neon is measured before it is spent

Status: accepted, 16 November 2026

## Context

Phase 3 adds an advisory corpus with its vectors, a store of triage runs and the checkpoints of the
graph, and the API serves all of it from the same Neon database as everything else. The plan limit
is 1 GB a project on the Neon free plan (its FAQ, updated 3 November 2026), and this build keeps a ceiling of
800 MB (config/budgets.yaml). The sync refuses a chunk that would pass the ceiling and writes nothing, so a
full database keeps the site up on old data while nothing new arrives.

When the API read the database at 2026-11-16T02:59:27Z it held 752.7 MB, 94.1% of the
ceiling: the event table 371.6 MB, the CVE table 304.2 MB and the predictions
65.6 MB, almost all of it.

## What was measured

Only the API reaches Neon, so nothing was tried there. scripts/measure_room.py measures on a Postgres
with pgvector that is not Neon (results/agent/room.json): Postgres 16.15 with pgvector 0.8.7, the
pgvector Neon offers. Neon runs Postgres 18.7; the prediction table, which no sync has updated, takes the
same room in both.

- **The serving tables, fresh.** The newest serving bundle loaded into an empty schema by the sync's
  own loader, with the event key this decision gives it: the CVE table takes 288.3 MB against
  304.2 MB in Neon, so its updates leave little behind; the predictions take the same 65.6 MB. The
  event table, 1,292,258 rows, takes 319.4 MB, of which 73.8 MB are its two indexes.
- **A day of the lake.** Two daily bundles compared row by row with the sync's own digests,
  1.40 days apart: 134 new CVEs, 3,345 changed CVE rows and 1,018 new events, so the
  new rows add 0.29 MB a day and the changes leave dead rows behind for autovacuum.
- **The corpus.** 1,006 chunks cut from the GitHub advisories that name a CVE the six stand in
  products carry, from the KEV catalog and from the CWE catalog, stored the way step 4 will store
  them, with a full text index, a halfvec(384) column and an HNSW index: 3,949 bytes a chunk with its
  indexes. The vectors are random unit vectors from a fixed seed, since the size of a halfvec column
  and of an HNSW graph depends on how many vectors there are, not on their values.
- **The checkpoints.** A fixture graph with the node names of the triage graph and the planned state,
  run to its approval interrupt with the Postgres checkpointer: 67.2 KB a run while it waits for a
  person, 10.7 KB once only its latest checkpoint is kept.

## Decision

- **Events are keyed by a bigint** (migration 0004). The 16 hex characters of an event id are 64
  bits; the table keeps them as one number, shifted so that the order of the numbers is the order of
  the hex strings, and every answer still carries the hex string. That frees 52.2 MB. Rewriting the
  table in place would need a second copy of it, and the plan has no room for one, so the migration
  empties the table and the sync loads it again from the serving release. A load inserts the keys
  in random order and leaves the primary key at 38.3 MB, so the end of a load rebuilds an index it
  left much larger than a fresh build: 29.0 MB.
- **The CVE table is vacuumed sooner.** Autovacuum reclaims its dead rows once they pass two percent
  of the table rather than a fifth, which bounds the room they hold to 5.8 MB.
- **Neon holds a scoped corpus.** The 602 advisories that name a CVE the six stand in products
  carry, the 1,781 KEV entries and the 984 CWE weaknesses: 4,828 chunks in 20.8 MB. The
  short sections of one document share a chunk, so a KEV entry is one chunk and not four; the links
  of an advisory and the notes of a KEV entry are kept with the document and not chunked; and the
  full text index is built on an expression rather than a stored column. The whole corpus, for the
  retrieval and agent evals, lives in Actions, in a Postgres that runs beside the job.
- **The run store is capped.** At most 100 runs wait for a person with every checkpoint; a decided
  run keeps only its latest checkpoint, for at most 500 runs, and after that only its record in
  the run tables: 19.2 MB at the caps.

## The projection

Once the event table is loaded again, Neon holds 700.5 MB. With the new rows of every day to
13 December, the dead rows at their bound, the corpus and the run store at its caps, the database
would hold 754.1 MB on 13 December, 94.3% of the ceiling and 45.9 MB under it (pass).

## Consequences

- From the deploy of migration 0004 until the sync has loaded the events again, the timeline and the
  as-of view of a CVE have no events. The reload is started by calling /internal/sync, which needs no
  input, until it answers done.
- The daily probe reads the room through /health, table by table, so the growth is read from one
  probe to the next rather than assumed.
- Two more trims are measured and kept for when the readings ask for them, each a dated decision:
  serving predictions only for CVEs without an NVD analysis and the evaluation sample frees the rows
  of 45,727 predictions (14.3 MB before their index), and keeping no history for CVEs published
  before 2024 that no stand in product carries and KEV does not list frees 331,668 events
  (59.1 MB before their indexes).
- A change to what the row digest of a CVE covers rewrites every row of the CVE table at once, which
  the room cannot hold; such a change ships with a load that vacuums between chunks.
- The ceiling stays where it is. Raising it is a dated change request with the plan limit it rests
  on, never an edit of config/budgets.yaml, which the plan stage of the registration holds.

## Alternatives

- **Raise the ceiling.** It would buy room without a measurement of where the room goes, and the
  plan has enough once the event key is a number.
- **Keep the vectors out of Postgres.** A file index in the bundle would hold them in the API's memory
  and keep the dense search out of SQL; step 5 compares the two on the same vectors, and the room
  plan does not depend on the answer.
- **Trim the history of old CVEs now.** It frees the most, but it takes the timeline away from CVEs
  a person may still look up; it waits until a reading asks for it.
