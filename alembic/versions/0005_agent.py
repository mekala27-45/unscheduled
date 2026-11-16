"""The agent's tables in Neon, as the room plan admits them (ADR 0011, Phase 3 step 14).

- corpus_document and corpus_chunk: the scoped corpus the API searches and the verifier reads, each
  version with known_from, known_to and withdrawn, a full text index on an expression and an HNSW
  index on the halfvec column (rows without a vector are not in it).
- agent_run: one row per triage run, the record that stays after its checkpoints go.
- agent_approval: a person's decisions, only ever added.
- agent_budget: the provider calls of each UTC day, so every function instance reads one count.

pgvector is installed here, after the room plan was committed, as ADR 0011 requires. The checkpoint
tables of the graph are created by the LangGraph saver itself, in a schema of their own named after
the API's (unscheduled_checkpoints beside unscheduled; db.checkpoint_schema), so two API schemas in
one database never share or drop each other's runs.
"""

from __future__ import annotations

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def _schema() -> str | None:
    return op.get_context().version_table_schema


def _checkpoints() -> str:
    # The same name as unscheduled_api.db.checkpoint_schema gives.
    return f"{_schema() or 'public'}_checkpoints"


def _t(name: str) -> str:
    schema = _schema()
    return f'"{schema}".{name}' if schema else name


def upgrade() -> None:
    op.execute("create extension if not exists vector")
    # doc_key is doc_id@version, one key for the sync to sweep and upsert by; row_digest lets a reload
    # write only the versions that changed (a known_to set when a newer version arrives).
    op.execute(
        f"create table {_t('corpus_document')} ("
        "doc_key text primary key, doc_id text not null, version text not null, source text not null, "
        "known_from timestamptz not null, known_to timestamptz, withdrawn timestamptz, "
        "cve_ids text[] not null default '{}', sections jsonb not null, row_digest text not null)"
    )
    op.execute(f"create index corpus_document_cves on {_t('corpus_document')} using gin (cve_ids)")
    op.execute(f"create index corpus_document_doc on {_t('corpus_document')} (doc_id, known_from)")
    op.execute(
        f"create table {_t('corpus_chunk')} ("
        "chunk_id text primary key, doc_id text not null, version text not null, source text not null, "
        "known_from timestamptz not null, known_to timestamptz, withdrawn timestamptz, "
        "ordinal integer not null, sections text[] not null, text text not null, embedding halfvec(384), "
        "row_digest text not null)"
    )
    op.execute(
        f"create index corpus_chunk_text on {_t('corpus_chunk')} using gin (to_tsvector('english', text))"
    )
    op.execute(
        f"create index corpus_chunk_hnsw on {_t('corpus_chunk')} "
        "using hnsw (embedding halfvec_cosine_ops) with (m = 16, ef_construction = 64)"
    )
    op.execute(
        f"create table {_t('agent_run')} ("
        "run_id text primary key, cve_id text not null, as_of timestamptz not null, parent_run_id text, "
        "created_at timestamptz not null, updated_at timestamptz not null, status text not null, "
        "plan_sha256 text, warning_sha256 text, checkpoints text not null default 'kept', "
        "summary jsonb not null default '{}'::jsonb)"
    )
    op.execute(f"create index agent_run_created on {_t('agent_run')} (created_at desc)")
    op.execute(f"create index agent_run_status on {_t('agent_run')} (status)")
    op.execute(
        f"create table {_t('agent_approval')} ("
        "id bigint generated always as identity primary key, run_id text not null, "
        "kind text not null check (kind in ('plan', 'warning')), sha256 text not null check (length(sha256) = 64), "
        "decision text not null check (decision in ('approve', 'reject')), decided_by text not null, "
        "decided_at timestamptz not null, token_ok boolean not null)"
    )
    op.execute(f"create index agent_approval_run on {_t('agent_approval')} (run_id)")
    op.execute(
        f"create table {_t('agent_budget')} ("
        "provider text not null, model text not null, day date not null, "
        "requests integer not null default 0, tokens integer not null default 0, primary key (provider, model, day))"
    )
    # The labels Ajay gives the forty development drafts for the judge: only ever added, and only with
    # the approver's token; the newest label on a draft's hash is the one that counts.
    op.execute(
        f"create table {_t('judge_label')} ("
        "id bigint generated always as identity primary key, draft_id text not null, "
        "sha256 text not null check (length(sha256) = 64), usable boolean not null, "
        "reason text not null check (length(reason) between 1 and 280), labelled_by text not null, "
        "labelled_at timestamptz not null)"
    )
    op.execute(f"create index judge_label_draft on {_t('judge_label')} (draft_id, labelled_at desc)")
    op.execute(f'create schema if not exists "{_checkpoints()}"')


def downgrade() -> None:
    for table in (
        "judge_label",
        "agent_budget",
        "agent_approval",
        "agent_run",
        "corpus_chunk",
        "corpus_document",
    ):
        op.execute(f"drop table if exists {_t(table)}")
    op.execute(f'drop schema if exists "{_checkpoints()}" cascade')
