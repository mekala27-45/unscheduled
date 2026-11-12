"""The Neon slice: the tables Alembic manages, and the engine every route and the sync share.

The tables are declared without a schema and every statement is compiled with a schema translate
map, so they land in the unscheduled schema whatever search path the connection has. Day 13 of the
series found that a pooler can drop a search path set in the startup options; a translate map does
not depend on it. The Alembic version table lives in the same schema (alembic/env.py), so another
project in the same database never sees these migrations.

    cve           the current state of each CVE in the bundle, one row per CVE, with the source and
                  known_from of every field in provenance
    cve_event     the ruler events: one row per dated event, keyed by a digest of its content
    product       the stand in products with their pins
    finding       the exposure findings per product and snapshot date, with every CVE each names
    match_log     one row per uploaded SBOM: its digest, counts, timing and hashed client, never the SBOM
    client_budget the daily count per hashed client and kind of request
    ops_run       the run ledger of the sync: one row per call that did work
    settings      small keyed values: the client salt, the loaded data version, the sync cursor
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

metadata = sa.MetaData()

settings = sa.Table(
    "settings",
    metadata,
    sa.Column("key", sa.Text, primary_key=True),
    sa.Column("value", JSONB, nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)

cve = sa.Table(
    "cve",
    metadata,
    sa.Column("cve_id", sa.Text, primary_key=True),
    sa.Column("state", sa.Text),
    sa.Column("published", sa.DateTime(timezone=True)),
    sa.Column("last_modified", sa.DateTime(timezone=True)),
    sa.Column("nvd_status", sa.Text),
    sa.Column("nvd_status_since", sa.DateTime(timezone=True)),
    sa.Column("filer", sa.Text),
    sa.Column("filer_type", sa.Text),
    sa.Column("description", sa.Text),
    sa.Column("cwes", ARRAY(sa.Text), nullable=False, server_default=sa.text("'{}'::text[]")),
    sa.Column("filer_cvss31_vector", sa.Text),
    sa.Column("filer_cvss31_score", sa.Float),
    sa.Column("filer_cvss31_band", sa.Text),
    sa.Column("filer_cvss40_vector", sa.Text),
    sa.Column("filer_cvss40_score", sa.Float),
    sa.Column("filer_cvss40_band", sa.Text),
    sa.Column("nvd_cvss31_vector", sa.Text),
    sa.Column("nvd_cvss31_score", sa.Float),
    sa.Column("nvd_cvss31_band", sa.Text),
    sa.Column("adp_cvss31_vector", sa.Text),
    sa.Column("adp_cvss31_score", sa.Float),
    sa.Column("adp_cvss31_band", sa.Text),
    sa.Column("ssvc_exploitation", sa.Text),
    sa.Column("ssvc_automatable", sa.Text),
    sa.Column("ssvc_technical_impact", sa.Text),
    sa.Column("kev_date_added", sa.Date),
    sa.Column("kev_ransomware", sa.Text),
    sa.Column("epss_score", sa.Float),
    sa.Column("epss_percentile", sa.Float),
    sa.Column("epss_date", sa.Date),
    sa.Column("exploit_first_seen", sa.Date),
    sa.Column("has_cpe", sa.Boolean),
    sa.Column("provenance", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("row_digest", sa.Text, nullable=False),
)
sa.Index("ix_cve_published", cve.c.published.desc().nulls_last(), cve.c.cve_id.desc())
sa.Index("ix_cve_nvd_status", cve.c.nvd_status)
sa.Index("ix_cve_filer", cve.c.filer)
sa.Index("ix_cve_filer_type", cve.c.filer_type)
sa.Index("ix_cve_kev", cve.c.kev_date_added, postgresql_where=cve.c.kev_date_added.isnot(None))
sa.Index("ix_cve_cwes", cve.c.cwes, postgresql_using="gin")

cve_event = sa.Table(
    "cve_event",
    metadata,
    sa.Column("event_id", sa.Text, primary_key=True),
    sa.Column("cve_id", sa.Text, nullable=False),
    sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("source", sa.Text),
    sa.Column("detail", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
)
sa.Index("ix_cve_event_cve_at", cve_event.c.cve_id, cve_event.c.at)

product = sa.Table(
    "product",
    metadata,
    sa.Column("product_id", sa.Text, primary_key=True),
    sa.Column("name", sa.Text, nullable=False),
    sa.Column("body", JSONB, nullable=False),
    sa.Column("row_digest", sa.Text, nullable=False),
)

finding = sa.Table(
    "finding",
    metadata,
    sa.Column("finding_id", sa.Text, primary_key=True),
    sa.Column("product_id", sa.Text, nullable=False),
    sa.Column("as_of", sa.Date, nullable=False),
    sa.Column("cve_ids", ARRAY(sa.Text), nullable=False, server_default=sa.text("'{}'::text[]")),
    sa.Column("body", JSONB, nullable=False),
    sa.Column("row_digest", sa.Text, nullable=False),
)
sa.Index("ix_finding_product_as_of", finding.c.product_id, finding.c.as_of)
sa.Index("ix_finding_cve_ids", finding.c.cve_ids, postgresql_using="gin")

match_log = sa.Table(
    "match_log",
    metadata,
    sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
    sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("sbom_sha256", sa.Text, nullable=False),
    sa.Column("sbom_bytes", sa.Integer, nullable=False),
    sa.Column("format", sa.Text, nullable=False),
    sa.Column("spec_version", sa.Text),
    sa.Column("components", sa.Integer, nullable=False),
    sa.Column("components_without_purl", sa.Integer, nullable=False),
    sa.Column("findings", sa.Integer),
    sa.Column("distinct_cves", sa.Integer),
    sa.Column("duration_ms", sa.Float, nullable=False),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("engine", sa.Text),
    sa.Column("client", sa.Text, nullable=False),
)
sa.Index("ix_match_log_at", match_log.c.at)

client_budget = sa.Table(
    "client_budget",
    metadata,
    sa.Column("client", sa.Text, primary_key=True),
    sa.Column("day", sa.Date, primary_key=True),
    sa.Column("kind", sa.Text, primary_key=True),
    sa.Column("used", sa.Integer, nullable=False),
)

ops_run = sa.Table(
    "ops_run",
    metadata,
    sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("bundle", sa.Text),
    sa.Column("step", sa.Text),
    sa.Column("rows_in", sa.Integer),
    sa.Column("rows_changed", sa.Integer),
    sa.Column("storage_bytes", sa.BigInteger),
    sa.Column("detail", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
)
sa.Index("ix_ops_run_kind_started", ops_run.c.kind, ops_run.c.started_at)

DATA_TABLES = ("cve", "cve_event", "product", "finding")


def make_engine(url: str, schema: str) -> sa.Engine:
    """One engine per process. A pooled Neon host gets no server side prepared statements."""
    connect_args: dict[str, Any] = {"connect_timeout": 10, "application_name": "unscheduled-api"}
    if "-pooler." in url:
        connect_args["prepare_threshold"] = None
    engine = sa.create_engine(
        url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        pool_recycle=300,
        connect_args=connect_args,
    )
    sa.event.listen(engine, "connect", _utc_session)
    return engine.execution_options(schema_translate_map={None: schema})


def _utc_session(dbapi_connection: Any, _record: Any) -> None:
    """Every session answers in UTC. Set after connecting, not in the startup options a pooler drops."""
    dbapi_connection.execute("set time zone 'UTC'")
    dbapi_connection.commit()


def qualified(schema: str, table: str) -> str:
    """A quoted schema qualified name for the few statements written as SQL text (COPY, sizes)."""
    return f'"{schema}"."{table}"'
