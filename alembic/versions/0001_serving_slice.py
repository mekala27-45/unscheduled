"""The serving slice and the operational tables: cve, cve_event, product, finding, match_log,
client_budget, ops_run and settings.

Tables are named without a schema; env.py translates them into the unscheduled schema. The columns
match packages/api/src/unscheduled_api/db.py, and tests/api/test_migrations.py compares the two.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "settings",
        sa.Column("key", sa.Text, primary_key=True),
        sa.Column("value", JSONB, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "cve",
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
    op.create_index("ix_cve_published", "cve", [sa.text("published DESC NULLS LAST"), sa.text("cve_id DESC")])
    op.create_index("ix_cve_nvd_status", "cve", ["nvd_status"])
    op.create_index("ix_cve_filer", "cve", ["filer"])
    op.create_index("ix_cve_filer_type", "cve", ["filer_type"])
    op.create_index(
        "ix_cve_kev", "cve", ["kev_date_added"], postgresql_where=sa.text("kev_date_added IS NOT NULL")
    )
    op.create_index("ix_cve_cwes", "cve", ["cwes"], postgresql_using="gin")

    op.create_table(
        "cve_event",
        sa.Column("event_id", sa.Text, primary_key=True),
        sa.Column("cve_id", sa.Text, nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("source", sa.Text),
        sa.Column("detail", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("ix_cve_event_cve_at", "cve_event", ["cve_id", "at"])

    op.create_table(
        "product",
        sa.Column("product_id", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("body", JSONB, nullable=False),
        sa.Column("row_digest", sa.Text, nullable=False),
    )
    op.create_table(
        "finding",
        sa.Column("finding_id", sa.Text, primary_key=True),
        sa.Column("product_id", sa.Text, nullable=False),
        sa.Column("as_of", sa.Date, nullable=False),
        sa.Column("cve_ids", ARRAY(sa.Text), nullable=False, server_default=sa.text("'{}'::text[]")),
        sa.Column("body", JSONB, nullable=False),
        sa.Column("row_digest", sa.Text, nullable=False),
    )
    op.create_index("ix_finding_product_as_of", "finding", ["product_id", "as_of"])
    op.create_index("ix_finding_cve_ids", "finding", ["cve_ids"], postgresql_using="gin")

    op.create_table(
        "match_log",
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
    op.create_index("ix_match_log_at", "match_log", ["at"])

    op.create_table(
        "client_budget",
        sa.Column("client", sa.Text, primary_key=True),
        sa.Column("day", sa.Date, primary_key=True),
        sa.Column("kind", sa.Text, primary_key=True),
        sa.Column("used", sa.Integer, nullable=False),
    )
    op.create_table(
        "ops_run",
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
    op.create_index("ix_ops_run_kind_started", "ops_run", ["kind", "started_at"])


def downgrade() -> None:
    for name in (
        "ops_run",
        "client_budget",
        "match_log",
        "finding",
        "product",
        "cve_event",
        "cve",
        "settings",
    ):
        op.drop_table(name)
