"""A prediction without an exploitation score: the CVEs CISA listed in KEV before their publication.

The exploitation step leaves the development CVEs listed before publication (quarantine Q03) out of
its population, so their batch rows carry the band, the metrics, the CWE and the products and no
exploitation score, probability or percentile. The three columns lose NOT NULL; the row builder in
packages/api/src/unscheduled_api/bundle.py takes them together or not at all.
"""

from __future__ import annotations

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

COLUMNS = ("exploit_score", "exploit_p", "exploit_pct")


def _schema() -> str | None:
    """The schema env.py migrates. The translate map that places a created table does not reach an
    ALTER, so this migration names the schema itself."""
    return op.get_context().version_table_schema


def upgrade() -> None:
    for column in COLUMNS:
        op.alter_column("prediction", column, nullable=True, schema=_schema())


def downgrade() -> None:
    schema = _schema()
    table = f'"{schema}".prediction' if schema else "prediction"
    op.execute(f"delete from {table} where exploit_score is null")
    for column in COLUMNS:
        op.alter_column("prediction", column, nullable=False, schema=schema)
