"""The batch predictions of Phase 2: one row per CVE no model was fit on, typed and compact.

The band and its four probabilities, its conformal set as text; the eight base metrics as one text
in the order AV, AC, PR, UI, S, C, I, A, their probabilities as one array and their sets as one text;
the CWE with its probability and top five; the exploitation score, its isotonic probability and
percentile; the chance of a KEV listing by 30, 90 and 180 days; the likeliest products as text. A
row digest of sixteen hex characters marks a changed row. The columns match
packages/api/src/unscheduled_api/db.py, and tests/api/test_migrations.py compares the two.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "prediction",
        sa.Column("cve_id", sa.Text, primary_key=True),
        sa.Column("band", sa.Text, nullable=False),
        sa.Column("band_p_low", sa.REAL, nullable=False),
        sa.Column("band_p_medium", sa.REAL, nullable=False),
        sa.Column("band_p_high", sa.REAL, nullable=False),
        sa.Column("band_p_critical", sa.REAL, nullable=False),
        sa.Column("band_set", sa.Text, nullable=False),
        sa.Column("metrics", sa.Text, nullable=False),
        sa.Column("metrics_p", ARRAY(sa.REAL), nullable=False),
        sa.Column("metric_sets", sa.Text, nullable=False),
        sa.Column("cwe", sa.Text, nullable=False),
        sa.Column("cwe_p", sa.REAL, nullable=False),
        sa.Column("cwe_top", sa.Text, nullable=False),
        sa.Column("exploit_score", sa.REAL, nullable=False),
        sa.Column("exploit_p", sa.REAL, nullable=False),
        sa.Column("exploit_pct", sa.REAL, nullable=False),
        sa.Column("listed_by_30", sa.REAL),
        sa.Column("listed_by_90", sa.REAL),
        sa.Column("listed_by_180", sa.REAL),
        sa.Column("products", sa.Text, nullable=False),
        sa.Column("row_digest", sa.Text, nullable=False),
    )
    op.create_index("ix_prediction_band", "prediction", ["band"])


def downgrade() -> None:
    op.drop_table("prediction")
