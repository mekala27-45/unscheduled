"""Events keyed by a bigint, and the CVE table vacuumed sooner: the room plan of Phase 3 (ADR 0011).

The 16 hex characters of an event id are 64 bits. Stored as text the key took 22 MB of the event
table and an index of 69 MB; as one bigint, shifted by 2**63 so that the signed order of the numbers
is the order of the hex strings, it takes 10 MB and an index of 29 MB, measured on a fresh copy of the
serving tables (results/agent/room.json). Answers still carry the hex string.

Rewriting the 372 MB table in place would need a second copy of it, and Neon's plan has no room for
one, so the table is emptied first and the sync loads it again from the serving release: the
migration clears the loaded release from the settings, and the next call to /internal/sync starts a
full load. Until it ends, the timeline and the as-of view of a CVE have no events.

The CVE table takes a few thousand updates a day (EPSS, the NVD status, last modified), and the
default autovacuum lets dead rows reach a fifth of a 260,000 row table before it reclaims them. At
two percent the dead rows of a few days are reclaimed instead of a few weeks.
"""

from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

# Flipping the top bit turns the two's complement reading of the 64 bits into the offset reading.
TOP_BIT = "x'8000000000000000'"


def _schema() -> str | None:
    """The schema env.py migrates; an ALTER does not reach the translate map, so name it here."""
    return op.get_context().version_table_schema


def _t(name: str) -> str:
    schema = _schema()
    return f'"{schema}".{name}' if schema else name


def upgrade() -> None:
    op.execute(f"truncate {_t('cve_event')}")
    op.execute(f"alter table {_t('cve_event')} drop constraint cve_event_pkey")
    op.execute(
        f"alter table {_t('cve_event')} alter column event_id type bigint "
        f"using ((('x' || event_id)::bit(64) # {TOP_BIT})::bigint)"
    )
    op.execute(f"alter table {_t('cve_event')} add constraint cve_event_pkey primary key (event_id)")
    op.execute(
        f"alter table {_t('cve')} set "
        "(autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.02)"
    )
    op.execute(f"delete from {_t('settings')} where key in ('data_version', 'release_check', 'sync')")


def downgrade() -> None:
    op.execute(f"truncate {_t('cve_event')}")
    op.execute(f"alter table {_t('cve_event')} drop constraint cve_event_pkey")
    op.execute(
        f"alter table {_t('cve_event')} alter column event_id type text "
        f"using lpad(to_hex(((event_id::bit(64)) # {TOP_BIT})::bigint), 16, '0')"
    )
    op.execute(f"alter table {_t('cve_event')} add constraint cve_event_pkey primary key (event_id)")
    op.execute(
        f"alter table {_t('cve')} reset (autovacuum_vacuum_scale_factor, autovacuum_analyze_scale_factor)"
    )
    op.execute(f"delete from {_t('settings')} where key in ('data_version', 'release_check', 'sync')")
