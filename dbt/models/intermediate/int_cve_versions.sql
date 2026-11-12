-- The versions of each CVE List record in the order the build saw them, with Q04 applied: when one
-- snapshot holds a CVE twice, the copy updated last is kept here and the others are quarantined.
-- dated_at is when every value of a version was certainly present: the record's own last update,
-- which is never after the snapshot that carried it.
with ranked as (
    select
        *,
        row_number() over (
            partition by cve_id, snapshot_at
            order by date_updated desc nulls last, record_digest desc
        ) as rank_in_snapshot
    from {{ ref('stg_cve_records') }}
)

select
    * exclude (rank_in_snapshot),
    row_number() over (partition by cve_id order by snapshot_at, date_updated nulls first, record_digest) as version_no,
    case when date_updated is not null and date_updated <= snapshot_at then date_updated else snapshot_at end as dated_at,
    case when date_updated is not null and date_updated <= snapshot_at then 'record_updated' else 'first_fetch' end as dated_by
from ranked
where rank_in_snapshot = 1
