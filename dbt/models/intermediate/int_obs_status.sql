{{ config(materialized='view') }}
-- Observations of the NVD status. A CVE published before the change history began and not received
-- in it starts in the status it had before the history (Analyzed if the NVD analyzed it then, else
-- Received), dated from publication and flagged (before_history). The events then move it
-- (int_nvd_status_events). The status the NVD gives today ends the chain: a status that follows a
-- record change (Received, Analyzed, Modified, Rejected) is dated by the record's last modification
-- time; a queue status the history never records (Awaiting Analysis, Undergoing Analysis, Deferred)
-- is dated by the first fetch that saw it, the only time the build can vouch for.
with spine as (
    select * from {{ ref('int_cve_spine') }}
),
pre as (
    select
        s.cve_id,
        case
            when s.nvd_status in ('Analyzed', 'Modified') then 'Analyzed'
            else 'Received'
        end as status0,
        s.published
    from spine as s
    where s.in_nvd and s.before_history and s.received_at is null
),
analysis_events as (
    select
        e.cve_id,
        e.cve_change_id,
        e.event_name,
        e.created,
        case when e.event_name in ('Initial Analysis', 'Reanalysis', 'Modified Analysis') then 1 else 0 end as is_analysis,
        case when p.status0 = 'Analyzed' then 1 else 0 end as analyzed_before_history
    from {{ ref('stg_nvd_changes') }} as e
    left join pre as p using (cve_id)
),
running as (
    select
        *,
        greatest(
            analyzed_before_history,
            max(is_analysis) over (
                partition by cve_id order by created, cve_change_id
                rows between unbounded preceding and current row
            )
        ) as analyzed_by_now
    from analysis_events
),
events as (
    select cve_id, created as seen_at, status
    from (
        select
            cve_id,
            created,
            case
                when event_name = 'New CVE Received' then 'Received'
                when is_analysis = 1 then 'Analyzed'
                when event_name = 'CVE Modified' and analyzed_by_now = 1 then 'Modified'
                when event_name = 'CVE Rejected' then 'Rejected'
                when event_name = 'CVE Unrejected' and analyzed_by_now = 1 then 'Modified'
                when event_name = 'CVE Unrejected' then 'Received'
            end as status
        from running
    )
    where status is not null
),
current_status as (
    select
        n.cve_id,
        n.vuln_status as status,
        case
            when n.vuln_status in ('Received', 'Analyzed', 'Modified', 'Rejected') and n.last_modified is not null
                then n.last_modified
            else n.first_fetched_at
        end as seen_at,
        case
            when n.vuln_status in ('Received', 'Analyzed', 'Modified', 'Rejected') and n.last_modified is not null
                then 'nvd_last_modified'
            else 'first_fetch'
        end as dated_by
    from {{ ref('int_nvd_latest') }} as n
    where n.vuln_status is not null
)

select cve_id, 'nvd_status' as field, 'nvd@nist.gov' as source, status0 as value, published as seen_at,
       'set' as op, 'before_history' as dated_by, true as pre_history
from pre
union all
select cve_id, 'nvd_status', 'nvd@nist.gov', status, seen_at, 'set', 'nvd_history', false
from events
union all
select cve_id, 'nvd_status', 'nvd@nist.gov', status, seen_at, 'set', dated_by, false
from current_status
