-- The NVD status each change history event puts a CVE in. Receipt makes it Received; an analysis
-- event makes it Analyzed; a change by a source after an analysis makes it Modified (before any
-- analysis such a change leaves the status where it was); a rejection makes it Rejected, and an
-- unrejection returns it to Modified or Received. Other events do not move the status.
with flagged as (
    select
        cve_id,
        cve_change_id,
        event_name,
        created,
        case when event_name in ('Initial Analysis', 'Reanalysis', 'Modified Analysis') then 1 else 0 end as is_analysis
    from {{ ref('stg_nvd_changes') }}
),
running as (
    select
        *,
        max(is_analysis) over (
            partition by cve_id order by created, cve_change_id
            rows between unbounded preceding and current row
        ) as analyzed_by_now
    from flagged
)

select
    cve_id,
    cve_change_id,
    event_name,
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
where status is not null
