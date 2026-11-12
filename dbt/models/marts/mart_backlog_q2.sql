-- Q2, after the change: every CVE published since 2026-04-15, its NVD status now, whether the NVD
-- analyzed it, whether it is in KEV, and for a KEV listed CVE the hours from the listing to the
-- first NVD analysis at or after it, against the goal of one business day (the same time on the next
-- weekday; federal holidays are not removed, so the goal is read slightly tighter than NIST's).
with base as (
    select *
    from {{ ref('cve_current') }}
    where published >= cast('{{ var("nvd_change_date") }}' as timestamptz)
),
analysis as (
    select cve_id, created
    from {{ ref('stg_nvd_changes') }}
    where event_name in ('Initial Analysis', 'Reanalysis', 'Modified Analysis')
),
after_listing as (
    select b.cve_id, min(a.created) as analysis_after_listing_at
    from base as b
    join analysis as a on a.cve_id = b.cve_id and a.created >= b.kev_listed_at
    where b.kev_listed
    group by b.cve_id
),
dated as (
    select
        b.*,
        al.analysis_after_listing_at,
        b.first_analysis_at is not null and b.kev_listed and b.first_analysis_at < b.kev_listed_at as analyzed_before_listing,
        case
            when b.kev_listed_at is null then null
            when dayofweek(b.kev_listed_at) = 5 then b.kev_listed_at + to_days(3)
            when dayofweek(b.kev_listed_at) = 6 then b.kev_listed_at + to_days(3) - (b.kev_listed_at - date_trunc('day', b.kev_listed_at))
            when dayofweek(b.kev_listed_at) = 0 then b.kev_listed_at + to_days(2) - (b.kev_listed_at - date_trunc('day', b.kev_listed_at))
            else b.kev_listed_at + to_days(1)
        end as business_day_deadline
    from base as b
    left join after_listing as al using (cve_id)
)

select
    cast(cve_id as varchar) as cve_id,
    cast(filer as varchar) as filer,
    cast(filer_type as varchar) as filer_type,
    cast(published as timestamptz) as published,
    cast(published_month as date) as published_month,
    cast(state as varchar) as state,
    cast(nvd_status as varchar) as nvd_status,
    cast(nvd_analyzed as boolean) as nvd_analyzed,
    cast(first_analysis_at as timestamptz) as first_analysis_at,
    cast(kev_listed as boolean) as kev_listed,
    cast(kev_listed_at as timestamptz) as kev_listed_at,
    cast(analysis_after_listing_at as timestamptz) as analysis_after_listing_at,
    cast(analyzed_before_listing as boolean) as analyzed_before_listing,
    cast(
        case when analysis_after_listing_at is not null
             then (epoch(analysis_after_listing_at) - epoch(kev_listed_at)) / 3600.0 end
        as double
    ) as hours_listing_to_analysis,
    cast(business_day_deadline as timestamptz) as business_day_deadline,
    cast(
        -- judged only once the deadline has passed, so a listing too recent to judge is left out
        -- whether or not the NVD has analyzed it yet
        case
            when not kev_listed then null
            when business_day_deadline > {{ data_cut() }} then null
            when analyzed_before_listing then true
            when analysis_after_listing_at is not null and analysis_after_listing_at <= business_day_deadline then true
            else false
        end as boolean
    ) as met_one_business_day
from dated
