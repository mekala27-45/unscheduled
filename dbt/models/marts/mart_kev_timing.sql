-- Q5, exploited and when: every KEV listed CVE published since 2021-01-01, the days from
-- publication to listing, the NVD status at the moment of listing read as of that moment from the
-- facts (so an analysis that came later never counts), and whether Metasploit or Nuclei code
-- existed before the listing. A listing dated before publication is quarantine rule Q03 and is not
-- timed here.
with kev as (
    select c.*
    from {{ ref('cve_current') }} as c
    where c.kev_listed
      and c.published >= cast('{{ var("serving_start") }}' as timestamptz)
      and c.kev_date_added >= c.published_day
),
status_at_listing as (
    select cve_id, value as nvd_status_at_listing, dated_by as status_dated_by
    from (
        {{ asof_join("kev", "kev_listed_at", fields=["nvd_status"]) }}
    )
),
listing_rule as (
    select cve_id, listed_dated_by from {{ ref('kev_events') }}
)

select
    cast(k.cve_id as varchar) as cve_id,
    cast(k.filer as varchar) as filer,
    cast(k.filer_type as varchar) as filer_type,
    cast(k.split_window as varchar) as split_window,
    cast(k.published as timestamptz) as published,
    cast(k.kev_date_added as date) as date_added,
    cast(k.kev_listed_at as timestamptz) as listed_at,
    cast(r.listed_dated_by as varchar) as listed_dated_by,
    cast(datediff('day', k.published_day, k.kev_date_added) as integer) as days_to_listing,
    cast(s.nvd_status_at_listing as varchar) as nvd_status_at_listing,
    cast(coalesce(s.nvd_status_at_listing in ('Analyzed', 'Modified'), false) as boolean) as nvd_analyzed_at_listing,
    cast(k.first_analysis_at as timestamptz) as first_analysis_at,
    cast(k.first_exploit_at as timestamptz) as first_exploit_at,
    cast(coalesce(k.first_exploit_at < k.kev_listed_at, false) as boolean) as exploit_before_listing,
    cast(coalesce(k.first_metasploit_at < k.kev_listed_at, false) as boolean) as metasploit_before_listing,
    cast(coalesce(k.first_nuclei_at < k.kev_listed_at, false) as boolean) as nuclei_before_listing
from kev as k
left join status_at_listing as s using (cve_id)
left join listing_rule as r using (cve_id)
