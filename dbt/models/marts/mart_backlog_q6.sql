-- Q6, who files the flood: CVEs published since 2020-01-01 by month and filer, with the filer type,
-- the month total and the filer's share of it.
with base as (
    select published_month, filer, filer_type, state
    from {{ ref('cve_current') }}
    where published >= cast('{{ var("study_start") }}' as timestamptz)
),
counts as (
    select published_month, filer, any_value(filer_type) as filer_type,
           count(*) as cves, count(*) filter (where state = 'REJECTED') as rejected
    from base
    group by published_month, filer
)

select
    cast(published_month as date) as published_month,
    cast(filer as varchar) as filer,
    cast(filer_type as varchar) as filer_type,
    cast(cves as bigint) as cves,
    cast(rejected as bigint) as rejected,
    cast(sum(cves) over (partition by published_month) as bigint) as month_total,
    cast(cves / sum(cves) over (partition by published_month) as double) as share_of_month
from counts
