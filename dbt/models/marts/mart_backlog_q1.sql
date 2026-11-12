-- Q1, the analysis delay: every CVE published since 2020-01-01, rejected CVEs excluded, with the
-- days from publication to the first NVD analysis event. A CVE counts as analyzed within k days only
-- when k days have passed by the data cut; otherwise its k day flag is null (censored), so a month
-- too recent to judge is never read as a month the NVD skipped. analysis_undated marks a CVE the NVD
-- calls analyzed whose analysis the change history does not date.
with base as (
    select *
    from {{ ref('cve_current') }}
    where published >= cast('{{ var("study_start") }}' as timestamptz)
      and state <> 'REJECTED'
),
cut as (
    select {{ data_cut() }} as data_cut
)

select
    cast(b.cve_id as varchar) as cve_id,
    cast(b.filer as varchar) as filer,
    cast(b.filer_type as varchar) as filer_type,
    cast(b.published as timestamptz) as published,
    cast(b.published_month as date) as published_month,
    cast(b.split_window as varchar) as split_window,
    cast(b.first_analysis_at as timestamptz) as first_analysis_at,
    cast(
        case when b.first_analysis_at is not null
             then greatest(epoch(b.first_analysis_at) - epoch(b.published), 0) / 86400.0 end
        as double
    ) as days_to_analysis,
    cast(b.nvd_status as varchar) as nvd_status,
    cast(b.nvd_analyzed and b.first_analysis_at is null as boolean) as analysis_undated,
    cast((epoch(c.data_cut) - epoch(b.published)) / 86400.0 as double) as followup_days,
    {% for k in [7, 30, 90] %}
    cast(
        -- censored first: a CVE younger than k days is not judged at k days even when it was
        -- analyzed already, or the recent months would count only their quick analyses
        case
            when b.published + to_days({{ k }}) > c.data_cut then null
            when b.first_analysis_at is not null
             and epoch(b.first_analysis_at) - epoch(b.published) <= {{ k }} * 86400 then true
            when b.nvd_analyzed and b.first_analysis_at is null then null
            else false
        end as boolean
    ) as analyzed_{{ k }}d{% if not loop.last %},{% endif %}
    {% endfor %}
from base as b
cross join cut as c
