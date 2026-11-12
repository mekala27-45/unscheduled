{{ config(materialized='view') }}
-- Observations of what the sources hold today, for the metrics, CWEs and CPE configurations, dated
-- by the newest time at which the build can vouch the value was already there:
--   nvd_last_modified  a value in the NVD record was there when the record was last modified
--   record_updated     a value in a CVE List record was there when the record was last updated
--   first_fetch        when neither is known, the first fetch that saw it
--   before_history     an NVD value of a CVE published before the change history began, which the
--                      history never shows being set, was set before the history: dated from
--                      publication (CVSS 3.0, which the NVD backfilled, from the history start) and
--                      flagged, so the analysis can count how many CVEs depend on the rule
-- When the history also shows the value, the earlier history observation starts the fact and these
-- only confirm it, so a value never gets a later date than an event already gave it.
with spine as (
    select * from {{ ref('int_cve_spine') }}
),
history_keys as (
    select distinct cve_id, field, source from {{ ref('int_obs_history') }}
),
nvd_rows as (
    select cve_id, fetched_at, last_modified from {{ ref('stg_nvd_cves') }}
),
versions as (
    select cve_id, snapshot_at, dated_at, dated_by from {{ ref('int_cve_versions') }}
),
metrics as (
    select m.*
    from {{ ref('int_metrics_checked') }} as m
    where coalesce(m.quarantine_rule, 'none') not in ('Q01', 'Q05') and m.base_vector is not null
),
metrics_nvd as (
    select m.*, n.last_modified as record_at
    from metrics as m
    asof left join nvd_rows as n
        on n.cve_id = m.cve_id and m.observed_at >= n.fetched_at
    where m.origin = 'nvd_api'
),
metrics_cvelist as (
    select m.*, v.dated_at as record_at, v.dated_by as record_rule
    from metrics as m
    asof left join versions as v
        on v.cve_id = m.cve_id and m.observed_at >= v.snapshot_at
    where m.origin <> 'nvd_api'
),
metric_obs as (
    select
        m.cve_id,
        {{ cvss_field('m.version') }} as field,
        m.source,
        m.version,
        m.base_vector,
        m.computed_score,
        case
            when m.source = 'nvd@nist.gov' and s.before_history and m.version in ('2.0', '3.0') and h.cve_id is null
                then case when m.version = '3.0'
                          then greatest(s.published, cast('{{ var("history_start") }}' as timestamptz))
                          else s.published end
            when m.record_at is not null and m.record_at <= m.observed_at then m.record_at
            else m.observed_at
        end as seen_at,
        case
            when m.source = 'nvd@nist.gov' and s.before_history and m.version in ('2.0', '3.0') and h.cve_id is null
                then 'before_history'
            when m.record_at is not null and m.record_at <= m.observed_at then 'nvd_last_modified'
            else 'first_fetch'
        end as dated_by
    from metrics_nvd as m
    join spine as s using (cve_id)
    left join history_keys as h
        on h.cve_id = m.cve_id and h.source = m.source
       and h.field = {{ cvss_field('m.version') }}
    union all
    select
        m.cve_id,
        {{ cvss_field('m.version') }},
        m.source,
        m.version,
        m.base_vector,
        m.computed_score,
        case when m.record_at is not null and m.record_at <= m.observed_at then m.record_at else m.observed_at end,
        case when m.record_at is not null and m.record_at <= m.observed_at then m.record_rule else 'first_fetch' end
    from metrics_cvelist as m
),
cvss as (
    select cve_id, field, source, base_vector as value, seen_at, dated_by from metric_obs
    union all
    select cve_id, replace(field, '_vector', '_score'), source, printf('%.1f', computed_score), seen_at, dated_by
    from metric_obs
    union all
    select cve_id, replace(field, '_vector', '_severity'), source,
           case when version = '2.0' then {{ cvss2_band('computed_score') }} else {{ cvss_band('computed_score') }} end,
           seen_at, dated_by
    from metric_obs
),
weak as (
    select
        w.cve_id,
        w.cwe_id,
        w.origin,
        w.observed_at,
        case
            when w.raw_source = 'nvd@nist.gov' then 'nvd@nist.gov'
            when w.raw_source = {{ cisa_adp_id() }} or upper(w.raw_source) like 'CISA%ADP%' then 'CISA-ADP'
            when w.raw_source in (s.filer_nvd_id, s.filer_org_id, s.filer) then s.filer
            when w.origin <> 'nvd_api' and w.raw_source is null then s.filer
            else coalesce(w.raw_source, 'unknown')
        end as source,
        s.before_history,
        s.published
    from {{ ref('stg_cve_weaknesses') }} as w
    join spine as s using (cve_id)
    where s.state <> 'REJECTED'
),
weak_dated as (
    select w.*, n.last_modified as record_at, null::varchar as record_rule
    from weak as w
    asof left join nvd_rows as n on n.cve_id = w.cve_id and w.observed_at >= n.fetched_at
    where w.origin = 'nvd_api'
    union all
    select w.*, v.dated_at, v.dated_by
    from weak as w
    asof left join versions as v on v.cve_id = w.cve_id and w.observed_at >= v.snapshot_at
    where w.origin <> 'nvd_api'
),
cwe as (
    select
        w.cve_id,
        'cwe' as field,
        w.source,
        w.cwe_id as value,
        case
            when w.source = 'nvd@nist.gov' and w.before_history and h.cve_id is null then w.published
            when w.record_at is not null and w.record_at <= w.observed_at then w.record_at
            else w.observed_at
        end as seen_at,
        case
            when w.source = 'nvd@nist.gov' and w.before_history and h.cve_id is null then 'before_history'
            when w.record_at is not null and w.record_at <= w.observed_at
                then coalesce(w.record_rule, 'nvd_last_modified')
            else 'first_fetch'
        end as dated_by
    from weak_dated as w
    left join history_keys as h
        on h.cve_id = w.cve_id and h.field = 'cwe' and h.source = w.source
),
cpe as (
    select
        s.cve_id,
        'cpe_config' as field,
        'nvd@nist.gov' as source,
        'present' as value,
        case
            when s.before_history and h.cve_id is null then s.published
            when s.nvd_last_modified is not null then s.nvd_last_modified
            else s.nvd_fetched_at
        end as seen_at,
        case
            when s.before_history and h.cve_id is null then 'before_history'
            when s.nvd_last_modified is not null then 'nvd_last_modified'
            else 'first_fetch'
        end as dated_by
    from spine as s
    left join history_keys as h
        on h.cve_id = s.cve_id and h.field = 'cpe_config' and h.source = 'nvd@nist.gov'
    where s.has_cpe
)

select cve_id, field, source, value, seen_at, 'set' as op, dated_by, dated_by = 'before_history' as pre_history
from (
    select * from cvss
    union all
    select * from cwe
    union all
    select * from cpe
)
where value is not null and seen_at is not null
