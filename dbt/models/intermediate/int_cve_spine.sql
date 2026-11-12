-- One row per CVE known to the CVE List or the NVD: when it was published, who filed it, what kind of
-- filer that is, the window of config/splits.yaml it falls in, and where the NVD has it now.
with cvelist as (
    select * from {{ ref('int_cve_latest') }}
),
nvd as (
    select * from {{ ref('int_nvd_latest') }}
),
ids as (
    select cve_id from cvelist
    union
    select cve_id from nvd
),
joined as (
    select
        ids.cve_id,
        coalesce(c.date_published, n.published) as published,
        c.date_published as cvelist_published,
        n.published as nvd_published,
        c.date_reserved,
        c.date_updated,
        coalesce(
            c.state,
            case when n.vuln_status = 'Rejected' then 'REJECTED' else 'PUBLISHED' end
        ) as state,
        coalesce(c.assigner_short_name, n.source_identifier, 'unknown') as filer,
        c.assigner_org_id as filer_org_id,
        n.source_identifier as filer_nvd_id,
        c.description,
        c.problem_cwes,
        c.has_affected_versions,
        c.adp_cisa_present,
        c.snapshot_at as cvelist_snapshot_at,
        n.vuln_status as nvd_status,
        n.last_modified as nvd_last_modified,
        n.has_cpe,
        n.cpe_count,
        n.cisa_exploit_add,
        n.fetched_at as nvd_fetched_at,
        c.cve_id is not null as in_cvelist,
        n.cve_id is not null as in_nvd
    from ids
    left join cvelist as c using (cve_id)
    left join nvd as n using (cve_id)
),
typed as (
    select
        j.*,
        coalesce(fo.filer_type, fs.filer_type, 'unregistered') as filer_type
    from joined as j
    left join {{ source('config', 'filer_types') }} as fo
        on fo.org_id is not null and fo.org_id = j.filer_org_id
    left join {{ source('config', 'filer_types') }} as fs
        on fs.short_name = j.filer and fo.org_id is null
    qualify row_number() over (partition by j.cve_id order by fo.short_name nulls last, fs.short_name nulls last) = 1
)

select
    t.*,
    cast(t.published as date) as published_day,
    date_trunc('month', cast(t.published as date)) as published_month,
    coalesce(w.window_name, 'outside') as split_window,
    e.n_events,
    e.received_at,
    e.first_event_at,
    e.first_analysis_at,
    e.rejected_at,
    coalesce(e.n_events, 0) > 0 as has_history,
    t.published < cast('{{ var("history_start") }}' as timestamptz) as before_history
from typed as t
left join {{ source('config', 'splits') }} as w
    on cast(t.published as date) >= w.start_day
   and (w.end_day is null or cast(t.published as date) <= w.end_day)
left join {{ ref('int_nvd_event_summary') }} as e using (cve_id)
