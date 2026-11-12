-- gold.cve_current: one row per CVE, what every source holds about it now (the facts current at the
-- data cut), next to where it was published, who filed it and what the NVD has done with it.
with spine as (
    select * from {{ ref('int_cve_spine') }}
),
cur as (
    select f.*, s.filer
    from {{ ref('cve_fact') }} as f
    join spine as s using (cve_id)
    where f.known_to is null
),
current_values as (
    select
        cve_id,
        max(value) filter (where field = 'nvd_status') as nvd_status,
        max(known_from) filter (where field = 'nvd_status') as nvd_status_since,
        max(dated_by) filter (where field = 'nvd_status') as nvd_status_dated_by,
        max(value) filter (where field = 'cvss31_vector' and source = 'nvd@nist.gov') as nvd_cvss31_vector,
        max(value) filter (where field = 'cvss31_score' and source = 'nvd@nist.gov') as nvd_cvss31_score,
        max(value) filter (where field = 'cvss31_severity' and source = 'nvd@nist.gov') as nvd_cvss31_band,
        max(value) filter (where field = 'cvss40_vector' and source = 'nvd@nist.gov') as nvd_cvss40_vector,
        max(value) filter (where field = 'cvss31_vector' and source = filer) as filer_cvss31_vector,
        max(value) filter (where field = 'cvss31_score' and source = filer) as filer_cvss31_score,
        max(value) filter (where field = 'cvss31_severity' and source = filer) as filer_cvss31_band,
        max(value) filter (where field = 'cvss30_vector' and source = filer) as filer_cvss30_vector,
        max(value) filter (where field = 'cvss30_score' and source = filer) as filer_cvss30_score,
        max(value) filter (where field = 'cvss30_severity' and source = filer) as filer_cvss30_band,
        max(value) filter (where field = 'cvss40_vector' and source = filer) as filer_cvss40_vector,
        max(value) filter (where field = 'cvss40_score' and source = filer) as filer_cvss40_score,
        max(value) filter (where field = 'cvss40_severity' and source = filer) as filer_cvss40_band,
        max(value) filter (where field = 'cvss31_vector' and source = 'CISA-ADP') as adp_cvss31_vector,
        max(value) filter (where field = 'cvss31_score' and source = 'CISA-ADP') as adp_cvss31_score,
        max(value) filter (where field = 'cvss31_severity' and source = 'CISA-ADP') as adp_cvss31_band,
        list(distinct value order by value) filter (where field = 'cwe' and source = filer) as filer_cwes,
        list(distinct value order by value) filter (where field = 'cwe' and source = 'nvd@nist.gov') as nvd_cwes,
        list(distinct value order by value) filter (where field = 'cwe' and source = 'CISA-ADP') as adp_cwes,
        max(value) filter (where field = 'ssvc_exploitation') as ssvc_exploitation,
        max(value) filter (where field = 'ssvc_automatable') as ssvc_automatable,
        max(value) filter (where field = 'ssvc_technical_impact') as ssvc_technical_impact,
        max(value) filter (where field = 'kev_ransomware') as kev_ransomware,
        max(value) filter (where field = 'epss') as epss,
        max(known_from) filter (where field = 'epss') as epss_known_from,
        max(value) filter (where field = 'affected_versions' and source = filer) as affected_versions,
        bool_or(field = 'cpe_config') as has_cpe_fact,
        count(*) filter (where pre_history) as pre_history_facts
    from cur
    group by cve_id
),
kev as (
    select * from {{ ref('kev_events') }}
),
exploits as (
    select * from {{ ref('exploit_first_seen') }}
)

select
    cast(s.cve_id as varchar) as cve_id,
    cast(s.published as timestamptz) as published,
    cast(s.published_day as date) as published_day,
    cast(s.published_month as date) as published_month,
    cast(s.split_window as varchar) as split_window,
    cast(s.state as varchar) as state,
    cast(s.filer as varchar) as filer,
    cast(s.filer_org_id as varchar) as filer_org_id,
    cast(s.filer_type as varchar) as filer_type,
    cast(s.filer_nvd_id as varchar) as filer_nvd_id,
    cast(s.date_reserved as timestamptz) as date_reserved,
    cast(s.date_updated as timestamptz) as date_updated,
    cast(s.description as varchar) as description,
    cast(s.in_cvelist as boolean) as in_cvelist,
    cast(s.in_nvd as boolean) as in_nvd,
    cast(coalesce(p.nvd_status, s.nvd_status) as varchar) as nvd_status,
    cast(p.nvd_status_since as timestamptz) as nvd_status_since,
    cast(p.nvd_status_dated_by as varchar) as nvd_status_dated_by,
    cast(s.first_analysis_at as timestamptz) as first_analysis_at,
    -- Analyzed by the cut: a CVE the NVD does not hold, or holds with no status, has not been.
    cast(
        coalesce(
            s.first_analysis_at is not null or coalesce(p.nvd_status, s.nvd_status) in ('Analyzed', 'Modified'),
            false
        )
        as boolean
    ) as nvd_analyzed,
    cast(s.nvd_last_modified as timestamptz) as nvd_last_modified,
    cast(p.nvd_cvss31_vector as varchar) as nvd_cvss31_vector,
    cast(p.nvd_cvss31_score as double) as nvd_cvss31_score,
    cast(p.nvd_cvss31_band as varchar) as nvd_cvss31_band,
    cast(p.nvd_cvss40_vector as varchar) as nvd_cvss40_vector,
    cast(p.filer_cvss31_vector as varchar) as filer_cvss31_vector,
    cast(p.filer_cvss31_score as double) as filer_cvss31_score,
    cast(p.filer_cvss31_band as varchar) as filer_cvss31_band,
    cast(p.filer_cvss30_vector as varchar) as filer_cvss30_vector,
    cast(p.filer_cvss30_score as double) as filer_cvss30_score,
    cast(p.filer_cvss30_band as varchar) as filer_cvss30_band,
    cast(p.filer_cvss40_vector as varchar) as filer_cvss40_vector,
    cast(p.filer_cvss40_score as double) as filer_cvss40_score,
    cast(p.filer_cvss40_band as varchar) as filer_cvss40_band,
    cast(p.adp_cvss31_vector as varchar) as adp_cvss31_vector,
    cast(p.adp_cvss31_score as double) as adp_cvss31_score,
    cast(p.adp_cvss31_band as varchar) as adp_cvss31_band,
    cast(coalesce(p.filer_cwes, []) as varchar[]) as filer_cwes,
    cast(coalesce(p.nvd_cwes, []) as varchar[]) as nvd_cwes,
    cast(coalesce(p.adp_cwes, []) as varchar[]) as adp_cwes,
    cast(coalesce(p.affected_versions = 'true', s.has_affected_versions, false) as boolean) as has_affected_versions,
    cast(coalesce(s.adp_cisa_present, false) as boolean) as adp_cisa_present,
    cast(p.ssvc_exploitation as varchar) as ssvc_exploitation,
    cast(p.ssvc_automatable as varchar) as ssvc_automatable,
    cast(p.ssvc_technical_impact as varchar) as ssvc_technical_impact,
    cast(k.cve_id is not null as boolean) as kev_listed,
    cast(k.date_added as date) as kev_date_added,
    cast(k.listed_at as timestamptz) as kev_listed_at,
    cast(coalesce(p.kev_ransomware, k.known_ransomware) as varchar) as kev_ransomware,
    cast(p.epss as double) as epss,
    cast(cast(p.epss_known_from as date) as date) as epss_date,
    cast(e.first_seen as timestamptz) as first_exploit_at,
    cast(e.metasploit_first_seen as timestamptz) as first_metasploit_at,
    cast(e.nuclei_first_seen as timestamptz) as first_nuclei_at,
    cast(coalesce(s.has_cpe, false) as boolean) as has_cpe,
    cast(coalesce(s.cpe_count, 0) as integer) as cpe_count,
    cast(s.has_history as boolean) as has_history,
    cast(coalesce(s.n_events, 0) as bigint) as history_events,
    cast(s.before_history as boolean) as before_history,
    cast(coalesce(p.pre_history_facts, 0) as bigint) as pre_history_facts
from spine as s
left join current_values as p using (cve_id)
left join kev as k using (cve_id)
left join exploits as e using (cve_id)
