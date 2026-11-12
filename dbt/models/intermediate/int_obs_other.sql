{{ config(materialized='view') }}
-- Observations from the sources that date themselves: KEV (the listing), CISA Vulnrichment (the
-- commit of each version of a CVE's file), the exploit repositories (the first commit of a module or
-- template), EPSS (the score date), and the CVE List record itself (its state, its filer and whether
-- it names affected versions, each from the record's last update).
with kev as (
    select * from {{ ref('int_kev_listing') }}
),
kev_obs as (
    select cve_id, 'kev_listed' as field, 'kev' as source, 'true' as value, listed_at as seen_at, listed_dated_by as dated_by
    from kev
    union all
    -- A ransomware use CISA did not know at listing is dated from the catalog version that first said so.
    select cve_id, 'kev_ransomware', 'kev', 'Unknown', listed_at, listed_dated_by
    from kev
    where first_known_ransomware is distinct from 'Known'
    union all
    select cve_id, 'kev_ransomware', 'kev', 'Known',
           case when first_known_ransomware = 'Known' then listed_at else greatest(listed_at, known_ransomware_at) end,
           case when first_known_ransomware = 'Known' then listed_dated_by else 'kev_catalog_version' end
    from kev
    where known_ransomware = 'Known' and (first_known_ransomware = 'Known' or known_ransomware_at is not null)
),
vr as (
    select
        v.*,
        case when v.last_modified = v.first_added then 'git_first_commit' else 'git_commit' end as rule
    from {{ ref('stg_vulnrichment') }} as v
    where v.last_modified is not null
),
vr_checks as (
    select
        v.cve_id,
        v.last_modified,
        v.rule,
        c.version,
        c.base_vector,
        c.base_score
    from vr as v
    join {{ ref('int_vector_checks') }} as c
        on c.vector = v.adp_cvss_vector
       and c.version = {{ cvss_version('v.adp_cvss_vector', "'3.1'") }}
       and c.parses
),
vr_obs as (
    select cve_id, 'ssvc_exploitation' as field, 'CISA-ADP' as source, ssvc_exploitation as value, last_modified as seen_at, rule as dated_by
    from vr where ssvc_exploitation is not null
    union all
    select cve_id, 'ssvc_automatable', 'CISA-ADP', ssvc_automatable, last_modified, rule
    from vr where ssvc_automatable is not null
    union all
    select cve_id, 'ssvc_technical_impact', 'CISA-ADP', ssvc_technical_impact, last_modified, rule
    from vr where ssvc_technical_impact is not null
    union all
    select cve_id, {{ cvss_field('version') }}, 'CISA-ADP', base_vector, last_modified, rule from vr_checks
    union all
    select cve_id, replace({{ cvss_field('version') }}, '_vector', '_score'), 'CISA-ADP', printf('%.1f', base_score), last_modified, rule
    from vr_checks
    union all
    select cve_id, replace({{ cvss_field('version') }}, '_vector', '_severity'), 'CISA-ADP', {{ cvss_band('base_score') }}, last_modified, rule
    from vr_checks
),
vr_cwe as (
    select cve_id, 'cwe' as field, 'CISA-ADP' as source, upper(trim(unnest(adp_cwes))) as value, last_modified as seen_at, rule as dated_by
    from vr
),
exploit_obs as (
    select cve_id, 'exploit_code' as field, source, path as value, first_seen as seen_at, 'git_first_commit' as dated_by
    from {{ ref('stg_exploit_signals') }}
    where first_seen is not null
),
epss_obs as (
    select cve_id, 'epss' as field, 'epss' as source, printf('%.5f', epss) as value,
           cast(score_date as timestamptz) as seen_at, 'epss_score_date' as dated_by
    from {{ ref('stg_epss_offsets') }}
),
record_versions as (
    select v.*, s.filer, s.filer_nvd_id, s.received_at
    from {{ ref('int_cve_versions') }} as v
    join {{ ref('int_cve_spine') }} as s using (cve_id)
),
received as (
    select cve_id, min(created) as received_at, arg_min(source_identifier, created) as received_from
    from {{ ref('stg_nvd_changes') }}
    where event_name = 'New CVE Received'
    group by cve_id
),
record_obs as (
    select cve_id, 'cve_state' as field, 'cvelist' as source, state as value, dated_at as seen_at, dated_by
    from record_versions
    union all
    select cve_id, 'affected_versions', filer, case when has_affected_versions then 'true' else 'false' end, dated_at, dated_by
    from record_versions
    union all
    select cve_id, 'assigner', 'cvelist', assigner_short_name, dated_at, dated_by
    from record_versions
    where assigner_short_name is not null
    union all
    -- The history shows the filer at publication when the CNA that sent the record is the filer of today.
    select r.cve_id, 'assigner', 'cvelist', s.filer, r.received_at, 'nvd_history'
    from received as r
    join {{ ref('int_cve_spine') }} as s using (cve_id)
    where r.received_from = s.filer_nvd_id and s.in_cvelist
)

select cve_id, field, source, value, seen_at, 'set' as op, dated_by, false as pre_history
from (
    select * from kev_obs
    union all
    select * from vr_obs
    union all
    select * from vr_cwe
    union all
    select * from exploit_obs
    union all
    select * from epss_obs
    union all
    select * from record_obs
)
where value is not null and seen_at is not null
