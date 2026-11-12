-- Every row that failed a named rule, with the rule, the relation it came from and its key. Rows
-- here are kept out of the facts and the marts that the rule protects; they are never dropped
-- without a trace. The rules:
--   Q01 a CVSS vector does not parse
--   Q02 a stored score is more than 0.1 from both the vector as written and its base
--   Q03 a KEV listing before the CVE was published (kept out of the KEV timing mart)
--   Q04 a CVE twice in one CVE List snapshot (the copy updated last is kept)
--   Q05 a rejected CVE that still carries metrics
--   Q06 an advisory range version that does not parse in its ecosystem's scheme
--   Q07 an SBOM package component without a package URL (a CycloneDX type that names a package,
--       as packages/match reads the SBOMs; file and operating-system components never carry one
--       and are counted apart in config.sbom_non_package, not quarantined)
--   Q08 a change event for a CVE neither the CVE List nor the NVD has
with q01_metrics as (
    select 'Q01' as rule_id, 'cve_metrics' as relation, cve_id,
           concat_ws('|', cve_id, origin, raw_source, version, vector) as row_key,
           coalesce(parse_error, 'the vector does not parse') as detail
    from {{ ref('int_metrics_checked') }}
    where quarantine_rule = 'Q01'
),
q01_history as (
    select 'Q01', 'nvd_changes', d.cve_id,
           concat_ws('|', d.cve_change_id, cast(d.detail_index as varchar)),
           coalesce(c.error, 'no vector in the change detail: ' || left(coalesce(d.new_raw, d.old_raw, ''), 120))
    from {{ ref('int_nvd_details') }} as d
    left join {{ ref('int_vector_checks') }} as c
        on c.version = d.version and c.vector = coalesce(d.new_text, d.old_text)
    where d.field like 'cvss%'
      and coalesce(d.new_raw, d.old_raw, '') <> ''
      and (coalesce(d.new_text, d.old_text) is null or not coalesce(c.parses, false))
),
q01_vulnrichment as (
    select 'Q01', 'vulnrichment', v.cve_id,
           concat_ws('|', v.cve_id, cast(v.last_modified as varchar)),
           coalesce(c.error, 'the vector does not parse')
    from {{ ref('stg_vulnrichment') }} as v
    left join {{ ref('int_vector_checks') }} as c
        on c.vector = v.adp_cvss_vector and c.version = {{ cvss_version('v.adp_cvss_vector', "'3.1'") }}
    where v.adp_cvss_vector is not null and not coalesce(c.parses, false)
),
q02 as (
    select 'Q02', 'cve_metrics', cve_id,
           concat_ws('|', cve_id, origin, raw_source, version, vector),
           'stored ' || cast(stored_score as varchar) || ', the vector as written gives ' || cast(vector_score as varchar)
               || ', its base ' || cast(computed_score as varchar)
    from {{ ref('int_metrics_checked') }}
    where quarantine_rule = 'Q02'
),
q03 as (
    select 'Q03', 'kev', k.cve_id,
           concat_ws('|', k.cve_id, cast(k.date_added as varchar)),
           'listed ' || cast(k.date_added as varchar) || ', published ' || cast(s.published_day as varchar)
    from {{ ref('int_kev_listing') }} as k
    join {{ ref('int_cve_spine') }} as s using (cve_id)
    where k.date_added < s.published_day
),
q04 as (
    select 'Q04', 'cve_records', r.cve_id,
           concat_ws('|', r.cve_id, r.record_digest),
           'another copy in the snapshot of ' || cast(r.snapshot_at as varchar)
    from {{ ref('stg_cve_records') }} as r
    anti join {{ ref('int_cve_versions') }} as v
        on v.cve_id = r.cve_id and v.record_digest = r.record_digest
),
q05 as (
    select 'Q05', 'cve_metrics', cve_id,
           concat_ws('|', cve_id, origin, raw_source, version, vector),
           'the CVE is rejected'
    from {{ ref('int_metrics_checked') }}
    where quarantine_rule = 'Q05'
),
q06 as (
    select 'Q06', e.database || '_advisories', null::varchar,
           concat_ws('|', e.advisory_id, cast(e.modified as varchar), e.ecosystem, e.package, e.range_type, e.event, e.version),
           c.reason
    from {{ ref('int_advisory_range_events') }} as e
    join {{ ref('int_range_version_checks') }} as c
      on c.base_ecosystem is not distinct from e.base_ecosystem
     and c.range_type = e.range_type
     and c.version = e.version
    where c.status = 'bad'
),
q07 as (
    select 'Q07', 'sbom_components', null::varchar,
           concat_ws('|', sbom, bom_ref, type, name, version),
           'a ' || type || ' package with no package URL'
    from {{ source('config', 'sbom_components') }}
    where package and (purl is null or purl = '')
),
q08 as (
    select 'Q08', 'nvd_changes', c.cve_id, c.cve_change_id, 'event ' || coalesce(c.event_name, '') || ' for a CVE neither source has'
    from {{ ref('stg_nvd_changes') }} as c
    anti join {{ ref('int_cve_spine') }} as s on s.cve_id = c.cve_id
)

select
    rule_id,
    case rule_id
        when 'Q01' then 'vector does not parse'
        when 'Q02' then 'score disagrees with its vector'
        when 'Q03' then 'KEV listing before publication'
        when 'Q04' then 'duplicate CVE in one snapshot'
        when 'Q05' then 'rejected CVE that still carries metrics'
        when 'Q06' then 'advisory range that does not parse in its scheme'
        when 'Q07' then 'SBOM component without a package URL'
        when 'Q08' then 'change event for an unknown CVE'
    end as rule,
    relation,
    cve_id,
    row_key,
    detail
from (
    select * from q01_metrics
    union all select * from q01_history
    union all select * from q01_vulnrichment
    union all select * from q02
    union all select * from q03
    union all select * from q04
    union all select * from q05
    union all select * from q06
    union all select * from q07
    union all select * from q08
)
