{{ config(materialized='view') }}
-- Observations from the NVD change history, each dated by the event that carried it (nvd_history).
-- A CVSS vector added or changed is set from the event; one removed is unset. A CWE is a set of
-- values, so a change unsets the old value and sets the new one. The score and the band of a vector
-- follow it, computed by the cvss library from the base vector. A CPE configuration added or changed
-- sets cpe_config; a removal unsets it only when the CVE has no configuration today.
with details as (
    select * from {{ ref('int_nvd_details') }}
),
checks as (
    select * from {{ ref('int_vector_checks') }} where parses
),
vector_rows as (
    select d.cve_id, d.field, d.source, d.version, d.created, d.detail_index, d.cve_change_id,
           'set' as op, c.base_vector, c.base_score
    from details as d
    join checks as c on c.version = d.version and c.vector = d.new_text
    where d.field like 'cvss%' and d.action in ('Added', 'Changed')
    union all
    select d.cve_id, d.field, d.source, d.version, d.created, d.detail_index, d.cve_change_id,
           'unset' as op, c.base_vector, c.base_score
    from details as d
    join checks as c on c.version = d.version and c.vector = d.old_text
    where d.field like 'cvss%' and d.action = 'Removed'
),
cvss as (
    select cve_id, field, source, base_vector as value, created as seen_at, op from vector_rows
    union all
    select cve_id, replace(field, '_vector', '_score'), source, printf('%.1f', base_score), created, op
    from vector_rows
    union all
    select cve_id, replace(field, '_vector', '_severity'), source,
           case when version = '2.0' then {{ cvss2_band('base_score') }} else {{ cvss_band('base_score') }} end,
           created, op
    from vector_rows
),
cwe as (
    select cve_id, 'cwe' as field, source, new_text as value, created as seen_at, 'set' as op
    from details
    where field = 'cwe' and action in ('Added', 'Changed') and new_text is not null
    union all
    select cve_id, 'cwe', source, old_text, created, 'unset'
    from details
    where field = 'cwe' and action in ('Removed', 'Changed') and old_text is not null
),
cpe_events as (
    select
        d.cve_id,
        d.created,
        d.action,
        max(d.created) over (partition by d.cve_id) as last_cpe_at,
        coalesce(s.has_cpe, false) as has_cpe_now
    from details as d
    left join {{ ref('int_cve_spine') }} as s using (cve_id)
    where d.field = 'cpe_config'
),
cpe as (
    select distinct cve_id, 'cpe_config' as field, 'nvd@nist.gov' as source, 'present' as value, created as seen_at, 'set' as op
    from cpe_events
    where action in ('Added', 'Changed')
    union all
    select distinct cve_id, 'cpe_config', 'nvd@nist.gov', 'present', created, 'unset'
    from cpe_events
    where action = 'Removed' and created = last_cpe_at and not has_cpe_now
)

select cve_id, field, source, value, seen_at, op, 'nvd_history' as dated_by, false as pre_history
from (
    select * from cvss
    union all
    select * from cwe
    union all
    select * from cpe
)
where value is not null
