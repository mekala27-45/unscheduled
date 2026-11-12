-- The change history unnested to one row per detail, for the details the facts are made of: CVSS
-- vectors of every version, CWEs and CPE configurations. Each detail is attributed to a source: the
-- NVD when it labels the value NIST, CISA when the change came from its ADP, and otherwise the
-- source that made the change, named as the facts name it (the filer by its CNA short name).
with events as (
    select
        c.cve_id,
        c.event_name,
        c.cve_change_id,
        c.source_identifier,
        c.created,
        from_json(
            c.details_json,
            '[{"action":"VARCHAR","newValue":"VARCHAR","oldValue":"VARCHAR","type":"VARCHAR"}]'
        ) as details
    from {{ ref('stg_nvd_changes') }} as c
    where c.details_json is not null and c.details_json <> '[]'
),
flat as (
    select
        cve_id,
        event_name,
        cve_change_id,
        source_identifier,
        created,
        unnest(range(len(details))) as detail_index,
        unnest(details) as d
    from events
),
typed as (
    select
        cve_id,
        event_name,
        cve_change_id,
        source_identifier,
        created,
        detail_index,
        d['action'] as action,
        d['type'] as detail_type,
        d['oldValue'] as old_value,
        d['newValue'] as new_value,
        case
            when d['type'] = 'CVSS V2' then 'cvss'
            when d['type'] in ('CVSS V3', 'CVSS V3.0', 'CVSS V3.1', 'CVSS V4', 'CVSS V4.0') then 'cvss'
            when d['type'] = 'CWE' then 'cwe'
            when d['type'] = 'CPE Configuration' then 'cpe_config'
        end as field
    from flat
),
parsed as (
    select
        t.*,
        case
            when t.field <> 'cvss' then null
            when t.detail_type = 'CVSS V2' then '2.0'
            else coalesce(
                nullif(regexp_extract(coalesce(t.new_value, t.old_value, ''), 'CVSS:([0-9]\.[0-9])/', 1), ''),
                case t.detail_type when 'CVSS V3.1' then '3.1' when 'CVSS V4' then '4.0' when 'CVSS V4.0' then '4.0' else '3.0' end
            )
        end as version,
        case
            when t.field = 'cvss' then nullif(regexp_extract(t.new_value, '((?:CVSS:[0-9]\.[0-9]/)?AV:[^\s()]+)', 1), '')
            when t.field = 'cwe' then nullif(regexp_extract(t.new_value, '(CWE-[0-9]+|NVD-CWE-Other|NVD-CWE-noinfo)', 1), '')
            when t.field = 'cpe_config' then case when t.new_value is not null and t.new_value <> '' then 'present' end
        end as new_text,
        case
            when t.field = 'cvss' then nullif(regexp_extract(t.old_value, '((?:CVSS:[0-9]\.[0-9]/)?AV:[^\s()]+)', 1), '')
            when t.field = 'cwe' then nullif(regexp_extract(t.old_value, '(CWE-[0-9]+|NVD-CWE-Other|NVD-CWE-noinfo)', 1), '')
            when t.field = 'cpe_config' then case when t.old_value is not null and t.old_value <> '' then 'present' end
        end as old_text,
        trim(regexp_extract(coalesce(t.new_value, t.old_value, ''), '^(.*?)\s*\(?\s*(?:CVSS:[0-9]\.[0-9]/)?(?:AV:|CWE-|NVD-CWE-)', 1)) as value_label
    from typed as t
    where t.field is not null
)

select
    p.cve_id,
    p.cve_change_id,
    p.event_name,
    p.source_identifier as event_source,
    p.created,
    p.detail_index,
    p.action,
    p.detail_type,
    case when p.field = 'cvss' then {{ cvss_field('p.version') }} else p.field end as field,
    p.version,
    p.value_label,
    case
        when p.field = 'cpe_config' then 'nvd@nist.gov'
        when upper(p.value_label) like 'NIST%' then 'nvd@nist.gov'
        when p.value_label = '' and p.source_identifier = 'nvd@nist.gov' then 'nvd@nist.gov'
        when p.source_identifier = {{ cisa_adp_id() }} or upper(p.value_label) like 'CISA%ADP%' then 'CISA-ADP'
        when p.source_identifier = s.filer_nvd_id then s.filer
        else coalesce(p.source_identifier, 'unknown')
    end as source,
    p.new_text,
    p.old_text,
    p.new_value as new_raw,
    p.old_value as old_raw
from parsed as p
left join {{ ref('int_cve_spine') }} as s using (cve_id)
