-- One row per version of a CVE List record, as bronze keeps them: a version is new when its digest is.
select
    cve_id,
    upper(state) as state,
    assigner_org_id,
    assigner_short_name,
    date_reserved,
    date_published,
    date_updated,
    description,
    coalesce(problem_cwes, []::varchar[]) as problem_cwes,
    affected_json,
    coalesce(has_affected_versions, false) as has_affected_versions,
    references_count,
    coalesce(adp_cisa_present, false) as adp_cisa_present,
    snapshot_at,
    record_digest
from {{ source('bronze', 'cve_records') }}
