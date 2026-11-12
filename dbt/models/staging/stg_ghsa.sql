-- Reviewed GitHub advisories, one row per version (its modified time). CC BY 4.0, attributed on every page.
select
    ghsa_id as advisory_id,
    coalesce(cve_ids, []::varchar[]) as cve_ids,
    published,
    modified,
    withdrawn,
    severity,
    coalesce(cwe_ids, []::varchar[]) as cwe_ids,
    affected_json,
    first_seen_commit
from {{ source('bronze', 'ghsa') }}
