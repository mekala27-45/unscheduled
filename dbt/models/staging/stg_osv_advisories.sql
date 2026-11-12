-- OSV advisories per ecosystem, one row per version of an advisory (its modified time).
select
    id as advisory_id,
    ecosystem,
    coalesce(aliases, []::varchar[]) as aliases,
    published,
    modified,
    withdrawn,
    summary,
    severity_json,
    affected_json,
    source_db
from {{ source('bronze', 'osv_advisories') }}
