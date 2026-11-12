-- Every OSV and GitHub advisory with the time each version of it was known, so the matcher can
-- match as of a date. A version is known from its modified time, and for a GitHub advisory never
-- before the first commit that carried it; it is current until the next version became known.
with osv as (
    select
        'osv' as database,
        advisory_id,
        ecosystem,
        aliases,
        published,
        modified,
        withdrawn,
        source_db,
        affected_json,
        coalesce(modified, published) as known_from
    from {{ ref('stg_osv_advisories') }}
),
ghsa as (
    select
        'ghsa' as database,
        advisory_id,
        null::varchar as ecosystem,
        cve_ids as aliases,
        published,
        modified,
        withdrawn,
        'GHSA' as source_db,
        affected_json,
        case
            when first_seen_commit is not null and first_seen_commit > coalesce(modified, published)
                then first_seen_commit
            else coalesce(modified, published)
        end as known_from
    from {{ ref('stg_ghsa') }}
),
unioned as (
    select * from osv
    union all
    select * from ghsa
)

select
    database,
    advisory_id,
    ecosystem,
    aliases,
    list_filter(aliases, lambda x: x like 'CVE-%') as cve_ids,
    published,
    modified,
    withdrawn,
    source_db,
    affected_json,
    known_from,
    lead(known_from) over (partition by database, advisory_id, ecosystem order by known_from, modified) as known_to
from unioned
where known_from is not null
