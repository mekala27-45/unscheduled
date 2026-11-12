-- Every version an advisory range names, one row per event, for quarantine rule Q06: the advisory
-- version, the package and its ecosystem, the range type, which event (introduced, fixed,
-- last_affected, limit) and the version string. A version of 0 means from the beginning.
with affected as (
    select
        a.database,
        a.advisory_id,
        a.modified,
        a.ecosystem as ecosystem_hint,
        unnest(
            from_json(
                a.affected_json,
                '[{"package":{"ecosystem":"VARCHAR","name":"VARCHAR"},"ranges":[{"type":"VARCHAR","events":[{"introduced":"VARCHAR","fixed":"VARCHAR","last_affected":"VARCHAR","limit":"VARCHAR"}]}]}]'
            )
        ) as item
    from {{ ref('advisory_versions') }} as a
    where a.affected_json is not null and a.affected_json like '[%'
),
ranges as (
    select
        database,
        advisory_id,
        modified,
        coalesce(item.package.ecosystem, ecosystem_hint) as ecosystem,
        item.package.name as package,
        unnest(item.ranges) as rng
    from affected
),
events as (
    select
        database,
        advisory_id,
        modified,
        ecosystem,
        split_part(ecosystem, ':', 1) as base_ecosystem,
        package,
        upper(rng.type) as range_type,
        unnest(rng.events) as ev
    from ranges
)

select database, advisory_id, modified, ecosystem, base_ecosystem, package, range_type, 'introduced' as event, ev.introduced as version
from events where ev.introduced is not null
union all
select database, advisory_id, modified, ecosystem, base_ecosystem, package, range_type, 'fixed', ev.fixed
from events where ev.fixed is not null
union all
select database, advisory_id, modified, ecosystem, base_ecosystem, package, range_type, 'last_affected', ev.last_affected
from events where ev.last_affected is not null
union all
select database, advisory_id, modified, ecosystem, base_ecosystem, package, range_type, 'limit', ev.limit
from events where ev.limit is not null
