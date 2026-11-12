-- Every advisory range version parses in its ecosystem's scheme, or it is in quarantine as Q06.
with bad as (
    select count(*) as n
    from {{ ref('int_advisory_range_events') }} as e
    join {{ ref('int_range_version_checks') }} as c
      on c.base_ecosystem is not distinct from e.base_ecosystem
     and c.range_type = e.range_type
     and c.version = e.version
    where c.status = 'bad'
),
quarantined as (
    select count(*) as n from {{ ref('quarantine') }} where rule_id = 'Q06'
)
select b.n as bad, q.n as quarantined
from bad as b, quarantined as q
where b.n <> q.n
