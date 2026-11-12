-- Every observation the facts are made of, from every source, in one shape: a value of a field
-- from a source, set or unset at a time, with the rule that dated it.
select
    cve_id,
    field,
    source,
    value,
    seen_at,
    op,
    dated_by,
    pre_history,
    field in ('cwe', 'exploit_code') as multi
from (
    select * from {{ ref('int_obs_history') }}
    union all
    select * from {{ ref('int_obs_status') }}
    union all
    select * from {{ ref('int_obs_current') }}
    union all
    select * from {{ ref('int_obs_other') }}
)
where cve_id in (select cve_id from {{ ref('int_cve_spine') }})
