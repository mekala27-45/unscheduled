-- A series (one field of one source, or one value of a set field) never holds two facts at once:
-- every fact ends no later than the next one of its series starts, and only the last is open.
with series as (
    select
        *,
        case when field in ('cwe', 'exploit_code') then value else '' end as series_value,
        lead(known_from) over w as next_from,
        count(*) filter (where known_to is null) over (partition by cve_id, field, source,
            case when field in ('cwe', 'exploit_code') then value else '' end) as open_facts
    from {{ ref('cve_fact') }}
    window w as (
        partition by cve_id, field, source, case when field in ('cwe', 'exploit_code') then value else '' end
        order by known_from, known_to nulls last
    )
)
select cve_id, field, source, value, known_from, known_to, next_from, open_facts
from series
where known_to < known_from
   or (next_from is not null and (known_to is null or known_to > next_from))
   or open_facts > 1
