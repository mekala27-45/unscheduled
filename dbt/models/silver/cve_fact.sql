-- silver.cve_fact: every value anyone published about a CVE, with the time it became known and the
-- time it stopped being current. Observations (int_observations) are cut into facts per series: a
-- series is one field of one source, or for a field that holds a set (cwe, exploit_code) one value
-- of it. In time order, a set of a new value starts a fact and ends the one before; an unset ends
-- the current fact; a set of the value already current only confirms it. known_from is the first
-- observation of a fact, so a fact never starts later than the earliest time a source vouched for
-- it, and known_to is when the next fact of its series became known, so at any time a series holds
-- at most one fact. dated_by names the rule that dated known_from; pre_history marks a fact dated
-- from publication because it predates the NVD change history.
with keyed as (
    select
        cve_id,
        field,
        source,
        value,
        seen_at,
        op,
        dated_by,
        pre_history,
        case when multi then value else '' end as series_value
    from {{ ref('int_observations') }}
),
ordered as (
    select
        *,
        row_number() over (
            partition by cve_id, field, source, series_value
            order by seen_at, case op when 'unset' then 0 else 1 end, value, dated_by
        ) as seq
    from keyed
),
lagged as (
    select
        *,
        lag(op) over w as prev_op,
        lag(value) over w as prev_value
    from ordered
    window w as (partition by cve_id, field, source, series_value order by seq)
),
marked as (
    select
        *,
        case
            when prev_op is null then 1
            when op <> prev_op then 1
            when op = 'set' and value is distinct from prev_value then 1
            else 0
        end as starts
    from lagged
),
grouped as (
    select
        *,
        sum(starts) over (
            partition by cve_id, field, source, series_value order by seq
            rows between unbounded preceding and current row
        ) as segment
    from marked
),
segments as (
    select
        cve_id,
        field,
        source,
        series_value,
        segment,
        min(op) as op,
        arg_min(value, seq) as value,
        min(seen_at) as known_from,
        arg_min(dated_by, seq) as dated_by,
        arg_min(pre_history, seq) as pre_history
    from grouped
    group by cve_id, field, source, series_value, segment
),
bounded as (
    select
        *,
        lead(known_from) over (partition by cve_id, field, source, series_value order by segment) as known_to
    from segments
)

select
    cve_id,
    field,
    source,
    value,
    known_from,
    known_to,
    dated_by,
    pre_history
from bounded
where op = 'set'
