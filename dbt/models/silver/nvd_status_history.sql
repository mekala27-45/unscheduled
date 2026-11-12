-- The NVD status of every CVE over time: each status, from when, to when, and the rule that dated
-- it. The rows are the nvd_status facts, so the history and the as-of engine always agree.
select
    cast(cve_id as varchar) as cve_id,
    cast(value as varchar) as status,
    cast(known_from as timestamptz) as status_from,
    cast(known_to as timestamptz) as status_to,
    cast(dated_by as varchar) as dated_by,
    cast(pre_history as boolean) as pre_history
from {{ ref('cve_fact') }}
where field = 'nvd_status'
