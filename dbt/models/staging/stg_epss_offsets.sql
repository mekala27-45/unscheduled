-- EPSS scores kept at the registered offsets after publication, and daily for KEV listed CVEs.
select
    cve_id,
    score_date,
    epss,
    percentile,
    model_version,
    offset_days
from {{ source('bronze', 'epss_offsets') }}
where epss is not null
