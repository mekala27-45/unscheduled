-- The newest NVD record of each CVE, with the first time the build saw any NVD record of it.
select
    *,
    min(fetched_at) over (partition by cve_id) as first_fetched_at
from {{ ref('stg_nvd_cves') }}
qualify row_number() over (partition by cve_id order by fetched_at desc, last_modified desc nulls last, vuln_status) = 1
