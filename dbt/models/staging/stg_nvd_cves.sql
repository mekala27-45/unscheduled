-- The NVD record of each CVE, one row per state bronze has seen (status and last modified time).
select
    cve_id,
    vuln_status,
    published,
    last_modified,
    source_identifier,
    coalesce(has_cpe, false) as has_cpe,
    coalesce(cpe_count, 0) as cpe_count,
    cisa_exploit_add,
    fetched_at
from {{ source('bronze', 'nvd_cves') }}
