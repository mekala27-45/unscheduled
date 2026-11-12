-- Every KEV catalog row bronze has seen, one per CVE and catalog version.
select
    cve_id,
    vendor_project,
    product,
    vulnerability_name,
    date_added,
    due_date,
    known_ransomware,
    coalesce(cwes, []::varchar[]) as cwes,
    catalog_version,
    first_seen_commit
from {{ source('bronze', 'kev') }}
