-- One row per KEV listing: the CVE, the day CISA added it, the moment the build dates the listing
-- to and by which rule, the due date, and the ransomware use as the catalog states it now.
select
    cve_id,
    date_added,
    listed_at,
    listed_dated_by,
    due_date,
    vendor_project,
    product,
    vulnerability_name,
    known_ransomware,
    first_seen_commit
from {{ ref('int_kev_listing') }}
