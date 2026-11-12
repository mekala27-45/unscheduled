-- Every NVD change history event, keyed by its change id.
select
    cve_id,
    event_name,
    cve_change_id,
    source_identifier,
    created,
    details_json
from {{ source('bronze', 'nvd_changes') }}
