-- CISA Vulnrichment: SSVC decision points, CVSS and CWE added by CISA, one row per file version.
select
    cve_id,
    lower(ssvc_exploitation) as ssvc_exploitation,
    lower(ssvc_automatable) as ssvc_automatable,
    lower(ssvc_technical_impact) as ssvc_technical_impact,
    nullif(trim(adp_cvss_vector), '') as adp_cvss_vector,
    coalesce(adp_cwes, []::varchar[]) as adp_cwes,
    first_added,
    last_modified
from {{ source('bronze', 'vulnrichment') }}
