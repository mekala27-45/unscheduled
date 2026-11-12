-- Every CVSS metric bronze has seen, from the CVE List (filer and ADP containers) and the NVD API.
select
    cve_id,
    source as raw_source,
    lower(source_type) as source_type,
    {{ cvss_version('vector', 'version') }} as version,
    trim(vector) as vector,
    base_score,
    upper(base_severity) as base_severity,
    origin,
    observed_at
from {{ source('bronze', 'cve_metrics') }}
where vector is not null and trim(vector) <> ''
