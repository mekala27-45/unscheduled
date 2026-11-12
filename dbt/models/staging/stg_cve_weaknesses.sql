-- Every CWE bronze has seen for a CVE, by who supplied it and where it was read.
select
    cve_id,
    source as raw_source,
    upper(trim(cwe_id)) as cwe_id,
    origin,
    observed_at
from {{ source('bronze', 'cve_weaknesses') }}
where cwe_id is not null and trim(cwe_id) <> ''
