-- The newest version of each CVE List record.
select *
from {{ ref('int_cve_versions') }}
qualify row_number() over (partition by cve_id order by version_no desc) = 1
