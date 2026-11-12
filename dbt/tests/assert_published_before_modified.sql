-- The NVD never modified a record before it published it.
select cve_id, published, last_modified
from {{ ref('stg_nvd_cves') }}
where last_modified < published
