-- A published CVE always has a publication time; only a rejected record may lack one.
select cve_id, state
from {{ ref('cve_current') }}
where state <> 'REJECTED' and published is null
