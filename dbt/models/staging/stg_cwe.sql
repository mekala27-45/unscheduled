-- The MITRE CWE catalog.
select cwe_id, name, abstraction, coalesce(parents, []::varchar[]) as parents
from {{ source('bronze', 'cwe') }}
