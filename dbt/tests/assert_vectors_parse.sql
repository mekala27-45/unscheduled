-- Every CVSS vector the facts hold parses by the cvss library: it is the base vector of a check
-- that passed. A vector that did not parse is in quarantine as Q01 instead.
select f.cve_id, f.field, f.source, f.value
from {{ ref('cve_fact') }} as f
where f.field like 'cvss%_vector'
  and not exists (
      select 1 from {{ ref('int_vector_checks') }} as c
      where c.parses and c.base_vector = f.value
  )
