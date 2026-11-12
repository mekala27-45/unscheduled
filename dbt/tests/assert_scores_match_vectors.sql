-- Every stored score outside quarantine is within 0.1 of the score its vector as written gives or
-- of the score of its base vector, the two readings CVSS 4.0 with threat metrics allows.
select cve_id, origin, raw_source, version, vector, stored_score, vector_score, computed_score
from {{ ref('int_metrics_checked') }}
where quarantine_rule is null
  and stored_score is not null
  and abs(stored_score - vector_score) > 0.1 + 1e-9
  and abs(stored_score - computed_score) > 0.1 + 1e-9
