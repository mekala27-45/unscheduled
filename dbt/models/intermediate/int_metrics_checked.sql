-- Every metric with what the cvss library made of its vector, the source named as the facts name
-- it, and the quarantine rule it breaks, if any: Q01 the vector does not parse, Q02 the stored score
-- is more than 0.1 from both the score of the vector as written and the score of its base vector,
-- Q05 the CVE is rejected and still carries the metric. The two scores differ only for CVSS 4.0
-- with threat metrics: the FIRST schema's baseScore names the score of the base alone, VulDB stores
-- that one, and most other filers store the score of the whole vector, so either agrees. A Q01 or Q05 metric never becomes a fact. A Q02 metric keeps its vector
-- in the facts, because the facts never carry a stored score: every score there is the cvss
-- library's score of the base vector, so what Q02 sets aside is the stored score itself.
select
    m.cve_id,
    m.raw_source,
    m.source_type,
    {{ fact_source('m.source_type', 'm.raw_source', 's.filer') }} as source,
    m.version,
    m.vector,
    m.base_score as stored_score,
    m.base_severity as stored_severity,
    m.origin,
    m.observed_at,
    c.parses,
    c.base_vector,
    c.base_score as computed_score,
    c.vector_score,
    c.error as parse_error,
    s.state,
    case
        when not coalesce(c.parses, false) then 'Q01'
        when s.state = 'REJECTED' then 'Q05'
        when m.base_score is not null
             and abs(m.base_score - c.vector_score) > 0.1 + 1e-9
             and abs(m.base_score - c.base_score) > 0.1 + 1e-9 then 'Q02'
    end as quarantine_rule
from {{ ref('stg_cve_metrics') }} as m
left join {{ ref('int_vector_checks') }} as c
    on c.version = m.version and c.vector = m.vector
left join {{ ref('int_cve_spine') }} as s
    on s.cve_id = m.cve_id
