-- How many rows each rule moved to quarantine, every rule listed even when it caught nothing.
with rules as (
    select * from (values
        ('Q01', 'vector does not parse'),
        ('Q02', 'score disagrees with its vector'),
        ('Q03', 'KEV listing before publication'),
        ('Q04', 'duplicate CVE in one snapshot'),
        ('Q05', 'rejected CVE that still carries metrics'),
        ('Q06', 'advisory range that does not parse in its scheme'),
        ('Q07', 'SBOM component without a package URL'),
        ('Q08', 'change event for an unknown CVE')
    ) as r(rule_id, rule)
)

select r.rule_id, r.rule, count(q.rule_id) as row_count, count(distinct q.cve_id) as cve_count
from rules as r
left join {{ ref('quarantine') }} as q using (rule_id)
group by r.rule_id, r.rule
order by r.rule_id
