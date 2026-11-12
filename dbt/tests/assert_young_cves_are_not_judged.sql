-- A CVE younger than k days at the data cut is not judged at k days, analyzed or not; and a KEV
-- listing whose one business day has not passed is not judged either. Any row here would let the
-- recent months count only their quick analyses.
select cve_id, 'q1 7 days' as flag
from {{ ref('mart_backlog_q1') }}
where published + to_days(7) > {{ data_cut() }} and analyzed_7d is not null
union all
select cve_id, 'q1 30 days'
from {{ ref('mart_backlog_q1') }}
where published + to_days(30) > {{ data_cut() }} and analyzed_30d is not null
union all
select cve_id, 'q1 90 days'
from {{ ref('mart_backlog_q1') }}
where published + to_days(90) > {{ data_cut() }} and analyzed_90d is not null
union all
select cve_id, 'q2 one business day'
from {{ ref('mart_backlog_q2') }}
where business_day_deadline > {{ data_cut() }} and met_one_business_day is not null
