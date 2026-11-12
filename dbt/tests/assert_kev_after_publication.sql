-- Every KEV listing is on or after the day its CVE was published, or it is in quarantine as Q03.
select k.cve_id, k.date_added, s.published_day
from {{ ref('kev_events') }} as k
join {{ ref('int_cve_spine') }} as s using (cve_id)
where k.date_added < s.published_day
  and not exists (
      select 1 from {{ ref('quarantine') }} as q
      where q.rule_id = 'Q03' and q.cve_id = k.cve_id
  )
