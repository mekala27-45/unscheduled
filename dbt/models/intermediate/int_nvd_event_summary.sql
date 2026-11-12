-- What the change history shows for each CVE: how many events, when it was received, when the NVD
-- first analyzed it. The first analysis is the first Initial Analysis, Reanalysis or Modified
-- Analysis event, the NVD's own record of having analyzed the CVE.
select
    cve_id,
    count(*) as n_events,
    min(created) as first_event_at,
    max(created) as last_event_at,
    min(created) filter (where event_name = 'New CVE Received') as received_at,
    min(created) filter (where event_name in ('Initial Analysis', 'Reanalysis', 'Modified Analysis')) as first_analysis_at,
    min(created) filter (where event_name = 'CVE Rejected') as rejected_at
from {{ ref('stg_nvd_changes') }}
group by cve_id
