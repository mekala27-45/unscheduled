-- One row per KEV listed CVE: the day CISA added it, and the moment the build can date the listing
-- to. kev-data commits the catalog as CISA updates it, so the first commit that carried the entry,
-- when it falls on the day of dateAdded or within the window after it, gives the listing its hour
-- (kev_commit). Otherwise the listing is dated from the start of dateAdded in UTC (kev_date_added).
with rows as (
    select * from {{ ref('stg_kev') }}
),
per_cve as (
    select
        cve_id,
        min(date_added) as date_added,
        min(due_date) as due_date,
        min(first_seen_commit) as first_seen_commit,
        arg_max(vendor_project, catalog_version) as vendor_project,
        arg_max(product, catalog_version) as product,
        arg_max(vulnerability_name, catalog_version) as vulnerability_name,
        arg_max(known_ransomware, catalog_version) as known_ransomware,
        arg_min(known_ransomware, catalog_version) as first_known_ransomware,
        min(catalog_version) filter (where known_ransomware = 'Known') as first_known_version
    from rows
    group by cve_id
)

select
    p.*,
    case
        when p.first_seen_commit >= cast(p.date_added as timestamptz)
         and p.first_seen_commit < cast(p.date_added as timestamptz) + to_days({{ var('kev_commit_window_days') }})
            then p.first_seen_commit
        else cast(p.date_added as timestamptz)
    end as listed_at,
    case
        when p.first_seen_commit >= cast(p.date_added as timestamptz)
         and p.first_seen_commit < cast(p.date_added as timestamptz) + to_days({{ var('kev_commit_window_days') }})
            then 'kev_commit'
        else 'kev_date_added'
    end as listed_dated_by,
    coalesce(
        cast(try_strptime(p.first_known_version, '%Y.%m.%d') as timestamptz),
        cast(try_strptime(p.first_known_version, '%Y-%m-%d') as timestamptz)
    ) as known_ransomware_at
from per_cve as p
