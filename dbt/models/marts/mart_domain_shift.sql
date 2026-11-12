-- Q8, how different the skipped CVEs are: every CVE published in the shadow window (from
-- 2026-04-15), rejected CVEs excluded, with the label (the NVD analyzed it) and the registered
-- features: filer, filer type, CWE, published month, which filer vectors are present, and the
-- description for the TF-IDF. half is the registered time split: the earlier half by publication
-- (ties by CVE id) fits the classifier, the later half scores it. Nothing here is random.
with base as (
    select *
    from {{ ref('cve_current') }}
    where split_window = 'shadow' and state <> 'REJECTED'
),
ordered as (
    select
        *,
        row_number() over (order by published, cve_id) as position,
        count(*) over () as total
    from base
)

select
    cast(cve_id as varchar) as cve_id,
    cast(nvd_analyzed as boolean) as nvd_analyzed,
    cast(filer as varchar) as filer,
    cast(filer_type as varchar) as filer_type,
    cast(filer_cwes as varchar[]) as filer_cwes,
    cast(published as timestamptz) as published,
    cast(published_month as date) as published_month,
    cast(filer_cvss31_vector is not null or filer_cvss30_vector is not null as boolean) as has_filer_cvss3,
    cast(filer_cvss40_vector is not null as boolean) as has_filer_cvss40,
    cast(coalesce(description, '') as varchar) as description,
    cast(case when position <= total / 2 then 'fit' else 'score' end as varchar) as half,
    cast(position as bigint) as position
from ordered
