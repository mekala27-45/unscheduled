-- Q4, can a filer score stand in for the NVD: every CVE that both its filer and the NVD scored with
-- CVSS 3.1, in the train, development and shadow windows only (never test, never the gap), each base
-- metric from both vectors side by side, and both bands with their ordinals.
with scored as (
    select *
    from {{ ref('cve_current') }}
    where nvd_cvss31_vector is not null
      and filer_cvss31_vector is not null
      and filer <> 'nvd@nist.gov'
      and split_window in ('train', 'development', 'shadow')
      and state <> 'REJECTED'
)

select
    cast(cve_id as varchar) as cve_id,
    cast(filer as varchar) as filer,
    cast(filer_type as varchar) as filer_type,
    cast(split_window as varchar) as split_window,
    cast(published as timestamptz) as published,
    cast(nvd_cvss31_vector as varchar) as nvd_vector,
    cast(filer_cvss31_vector as varchar) as filer_vector,
    {% for m in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] %}
    cast({{ cvss3_metric('nvd_cvss31_vector', m) }} as varchar) as nvd_{{ m | lower }},
    cast({{ cvss3_metric('filer_cvss31_vector', m) }} as varchar) as filer_{{ m | lower }},
    {% endfor %}
    cast(nvd_cvss31_score as double) as nvd_score,
    cast(filer_cvss31_score as double) as filer_score,
    cast(nvd_cvss31_band as varchar) as nvd_band,
    cast(filer_cvss31_band as varchar) as filer_band,
    cast({{ band_rank('nvd_cvss31_band') }} as integer) as nvd_band_rank,
    cast({{ band_rank('filer_cvss31_band') }} as integer) as filer_band_rank
from scored
