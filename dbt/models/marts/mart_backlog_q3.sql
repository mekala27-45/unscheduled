-- Q3, what the filer gives instead: every CVE the NVD has not analyzed, rejected CVEs excluded, in
-- every window, and what its filer and CISA supplied: a filer CVSS 3.x (3.0 or 3.1), a filer CVSS
-- 4.0, a filer CWE (a CWE id, not the NVD placeholders), affected versions, and any CISA ADP value
-- (a CVSS vector, a CWE or an SSVC decision).
select
    cast(cve_id as varchar) as cve_id,
    cast(filer as varchar) as filer,
    cast(filer_type as varchar) as filer_type,
    cast(published as timestamptz) as published,
    cast(split_window as varchar) as split_window,
    cast(nvd_status as varchar) as nvd_status,
    cast(filer_cvss31_vector is not null or filer_cvss30_vector is not null as boolean) as has_filer_cvss3,
    cast(filer_cvss40_vector is not null as boolean) as has_filer_cvss40,
    cast(len(list_filter(filer_cwes, lambda x: x like 'CWE-%')) > 0 as boolean) as has_filer_cwe,
    cast(has_affected_versions as boolean) as has_affected_versions,
    cast(adp_cvss31_vector is not null as boolean) as has_adp_cvss,
    cast(len(list_filter(adp_cwes, lambda x: x like 'CWE-%')) > 0 as boolean) as has_adp_cwe,
    cast(ssvc_exploitation is not null as boolean) as has_adp_ssvc,
    cast(
        adp_cvss31_vector is not null or len(list_filter(adp_cwes, lambda x: x like 'CWE-%')) > 0 or ssvc_exploitation is not null
        as boolean
    ) as has_adp_value
from {{ ref('cve_current') }}
where not nvd_analyzed and state <> 'REJECTED' and published is not null
