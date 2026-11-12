-- Every distinct vector text the warehouse has to judge, with the version it claims: the metrics as
-- the sources wrote them, the vectors CISA wrote in Vulnrichment, and the vectors the change history
-- carries. int_vector_checks parses each once with the cvss library.
select distinct version, vector
from (
    select version, vector from {{ ref('stg_cve_metrics') }}
    union all
    select {{ cvss_version('adp_cvss_vector', "'3.1'") }} as version, adp_cvss_vector as vector
    from {{ ref('stg_vulnrichment') }}
    where adp_cvss_vector is not null
    union all
    select version, new_text as vector from {{ ref('int_nvd_details') }}
    where field like 'cvss%' and new_text is not null
    union all
    select version, old_text as vector from {{ ref('int_nvd_details') }}
    where field like 'cvss%' and old_text is not null
)
where version is not null and vector is not null
