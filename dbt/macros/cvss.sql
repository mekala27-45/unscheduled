{#- CVSS helpers used across the models. Scores and their validity come from the cvss library in
    int_vector_checks; these macros only cut and band what that model already checked. -#}

{# The qualitative band of a CVSS 3.x or 4.0 base score, as the specifications define it. #}
{% macro cvss_band(score) -%}
case
  when {{ score }} is null then null
  when {{ score }} = 0 then 'None'
  when {{ score }} < 4.0 then 'Low'
  when {{ score }} < 7.0 then 'Medium'
  when {{ score }} < 9.0 then 'High'
  else 'Critical'
end
{%- endmacro %}

{# The NVD bands for CVSS 2.0, which has no None and no Critical. #}
{% macro cvss2_band(score) -%}
case
  when {{ score }} is null then null
  when {{ score }} < 4.0 then 'Low'
  when {{ score }} < 7.0 then 'Medium'
  else 'High'
end
{%- endmacro %}

{# The ordinal of a band, for the quadratic weighted kappa and the direction of disagreement. #}
{% macro band_rank(band) -%}
case {{ band }} when 'None' then 0 when 'Low' then 1 when 'Medium' then 2 when 'High' then 3 when 'Critical' then 4 end
{%- endmacro %}

{# One base metric of a CVSS 3.x vector, for example cvss3_metric('v', 'AV') gives N, A, L or P. #}
{% macro cvss3_metric(vector, metric) -%}
regexp_extract({{ vector }}, '(?:^|/){{ metric }}:([A-Z])', 1)
{%- endmacro %}

{# The base part of a CVSS vector in the canonical form the facts store. version is 2.0, 3.0, 3.1 or 4.0. #}
{% macro cvss_base_vector(raw, version) -%}
case
  when {{ version }} = '2.0' then nullif(regexp_extract({{ raw }}, 'AV:[LAN]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]'), '')
  when {{ version }} in ('3.0', '3.1') then 'CVSS:' || {{ version }} || '/' || nullif(regexp_extract({{ raw }}, 'AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]'), '')
  when {{ version }} = '4.0' then 'CVSS:4.0/' || nullif(regexp_extract({{ raw }}, 'AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]/SC:[HLN]/SI:[HLN]/SA:[HLN]'), '')
end
{%- endmacro %}

{# The version a vector declares in its prefix, else the version its row gives. #}
{% macro cvss_version(raw, fallback) -%}
coalesce(nullif(regexp_extract({{ raw }}, 'CVSS:([0-9]\.[0-9])/', 1), ''), {{ fallback }})
{%- endmacro %}

{# The fact field of a CVSS vector of a version: cvss2_vector, cvss30_vector, cvss31_vector, cvss40_vector. #}
{% macro cvss_field(version) -%}
(case {{ version }} when '2.0' then 'cvss2' when '3.0' then 'cvss30' when '3.1' then 'cvss31' when '4.0' then 'cvss40' end || '_vector')
{%- endmacro %}
