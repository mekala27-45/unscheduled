{#- How a source is named in the facts: the filer by its CNA short name, the NVD by its address,
    CISA by its ADP name. Every model that writes a source goes through this one macro. -#}
{% macro fact_source(source_type, raw_source, filer) -%}
case
  when {{ source_type }} = 'nvd' then 'nvd@nist.gov'
  when {{ source_type }} = 'adp' then 'CISA-ADP'
  when {{ source_type }} = 'cna' then coalesce({{ filer }}, {{ raw_source }})
  else coalesce({{ raw_source }}, 'unknown')
end
{%- endmacro %}

{# The CISA ADP organization id as the NVD and the CVE List credit it. #}
{% macro cisa_adp_id() -%}'134c704f-9b21-4f2e-91b3-4a467353bcc0'{%- endmacro %}

{# The data cut as a time. #}
{% macro data_cut() -%}cast('{{ var("data_cut") }}' as timestamptz){%- endmacro %}

{# The window of config/splits.yaml a publication day falls in. #}
{% macro split_window(day) -%}
coalesce((select w.window_name from {{ source('config', 'splits') }} as w
          where {{ day }} >= w.start_day and (w.end_day is null or {{ day }} <= w.end_day)
          order by w.start_day limit 1), 'outside')
{%- endmacro %}
