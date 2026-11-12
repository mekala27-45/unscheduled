{#- Schemas are named as the layers are (staging, intermediate, silver, quarantine, gold), not
    prefixed with the target schema, so the lake file reads the same from every tool. -#}
{% macro generate_schema_name(custom_schema_name, node) -%}
    {%- if custom_schema_name is none -%}{{ target.schema }}{%- else -%}{{ custom_schema_name | trim }}{%- endif -%}
{%- endmacro %}
