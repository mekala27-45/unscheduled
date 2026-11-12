{#-
  The as-of engine in SQL. The state of a CVE at a time t is every fact known at or before t that
  had not ended by t: known_from <= t and (known_to is null or known_to > t). A fact whose
  known_from is after t can never appear, whatever else is true of it.

  packages/lake/src/unscheduled_lake/engine.py holds the same query for Python, and
  tests/lake/test_asof_parity.py requires the two to return identical frames on the same facts.

  t        a SQL expression that evaluates to a time, for example timestamptz '2026-04-15 00:00:00+00'
  cve_ids  a list of CVE ids, or none for every CVE (the frame at t)
  facts    the fact relation, cve_fact unless a test passes another
-#}
{% macro asof(t, cve_ids=none, facts=none) -%}
{%- set rel = facts if facts is not none else ref('cve_fact') -%}
select f.cve_id, f.field, f.source, f.value, f.known_from, f.known_to, f.dated_by
from {{ rel }} as f
where f.known_from <= cast({{ t }} as timestamptz)
  and (f.known_to is null or f.known_to > cast({{ t }} as timestamptz))
{%- if cve_ids is not none %}
  and f.cve_id in ({% for c in cve_ids %}'{{ c | replace("'", "''") }}'{% if not loop.last %}, {% endif %}{% endfor %})
{%- endif %}
{%- endmacro %}

{#-
  The as-of join: for every row of `left`, the facts of its CVE that were current at the time in
  its column `at_column`. The same predicate as asof(), with t taken per row.
-#}
{% macro asof_join(left, at_column, fields=none, facts=none) -%}
{%- set rel = facts if facts is not none else ref('cve_fact') -%}
select l.*, f.field, f.source, f.value, f.known_from, f.dated_by
from {{ left }} as l
join {{ rel }} as f
  on f.cve_id = l.cve_id
 and f.known_from <= l.{{ at_column }}
 and (f.known_to is null or f.known_to > l.{{ at_column }})
{%- if fields is not none %}
 and f.field in ({% for x in fields %}'{{ x }}'{% if not loop.last %}, {% endif %}{% endfor %})
{%- endif %}
{%- endmacro %}
