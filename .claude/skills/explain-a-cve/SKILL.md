---
name: explain-a-cve
description: Explain one CVE through the unscheduled API with every field tied to its source and the time it became known. Use when someone asks what is known about a CVE, why it has no NVD analysis, or what was known on a given day.
---

# Explain a CVE

1. Ask the live API, never memory: `GET https://unscheduled-api.vercel.app/v1/cves/{id}` for the
   current record, `.../v1/cves/{id}?as_of=YYYY-MM-DD` for what was known that day, and
   `.../v1/cves/{id}/timeline` for every dated event. Locally the same answers come from
   `uv run unsched cve {id}` and `uv run unsched timeline {id}`.
2. For each field you state (severity, CVSS vector, CWE, NVD status, KEV listing, exploit code,
   EPSS), give its value, its source in words (the filer, the NVD, CISA ADP, CISA KEV, FIRST,
   Metasploit or Nuclei) and since when. If two sources disagree, show both.
3. Say how the date was set: an event in the source's own history, or a named rule (dated_by). Say
   so when a value predates 2017 and rests on a rule.
4. If the NVD has not analyzed it, give the status the NVD gives and the days since publication, as
   the ruler draws it. Do not guess why.
5. End with the statement: it is a portfolio demonstration, not an official score, and not for
   security decisions.

Refuse to give a score the API does not hold. Phase 1 fills nothing in.
