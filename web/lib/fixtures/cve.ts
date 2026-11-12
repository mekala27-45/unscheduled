/**
 * FIXTURE. Invented values in the shape of the API, for the unit tests, the Playwright mocks and the
 * /design specimen. CVE-2099-0001 does not exist, the filer is example.com, and data_version says
 * "fixture" so every page that shows this record says so. Nothing here is data.
 */
import type { Cve, CveSummary, Timeline } from "../api/client";
import { STATEMENT } from "../statement";

export const FIXTURE_ID = "CVE-2099-0001";
export const FIXTURE_NOTE = "Fixture: invented values in the API's shape. CVE-2099-0001 is not a real CVE.";

export const TIMELINE_FIXTURE: Timeline = {
  data_version: "fixture",
  statement: STATEMENT,
  id: FIXTURE_ID,
  now: "2026-11-07T12:00:00Z",
  events: [
    { at: "2026-03-02T14:05:00Z", kind: "published", source: "example.com", value: null, analyzed: null },
    { at: "2026-03-02T14:05:00Z", kind: "filer_score", source: "example.com", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", analyzed: null },
    { at: "2026-03-02T16:40:00Z", kind: "nvd_status", source: "nvd@nist.gov", value: "Received", analyzed: false },
    { at: "2026-03-05T09:12:00Z", kind: "ghsa_advisory", source: "GitHub Advisory Database", value: "GHSA-xxxx-xxxx-xxxx", analyzed: null },
    { at: "2026-03-11T08:30:00Z", kind: "cisa_adp", source: "CISA-ADP", value: "SSVC exploitation: poc", analyzed: null },
    { at: "2026-03-24T00:00:00Z", kind: "nvd_status", source: "nvd@nist.gov", value: "Awaiting Analysis", analyzed: false },
    { at: "2026-05-19T21:47:00Z", kind: "exploit_code", source: "nuclei-templates", value: "first template commit", analyzed: null },
    { at: "2026-06-30T00:00:00Z", kind: "kev_listed", source: "CISA KEV", value: null, analyzed: null },
  ],
};

export const CVE_FIXTURE: Cve = {
  data_version: "fixture",
  statement: STATEMENT,
  id: FIXTURE_ID,
  state: "PUBLISHED",
  as_of: null,
  published: "2026-03-02T14:05:00Z",
  last_modified: "2026-06-30T00:00:00Z",
  filer: "example.com",
  filer_type: "vendor",
  nvd_status: "Awaiting Analysis",
  nvd_status_since: "2026-03-24T00:00:00Z",
  description: "Fixture text standing in for a CNA description: an example service accepts a crafted request and runs it.",
  cve_org_url: "https://www.cve.org/CVERecord?id=CVE-2099-0001",
  kev: { listed: true, date_added: "2026-06-30", due_date: "2026-07-21", ransomware: "Unknown" },
  fields: [
    { field: "cvss31_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", source: "example.com (filer)", known_from: "2026-03-02T14:05:00Z", dated_by: "event" },
    { field: "severity", value: "critical", source: "example.com (filer)", known_from: "2026-03-02T14:05:00Z", dated_by: "event" },
    { field: "cwe", value: "CWE-94", source: "example.com (filer)", known_from: "2026-03-02T14:05:00Z", dated_by: "publication" },
    { field: "nvd_status", value: "Awaiting Analysis", source: "nvd@nist.gov", known_from: "2026-03-24T00:00:00Z", dated_by: "event" },
    { field: "ssvc_exploitation", value: "poc", source: "CISA-ADP", known_from: "2026-03-11T08:30:00Z", dated_by: "event" },
    { field: "kev_listed", value: true, source: "CISA KEV", known_from: "2026-06-30T00:00:00Z", dated_by: "event" },
  ],
  affected: [
    { ecosystem: "npm", name: "example-server", purl: "pkg:npm/example-server", ranges: [">=2.0.0, <2.4.1"], fixed: ["2.4.1"], source: "GitHub Advisory Database" },
  ],
  epss: [
    { offset_days: 0, score: 0.004, percentile: 0.41, score_date: "2026-03-02", model_version: "fixture" },
    { offset_days: 1, score: 0.006, percentile: 0.52, score_date: "2026-03-03", model_version: "fixture" },
    { offset_days: 7, score: 0.011, percentile: 0.66, score_date: "2026-03-09", model_version: "fixture" },
    { offset_days: 30, score: 0.052, percentile: 0.88, score_date: "2026-04-01", model_version: "fixture" },
    { offset_days: 90, score: null, percentile: null, score_date: null, model_version: null },
  ],
  references: [{ url: "https://example.com/advisories/0001", source: "example.com", tags: ["vendor-advisory"] }],
};

export const SUMMARY_FIXTURE: CveSummary[] = [
  { id: "CVE-2099-0001", published: "2026-03-02T14:05:00Z", last_modified: "2026-06-30T00:00:00Z", nvd_status: "Awaiting Analysis", kev_listed: true, kev_date_added: "2026-06-30", filer: "example.com", filer_type: "vendor", cwe: ["CWE-94"], filer_cvss: 9.8, filer_severity: "critical" },
  { id: "CVE-2099-0002", published: "2026-04-21T10:00:00Z", last_modified: "2026-04-22T10:00:00Z", nvd_status: "Received", kev_listed: false, kev_date_added: null, filer: "example.org", filer_type: "open_source", cwe: ["CWE-79"], filer_cvss: 6.1, filer_severity: "medium" },
  { id: "CVE-2099-0003", published: "2026-05-08T08:00:00Z", last_modified: "2026-05-30T08:00:00Z", nvd_status: "Analyzed", kev_listed: false, kev_date_added: null, filer: "example.net", filer_type: "research", cwe: ["CWE-22"], filer_cvss: 7.5, filer_severity: "high" },
  { id: "CVE-2099-0004", published: "2026-06-14T12:30:00Z", last_modified: "2026-06-14T12:30:00Z", nvd_status: null, kev_listed: false, kev_date_added: null, filer: "example.com", filer_type: "vendor", cwe: [], filer_cvss: null, filer_severity: null },
];
