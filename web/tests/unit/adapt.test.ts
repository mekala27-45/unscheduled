import { describe, expect, it } from "vitest";
import { fieldLabel, toBacklog, toCve, toExposure, toFreshness, toMatch, toMeta, toSummary, toTimeline } from "@/lib/api/adapt";
import { API_CVE, API_META_EMPTY, API_SUMMARIES, API_TIMELINE } from "@/lib/fixtures/api";

// FIXTURE: every input below is invented in the API's shape (lib/fixtures/api.ts); none is data.

describe("a CVE record", () => {
  const cve = toCve(API_CVE);

  it("keeps every field the API sent, with its source and how it is dated, in the page's order", () => {
    expect(cve.fields).toHaveLength(Object.keys(API_CVE.fields).length);
    expect(cve.fields[0].field).toBe("state");
    const status = cve.fields.find((f) => f.field === "nvd_status");
    expect(status).toEqual({
      field: "nvd_status",
      value: "Awaiting Analysis",
      source: "nvd@nist.gov",
      known_from: "2026-03-24T00:00:00Z",
      dated_by: "event nvd_status, nvd_history",
    });
    expect(cve.fields.find((f) => f.field === "cwes")?.value).toEqual(["CWE-94"]);
  });

  it("reads the header facts from the fields and the links from the record", () => {
    expect(cve).toMatchObject({ id: "CVE-2099-0001", filer: "example.com", nvd_status: "Awaiting Analysis", known: true });
    expect(cve.kev).toEqual({ listed: true, date_added: "2026-06-30", ransomware: "Unknown" });
    expect(cve.epss).toEqual({ score: 0.052, since: "2026-04-01" });
    expect(cve.nvd_url).toBe("https://nvd.nist.gov/vuln/detail/CVE-2099-0001");
    expect(fieldLabel("filer_cvss31_vector")).toBe("Filer CVSS 3.1 vector");
  });

  it("an as-of view before publication has no fields and says the CVE was not known", () => {
    const early = toCve({ ...API_CVE, as_of: "2026-01-01", known: false, fields: {}, note: "not yet published" });
    expect(early.known).toBe(false);
    expect(early.fields).toEqual([]);
    expect(early.kev.listed).toBe(false);
  });
});

describe("a timeline", () => {
  const t = toTimeline(API_TIMELINE, "2026-11-07T12:00:00Z");

  it("draws the events the ruler knows and leaves the rest out", () => {
    expect(t.events.map((e) => e.kind)).toEqual([
      "published",
      "filer_score",
      "nvd_status",
      "cisa_adp",
      "nvd_status",
      "exploit_code",
      "kev_listed",
    ]);
    expect(t.events[2]).toMatchObject({ value: "Received", analyzed: false });
    expect(t.events[3].value).toBe("SSVC exploitation poc, automatable no, technical impact total");
    expect(t.now).toBe("2026-11-07T12:00:00Z");
  });

  it("turns the EPSS events into offsets from publication", () => {
    expect(t.epss).toEqual([
      { offset_days: 0, score: 0.004, score_date: "2026-03-02T16:40:00Z" },
      { offset_days: 30, score: 0.052, score_date: "2026-04-01T00:00:00Z" },
    ]);
  });
});

describe("lists, the backlog and meta", () => {
  it("a summary takes the filer's 4.0 score over its 3.1 score, with the band of the one it took", () => {
    const [first, , third] = API_SUMMARIES.map(toSummary);
    expect(first).toMatchObject({ filer_cvss: 9.8, filer_severity: "Critical", kev_listed: true, cwe: ["CWE-94"] });
    expect(third).toMatchObject({ filer_cvss: 7.5, filer_severity: "High", kev_listed: false });
  });

  it("keeps only backlog questions whose series fit their labels", () => {
    const good = { id: "q1", title: "t", source: "s", window: "w", unit: "share", kind: "line", x: ["a", "b"], series: [{ key: "k", label: "l", slot: 1, values: [0.1, null] }], rule: null, sql: "select 1" };
    const bad = { ...good, id: "q2", series: [{ key: "k", label: "l", slot: 1, values: [0.1] }] };
    const b = toBacklog({ data_version: "fixture", statement: "s", backlog: { data_cut: "2026-11-12T00:00:00Z", questions: [good, bad, "nonsense"] } });
    expect(b.questions.map((q) => q.id)).toEqual(["q1"]);
    expect(b.data_cut).toBe("2026-11-12T00:00:00Z");
    expect(toBacklog({ data_version: "fixture", statement: "s", backlog: null }).questions).toEqual([]);
  });

  it("reads the locks, the newest ledger rows first, and the quarantine counts from meta", () => {
    const m = toMeta({
      ...API_META_EMPTY,
      locks: {
        nvd: { updated_at: "2026-11-12T01:05:19Z", files: 697, rows: 2755405, lock_sha256: "a".repeat(64), cadence: "daily" },
        kev: { updated_at: "2026-11-12T01:07:38Z", files: 8, rows: 14198, lock_sha256: "b".repeat(64), cadence: "hourly" },
      },
      run_ledger: [
        { source: "kev", window: "w1", rows_in: 1, rows_changed: 0, digest: "d1", duration_s: 1, status: "ok", finished_at: "2026-11-12T01:00:00Z" },
        { source: "nvd", window: "w2", rows_in: 2, rows_changed: 1, digest: "d2", duration_s: 2, status: "ok", finished_at: "2026-11-12T02:00:00Z" },
      ],
      quarantine: [{ rule_id: "Q02", rule: "score disagrees with its vector", rows: 815, cves: 812 }],
    });
    expect(m.locks.map((l) => l.source)).toEqual(["kev", "nvd"]);
    expect(m.run_ledger[0].source).toBe("nvd");
    expect(m.quarantine).toEqual([{ rule: "Q02", description: "score disagrees with its vector", rows: 815, cves: 812 }]);
    const fresh = toFreshness(m.locks, Date.parse("2026-11-12T05:00:00Z"));
    expect(fresh).toEqual([
      { source: "kev", fetched_at: "2026-11-12T01:07:38Z", cadence: "hourly", stale: true },
      { source: "nvd", fetched_at: "2026-11-12T01:05:19Z", cadence: "daily", stale: false },
    ]);
  });
});

describe("exposure and a match", () => {
  const body = {
    component: "lodash",
    version: "4.17.20",
    purl: "pkg:npm/lodash@4.17.20",
    advisory_ids: ["GHSA-35jh-r3h4-6jhm"],
    matched_range: ">=0, <4.17.21",
    fixed: ["4.17.21"],
    fix_available: true,
    source: "osv",
    advisory_known_from: "2021-05-06T16:09:43Z",
  };

  it("an exposure finding takes the NVD status and the KEV listing of its CVE as of the snapshot", () => {
    const e = toExposure({
      data_version: "fixture",
      statement: "s",
      as_of_requested: "pin",
      snapshot: "2026-11-08",
      snapshots: ["2026-11-08", "2026-11-12"],
      product: { product_id: "p1", name: "Ledger", attributes: {} },
      summary: { findings: 1, findings_without_cve: 0, findings_fix_available: 1, distinct_cves: 1, cves_by_nvd_status: { Analyzed: 1 }, cves_kev_listed: 0, cves_with_exploit_code: 0 },
      findings: [{ finding_id: "f1", cve_ids: ["CVE-2021-23337"], attributes: body }],
      cves: [{ cve_id: "CVE-2021-23337", in_slice: true, known: true, nvd_status: "Analyzed", nvd_cvss31_band: "High", filer_cvss31_band: null, filer_cvss40_band: null, kev_listed: false, exploit_code_seen: false }],
    });
    expect(e.as_of).toBe("2026-11-08");
    expect(e.findings[0]).toMatchObject({ component: "lodash", cve_ids: ["CVE-2021-23337"], nvd_status: "Analyzed", kev_listed: false, fixed: ["4.17.21"] });
  });

  it("a match finding names its CVEs from the aliases and leaves the NVD state to the CVE page", () => {
    const m = toMatch({
      data_version: "fixture",
      statement: "s",
      as_of: "2026-11-12T00:00:00Z",
      stored: "digest and counts",
      engine: "fixture",
      duration_ms: 3,
      sbom: { sha256: "sha256:abc", format: "cyclonedx", spec_version: "1.6", bytes: 10, components: 2, with_purl: 1, without_purl: 1 },
      counts: { findings: 1, components_matched: 1, advisories_read: 1, distinct_cves: 1 },
      findings: [{ component: "lodash", package: "lodash", version: "4.17.20", advisory_ids: ["GHSA-35jh-r3h4-6jhm"], cve_aliases: ["CVE-2021-23337"], upstream_cves: [], matches: [{ matched_range: ">=0, <4.17.21", sources: ["osv", "ghsa"] }], fixed_versions: ["4.17.21"], known_from: "2021-05-06T16:09:43Z" }],
    });
    expect(m).toMatchObject({ sbom_digest: "sha256:abc", format: "CycloneDX 1.6", components: 2, without_purl: 1 });
    expect(m.findings[0]).toMatchObject({ cve_ids: ["CVE-2021-23337"], matched_range: ">=0, <4.17.21", source: "osv, ghsa", nvd_status: null, kev_listed: null });
  });
});
