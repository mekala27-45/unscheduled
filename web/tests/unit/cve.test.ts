import { describe, expect, it } from "vitest";
import { describeError, ApiError } from "@/lib/api/client";
import { normalizeCveId, normalizeCweId } from "@/lib/cve";
import { daysBetween, formatDate } from "@/lib/format";

describe("ids and dates", () => {
  it("normalizes a CVE id and refuses anything else", () => {
    expect(normalizeCveId(" cve-2026-12345 ")).toBe("CVE-2026-12345");
    expect(normalizeCveId("CVE-2026-123")).toBeNull();
    expect(normalizeCveId("CVE-1998-0001")).toBeNull();
    expect(normalizeCveId("GHSA-xxxx-xxxx-xxxx")).toBeNull();
    expect(normalizeCweId("cwe-79")).toBe("CWE-79");
    expect(normalizeCweId("79")).toBeNull();
  });

  it("prints dates one way, in UTC", () => {
    expect(formatDate("2026-04-15")).toBe("15 Apr 2026");
    expect(formatDate("2026-04-15T23:30:00-05:00", "long")).toBe("16 April 2026");
    expect(formatDate(null)).toBe("not recorded");
    expect(daysBetween("2026-04-15", "2026-11-07")).toBe(206);
  });
});

describe("error states", () => {
  it("says what broke and what to do for each kind of failure", () => {
    expect(describeError(new ApiError("not-configured", "/v1/cves", "x")).title).toBe("This build has no API address");
    expect(describeError(new ApiError("network", "/v1/cves", "x")).retry).toBe(true);
    const notFound = describeError(new ApiError("http", "/v1/backlog", "Not Found", 404));
    expect(notFound.title).toBe("The API has no data for this yet");
    const problem = describeError(new ApiError("http", "/v1/match", "Too large", 413, { type: "about:blank", title: "The SBOM is over 2 MB", status: 413, detail: "Send one up to 2 MB." }));
    expect(problem).toMatchObject({ title: "The SBOM is over 2 MB", body: "Send one up to 2 MB.", retry: false });
  });
});
