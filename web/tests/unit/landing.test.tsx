import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { BeforeAfter, NO_CPE_KEY } from "@/components/site/before-after";
import { HeroField } from "@/components/site/hero-field";

describe("the hero field without data", () => {
  it("is a dot grid that says so, and draws no canvas and no count", () => {
    const html = renderToStaticMarkup(<HeroField field={{ state: "absent" }} />);
    expect(html).toContain("No data release yet");
    expect(html).toContain("dotgrid");
    expect(html).not.toContain("<canvas");
  });

  it("names the file it could not read", () => {
    const html = renderToStaticMarkup(<HeroField field={{ state: "unreadable", file: "web/public/data/field.json" }} />);
    expect(html).toContain("web/public/data/field.json could not be read");
    expect(html).not.toContain("<canvas");
  });
});

describe("the before and after count", () => {
  it("prints the manifest share with one decimal", () => {
    const manifest = { state: "ok" as const, value: { as_of: "2026-11-12", values: { [NO_CPE_KEY]: { value: 0.4752, fmt: "pct1" } } } };
    const html = renderToStaticMarkup(<BeforeAfter manifest={manifest} />);
    expect(html).toContain("47.5%");
    expect(html).toContain("have no NVD CPE configuration");
  });

  it("leaves the line out when the manifest has no value", () => {
    for (const manifest of [{ state: "absent" as const }, { state: "ok" as const, value: { as_of: "2026-11-12", values: {} } }]) {
      const html = renderToStaticMarkup(<BeforeAfter manifest={manifest} />);
      expect(html).not.toContain("ba__count");
    }
  });
});
