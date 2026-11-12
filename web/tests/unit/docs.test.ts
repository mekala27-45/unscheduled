import { describe, expect, it } from "vitest";
import { docSources, leadOf, readDoc, readReports, renderMarkdown } from "@/lib/docs";

describe("renderMarkdown", () => {
  it("takes the first title out, ids every heading and collects the second level as contents", () => {
    const r = renderMarkdown("# The title\n\nText.\n\n## One, two\n\n### Deeper\n\n## One, two\n");
    expect(r.title).toBe("The title");
    expect(r.html).not.toContain("<h1");
    expect(r.html).toContain('<h2 id="one-two">');
    expect(r.html).toContain('<h3 id="deeper">');
    expect(r.html).toContain('<h2 id="one-two-1">');
    expect(r.toc).toEqual([
      { id: "one-two", text: "One, two" },
      { id: "one-two-1", text: "One, two" },
    ]);
  });

  it("wraps every table so a wide one scrolls inside its own box", () => {
    const r = renderMarkdown("| a | b |\n|---|---|\n| 1 | 2 |\n");
    expect(r.html).toContain('<div class="doc__table" tabindex="0"><table>');
    expect(r.html).toContain("</table></div>");
  });

  it("escapes code", () => {
    const r = renderMarkdown("```\n<script>x</script>\n```\n");
    expect(r.html).toContain("&lt;script&gt;");
    expect(r.html).toContain('<pre tabindex="0">');
  });
});

describe("leadOf", () => {
  it("is the first sentence of the first paragraph, past headings and quotes", () => {
    expect(leadOf("# T\n\n> a quote.\n\nFirst sentence here. Second one.\n")).toBe("First sentence here.");
    expect(leadOf("# T\n\nIt ends with a colon:\n\n- a\n")).toBe("It ends with a colon.");
    expect(leadOf("# T\n\nStatus: accepted\n\n## Context\n\nWhy.\n\n## Decision\n\nWhat was decided. More.\n", "Decision")).toBe("What was decided.");
    expect(leadOf("# T\n\nRuns probe_platform.py on data_cut.\n")).toBe("Runs probe_platform.py on data_cut.");
    expect(leadOf("# T\n\nDealt on 7 November (a draw: one, two. three) and kept. Next.\n")).toBe("Dealt on 7 November (a draw: one, two. three) and kept.");
  });
});

describe("the documents in this repository", () => {
  it("lists the architecture, the decisions and the runbooks, each with a title and a lead", () => {
    const slugs = docSources().map((d) => d.slug);
    expect(slugs).toContain("architecture");
    expect(slugs.filter((s) => s.startsWith("adr-")).length).toBeGreaterThanOrEqual(7);
    const doc = readDoc("architecture");
    expect(doc?.title).toBe("Architecture");
    expect(doc?.lead.length).toBeGreaterThan(20);
  });

  it("renders the report documents, each ending with the statement", () => {
    const reports = readReports();
    expect(reports.map((r) => r.slug)).toEqual(["backlog", "discovery", "legacy", "criteria", "data-card"]);
    for (const r of reports) expect(r.html).toContain("portfolio demonstration");
  });
});
