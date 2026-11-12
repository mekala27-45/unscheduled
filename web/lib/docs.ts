/**
 * The documents the site serves under /docs and /report, read from the repository when the site is
 * built and rendered from Markdown on the server. The site never edits one: each page is the file
 * at the commit the site was built from, and a file that is not there is not listed.
 * Server code only: these run in server components at build time.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { Marked, type Tokens } from "marked";

// Build time only, like lib/build-data.ts: every reader runs while static pages render.
const WEB_ROOT = existsSync(path.join(/*turbopackIgnore: true*/ process.cwd(), "next.config.ts")) ? process.cwd() : path.join(/*turbopackIgnore: true*/ process.cwd(), "web");
const REPO_ROOT = path.resolve(/*turbopackIgnore: true*/ WEB_ROOT, "..");

export type DocSection = "How it is built" | "Decisions" | "Runbooks" | "The data and the customer";
export const DOC_SECTIONS: DocSection[] = ["How it is built", "Decisions", "Runbooks", "The data and the customer"];

/** A file the site renders; a report has no section, a document under /docs has one. */
export type DocSource = { slug: string; file: string; section?: DocSection };
export type TocEntry = { id: string; text: string };
export type Doc = DocSource & { title: string; lead: string; html: string; toc: TocEntry[] };

const FIXED_DOCS: DocSource[] = [
  { slug: "architecture", file: "ARCHITECTURE.md", section: "How it is built" },
  { slug: "spec", file: "docs/SPEC.md", section: "How it is built" },
  { slug: "roadmap", file: "docs/ROADMAP.md", section: "How it is built" },
  { slug: "provenance", file: "data/PROVENANCE.md", section: "The data and the customer" },
  { slug: "customer", file: "customer/README.md", section: "The data and the customer" },
];

/** The four documents the build renders from the manifest, in reading order. */
export const REPORT_SOURCES: DocSource[] = [
  { slug: "backlog", file: "report/backlog.md" },
  { slug: "discovery", file: "report/discovery.md" },
  { slug: "legacy", file: "report/legacy.md" },
  { slug: "criteria", file: "report/criteria.md" },
];

function exists(file: string): boolean {
  return existsSync(path.join(/*turbopackIgnore: true*/ REPO_ROOT, file));
}

function listFolder(folder: string, section: DocSection, prefix: string): DocSource[] {
  const dir = path.join(/*turbopackIgnore: true*/ REPO_ROOT, folder);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => name.endsWith(".md") && name !== "README.md")
    .sort()
    .map((name) => {
      const stem = name.replace(/\.md$/, "");
      const number = /^(\d{4})-/.exec(stem)?.[1];
      return { slug: number ? `${prefix}-${number}` : stem, file: `${folder}/${name}`, section };
    });
}

/** Every document /docs serves, fixed ones first, then the decision records and the runbooks as filed. */
export function docSources(): DocSource[] {
  return [...FIXED_DOCS, ...listFolder("docs/adr", "Decisions", "adr"), ...listFolder("docs/runbooks", "Runbooks", "runbook")].filter((d) => exists(d.file));
}

export function reportSources(): DocSource[] {
  return REPORT_SOURCES.filter((r) => exists(r.file));
}

function slugify(text: string): string {
  const s = text
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/&[a-z#0-9]+;/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return s || "section";
}

/** Inline Markdown to plain text: code ticks and emphasis marks go, an underscore inside a name stays. */
function plain(text: string): string {
  return text
    .replace(/`/g, "")
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/(^|\s)[*_](\S.*?)[*_](?=\s|[.,;:]|$)/g, "$1$2")
    .trim();
}

/**
 * The first sentence of the first paragraph, as the line under a document's name in a list. With
 * `from`, the paragraph is the first one under that second level heading (a decision record is
 * listed by its decision, not its context); a status line is never the lead.
 */
export function leadOf(markdown: string, from?: string): string {
  const start = from ? markdown.search(new RegExp(`^## ${from}\\s*$`, "m")) : -1;
  const blocks = (start >= 0 ? markdown.slice(start) : markdown).split(/\n\s*\n/).map((b) => b.trim());
  const first = blocks.find((b) => b && !/^(#|>|```|\||-\s|\*\s|\d+\.\s|<|Status:)/.test(b)) ?? "";
  const text = plain(first.replace(/\s+/g, " "));
  // The sentence ends at the first full stop or colon outside parentheses that a space or the end follows.
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "(") depth++;
    else if (c === ")") depth = Math.max(0, depth - 1);
    else if (depth === 0 && (c === "." || c === ":") && (i + 1 === text.length || text[i + 1] === " ")) {
      return `${text.slice(0, i)}.`;
    }
  }
  return text;
}

/**
 * Markdown to HTML with an id on every heading below the title, the second level collected as the
 * contents, and every table in a scrolling wrapper so a wide one never widens the page. The ids
 * follow GitHub's anchors, so one may start with a digit. The first level one heading is taken out
 * and returned as the title.
 */
export function renderMarkdown(markdown: string): { title: string | null; html: string; toc: TocEntry[] } {
  const used = new Map<string, number>();
  const toc: TocEntry[] = [];
  let title: string | null = null;
  const marked = new Marked({
    gfm: true,
    renderer: {
      heading(token: Tokens.Heading) {
        const text = plain(token.text);
        if (token.depth === 1 && title === null) {
          title = text;
          return "";
        }
        const base = slugify(text);
        const seen = used.get(base) ?? 0;
        used.set(base, seen + 1);
        const id = seen ? `${base}-${seen}` : base;
        if (token.depth === 2) toc.push({ id, text });
        const inner = this.parser.parseInline(token.tokens);
        return `<h${token.depth} id="${id}">${inner}</h${token.depth}>\n`;
      },
    },
  });
  // A box that may scroll sideways takes keyboard focus, so a reader without a pointer can scroll it.
  const html = (marked.parse(markdown, { async: false }) as string)
    .replaceAll("<table>", '<div class="doc__table" tabindex="0"><table>')
    .replaceAll("</table>", "</table></div>")
    .replaceAll("<pre>", '<pre tabindex="0">');
  return { title, html, toc };
}

function load(source: DocSource): Doc | null {
  const file = path.join(/*turbopackIgnore: true*/ REPO_ROOT, source.file);
  if (!existsSync(file)) return null;
  const markdown = readFileSync(file, "utf8");
  const rendered = renderMarkdown(markdown);
  const lead = leadOf(markdown, source.section === "Decisions" ? "Decision" : undefined);
  return { ...source, title: rendered.title ?? source.file, lead, html: rendered.html, toc: rendered.toc };
}

export function readDoc(slug: string): Doc | null {
  const source = docSources().find((d) => d.slug === slug);
  return source ? load(source) : null;
}

export function readDocs(): Doc[] {
  return docSources()
    .map(load)
    .filter((d): d is Doc => d !== null);
}

export function readReport(slug: string): Doc | null {
  const source = reportSources().find((r) => r.slug === slug);
  return source ? load(source) : null;
}

export function readReports(): Doc[] {
  return reportSources()
    .map(load)
    .filter((d): d is Doc => d !== null);
}
