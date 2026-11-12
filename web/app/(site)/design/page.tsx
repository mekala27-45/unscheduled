import type { Metadata } from "next";
import type { CSSProperties } from "react";
import { EmptyState, ErrorState, Loading, SkeletonTable } from "@/components/console/region";
import { StatusText } from "@/components/console/status-text";
import { Ruler } from "@/components/ruler/ruler";
import { Mast } from "@/components/site/mast";
import { SiteNav } from "@/components/site/site-nav";
import { Button } from "@/components/ui/button";
import { Kbd } from "@/components/ui/kbd";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { FIXTURE_NOTE, SUMMARY_FIXTURE, TIMELINE_FIXTURE } from "@/lib/fixtures/cve";
import { formatDate } from "@/lib/format";
import { readColorTokens, type TokenPair } from "@/lib/tokens-read";

export const metadata: Metadata = {
  title: "Design system",
  description: "The desk: type, colour, keys, cut panels, a dense table and the four data states of unscheduled, read from its token file.",
};

const SLOTS = [
  ["--chart-1", "Slot 1, cobalt", "CVEs the NVD has not scheduled"],
  ["--chart-2", "Slot 2, amber", "NVD analyzed values"],
  ["--chart-3", "Slot 3, plum", "Filer (CNA) values"],
  ["--chart-4", "Slot 4, teal", "CISA ADP values"],
  ["--chart-5", "Slot 5, olive", "EPSS"],
  ["--chart-6", "Slot 6, violet", "Awaiting or undergoing analysis"],
  ["--chart-7", "Slot 7, brown", "Exploit code seen"],
  ["--chart-8", "Slot 8, slate", "Every other status"],
];

const SURFACES = ["--color-paper", "--color-paper-2", "--color-paper-3", "--color-card", "--color-ink", "--color-ink-2", "--color-muted", "--color-rule", "--color-rule-2", "--color-accent", "--color-accent-wash", "--color-graphite"];

function Swatch({ name, pairs, role }: { name: string; pairs: Map<string, TokenPair>; role?: string }) {
  const p = pairs.get(name);
  return (
    <div className="swatch">
      <span className="swatch__chip" style={{ background: `var(${name})` } as CSSProperties} />
      <span className="swatch__name mono">{name}</span>
      {role ? <span className="swatch__role">{role}</span> : null}
      <span className="swatch__values mono">
        {p ? `${p.light}, dark ${p.dark}` : "not in tokens.css"}
      </span>
    </div>
  );
}

function Spec({ id, title, note, children }: { id: string; title: string; note?: string; children: React.ReactNode }) {
  return (
    <section className="spec" aria-labelledby={`${id}-title`}>
      <div className="spec__head">
        <h2 id={`${id}-title`}>{title}</h2>
        {note ? <p>{note}</p> : null}
      </div>
      {children}
    </section>
  );
}

export default function DesignPage() {
  const pairs = new Map(readColorTokens().map((t) => [t.name, t]));
  const networkError = { kind: "network", path: "/v1/cves", message: "The API did not answer." };
  return (
    <div className="site">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <SiteNav banner={<span>The design system of unscheduled, read from web/styles/tokens.css when the site was built.</span>} />
      <main id="main" tabIndex={-1} className="container design">
        <header className="design__head">
          <h1>The desk, tokens first</h1>
          <p className="lead">Cool paper ruled with hairlines, keys with a real bottom edge, panels cut on two corners, and one cobalt signal.</p>
        </header>

        <Spec id="type" title="Type" note="Three faces from Fontsource 5.3.0, self hosted">
          <div className="typespec">
            <div>
              <p className="typespec__label">Rethink Sans 600, heads and display figures</p>
              <p className="typespec__display">The CVEs nobody scheduled</p>
            </div>
            <div>
              <p className="typespec__label">Anek Latin 400 and 500, the interface and the body</p>
              <p className="typespec__body">
                Since 15 April 2026 the NVD enriches the CVEs it ranks first and labels the rest lowest priority. Tables stay readable at
                14px; the console never sets type under 12px.
              </p>
            </div>
            <div>
              <p className="typespec__label">Mononoki 400, machine values only</p>
              <p className="typespec__mono mono">CVE-2099-0001 pkg:npm/example-server@2.4.0 sha256:3f9a0c</p>
            </div>
          </div>
          <dl className="scale">
            <dt>Landing and docs</dt>
            <dd>display clamp to 84px, section to 56px, lead to 22px, body 16px at 1.5</dd>
            <dt>Console</dt>
            <dd>fixed, ratio 8/7: 12, 14, 16, 18.3, 20.9 and 23.9px; tables at 14px</dd>
          </dl>
        </Spec>

        <Spec id="colour" title="Colour" note="Each swatch is the token in the current theme; the values are light first, then dark">
          <div className="swatches">
            {SURFACES.map((name) => (
              <Swatch key={name} name={name} pairs={pairs} />
            ))}
          </div>
          <h3 className="spec__sub">The chart palette, in fixed order</h3>
          <div className="swatches">
            {SLOTS.map(([name, label, role]) => (
              <Swatch key={name} name={name} pairs={pairs} role={`${label}: ${role}`} />
            ))}
          </div>
          <h3 className="spec__sub">Sequential and diverging</h3>
          <div className="ramp" aria-label="Sequential cobalt ramp, low to high">
            {["--seq-1", "--seq-2", "--seq-3", "--seq-4", "--seq-5"].map((n) => (
              <span key={n} style={{ background: `var(${n})` } as CSSProperties} title={n} />
            ))}
          </div>
          <div className="ramp" aria-label="Diverging ramp, amber where the filer scored higher, cobalt where lower">
            {["--div-1", "--div-2", "--div-3", "--div-4", "--div-mid", "--div-6", "--div-7", "--div-8", "--div-9"].map((n) => (
              <span key={n} style={{ background: `var(${n})` } as CSSProperties} title={n} />
            ))}
          </div>
          <p className="spec__note">Severity is ordinal and drawn on the cobalt ramp with its word, never in red.</p>
          <h3 className="spec__sub">Status, always a word and an icon</h3>
          <p className="flex flex-wrap gap-lg">
            <StatusText tone="good">Fresh</StatusText>
            <StatusText tone="warning">Stale past its cadence</StatusText>
            <StatusText tone="serious">Run failed</StatusText>
            <StatusText tone="critical">Listed in KEV</StatusText>
            <StatusText tone="quiet">No reading</StatusText>
          </p>
        </Spec>

        <Spec id="keys" title="Keys and fields" note="Keys lift a pixel on hover and sink on press; the one primary is solid cobalt">
          <div className="flex flex-wrap items-center gap-sm">
            <Button variant="primary">Look up a CVE</Button>
            <Button>Apply</Button>
            <Button aria-pressed="true">Table</Button>
            <Button variant="quiet">Clear filters</Button>
            <Button className="is-focus">Focused</Button>
            <Button disabled>Disabled</Button>
            <Button size="sm">Small key</Button>
          </div>
          <div className="tray mt-lg" role="group" aria-label="Exposure as of">
            <button type="button" className="key key--sm" aria-pressed="true">
              On the pin date
            </button>
            <button type="button" className="key key--sm" aria-pressed="false">
              Today
            </button>
          </div>
          <div className="mt-lg grid max-w-[44rem] gap-md wide:grid-cols-2">
            <div>
              <label className="label" htmlFor="spec-field">
                CVE id
              </label>
              <input id="spec-field" className="field field--mono" defaultValue="CVE-2099-0001" />
              <p className="help">A help line keeps its height so nothing jumps.</p>
            </div>
            <div>
              <label className="label" htmlFor="spec-bad">
                CWE
              </label>
              <input id="spec-bad" className="field field--mono" defaultValue="79" aria-invalid="true" aria-describedby="spec-bad-help" />
              <p id="spec-bad-help" className="help" data-tone="error">
                Write a CWE as CWE-79.
              </p>
            </div>
          </div>
          <p className="mt-md text-app-sm text-fg-2">
            Shortcuts are keycaps: <Kbd>g</Kbd> <Kbd>c</Kbd> opens the CVEs, <Kbd>/</Kbd> focuses search, <Kbd>?</Kbd> lists the rest.
          </p>
        </Spec>

        <Spec id="panels" title="Cut panels" note="One paper step and a hairline; graphite only for code and machine values">
          <div className="grid gap-lg wide:grid-cols-3">
            <div className="cut panel p-lg">
              <h3 className="spec__sub mt-0">A panel</h3>
              <p className="text-app-sm text-fg-2">The card face on the page ground, cut on two opposite corners.</p>
            </div>
            <div className="well">
              <h3 className="spec__sub mt-0">A well</h3>
              <p className="text-app-sm text-fg-2">A sunken paper step with no border, for states and quiet groups.</p>
            </div>
            <figure className="code">
              <figcaption className="code__head">
                <span>GET /v1/cves/CVE-2099-0001/timeline</span>
              </figcaption>
              <pre className="code__body">{`{ "kind": "nvd_status",\n  "value": "Awaiting Analysis",\n  "analyzed": false }`}</pre>
            </figure>
          </div>
        </Spec>

        <Spec id="table" title="A dense table" note={FIXTURE_NOTE}>
          <Table label="Specimen CVE table, fixture rows">
            <TableHeader>
              <TableRow>
                <TableHead>CVE</TableHead>
                <TableHead>Published</TableHead>
                <TableHead>NVD status</TableHead>
                <TableHead>KEV</TableHead>
                <TableHead>Filer</TableHead>
                <TableHead className="num">Filer CVSS</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {SUMMARY_FIXTURE.map((c, i) => (
                <TableRow key={c.id} data-active={i === 1 ? "true" : undefined}>
                  <TableCell className="lead mono">{c.id}</TableCell>
                  <TableCell>{formatDate(c.published)}</TableCell>
                  <TableCell>{c.nvd_status ?? <span className="text-fg-muted">No NVD status</span>}</TableCell>
                  <TableCell>{c.kev_listed ? <StatusText tone="critical">Listed</StatusText> : <span className="text-fg-muted">Not listed</span>}</TableCell>
                  <TableCell>{c.filer}</TableCell>
                  <TableCell className="num">{c.filer_cvss == null ? "none" : `${c.filer_cvss.toFixed(1)} ${c.filer_severity}`}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Spec>

        <Spec id="states" title="The four states" note="Every region that loads data draws all four">
          <div className="states-grid">
            <div>
              <p className="spec__label">Loading, in the shape of what comes</p>
              <Loading label="the specimen table">
                <SkeletonTable rows={3} cols={4} />
              </Loading>
            </div>
            <div>
              <p className="spec__label">Empty, with the one action that fills it</p>
              <EmptyState title="No CVE matches these filters" body="Loosen one filter at a time." action={{ label: "Clear filters", href: "/design#states" }} />
            </div>
            <div>
              <p className="spec__label">Error, with what broke and what to do</p>
              <ErrorState error={networkError} what="The CVE list" />
            </div>
            <div>
              <p className="spec__label">Full</p>
              <ul className="grid">
                {SUMMARY_FIXTURE.slice(0, 3).map((c) => (
                  <li key={c.id} className="grid gap-3xs border-t border-line py-xs">
                    <span className="mono text-app-sm">{c.id}</span>
                    <span className="text-app-xs text-fg-muted">
                      {c.filer}, {c.nvd_status ?? "no NVD status"}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </Spec>

        <Spec id="ruler" title="The ruler" note={FIXTURE_NOTE}>
          <Ruler id={TIMELINE_FIXTURE.id} events={TIMELINE_FIXTURE.events} now={TIMELINE_FIXTURE.now} />
        </Spec>
      </main>
      <Mast />
    </div>
  );
}
