"use client";

import Link from "next/link";
import { parseAsString, parseAsStringLiteral, useQueryState } from "nuqs";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { Exposure, Finding, Product } from "@/lib/api/client";
import { useExposure, useProducts } from "@/lib/api/queries";
import { formatDate, formatInt } from "@/lib/format";
import { PageHead } from "./page-head";
import { QueryRegion, Region, SkeletonTable } from "./region";
import { StatusText } from "./status-text";

function FindingsTable({ findings }: { findings: Finding[] }) {
  return (
    <Table label="Findings">
      <TableHeader>
        <TableRow>
          <TableHead>Component</TableHead>
          <TableHead>Version</TableHead>
          <TableHead>CVE</TableHead>
          <TableHead>NVD status</TableHead>
          <TableHead>KEV</TableHead>
          <TableHead>Matched range</TableHead>
          <TableHead>Fixed in</TableHead>
          <TableHead>Advisory source</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((f, i) => (
          <TableRow key={`${f.purl ?? f.component}-${f.advisory_ids.join()}-${i}`}>
            <TableCell className="lead">{f.component}</TableCell>
            <TableCell className="mono">{f.version}</TableCell>
            <TableCell>
              {f.cve_ids.length ? (
                f.cve_ids.map((id) => (
                  <Link key={id} href={`/app/cves/${id}`} className="mono mr-xs">
                    {id}
                  </Link>
                ))
              ) : (
                <span className="mono">{f.advisory_ids.join(", ")}</span>
              )}
            </TableCell>
            <TableCell>{f.nvd_status ?? <span className="text-fg-muted">No NVD status</span>}</TableCell>
            <TableCell>{f.kev_listed ? <StatusText tone="critical">Listed</StatusText> : <span className="text-fg-muted">Not listed</span>}</TableCell>
            <TableCell className="mono">{f.matched_range ?? "listed version"}</TableCell>
            <TableCell className="mono">{f.fixed.length ? f.fixed.join(", ") : "no fix"}</TableCell>
            <TableCell>{f.source}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function ExposureSummary({ e }: { e: Exposure }) {
  const cves = new Set(e.findings.flatMap((f) => f.cve_ids));
  const noNvd = e.findings.filter((f) => !f.nvd_status).length;
  const kev = e.findings.filter((f) => f.kev_listed).length;
  const fixed = e.findings.filter((f) => f.fixed.length > 0).length;
  const rows: [string, number][] = [
    ["Findings", e.findings.length],
    ["Distinct CVEs", cves.size],
    ["With no NVD status", noNvd],
    ["Listed in KEV", kev],
    ["With a fixed version", fixed],
  ];
  return (
    <dl className="mb-lg grid grid-cols-2 gap-y-md wide:grid-cols-5">
      {rows.map(([label, n], i) => (
        <div key={label} className={i === 0 ? "pr-md" : "border-l border-line px-md"}>
          <dt className="text-app-xs text-fg-muted">{label}</dt>
          <dd className="num font-heading text-app-2xl">{formatInt(n)}</dd>
        </div>
      ))}
    </dl>
  );
}

export function ProductsView() {
  const products = useProducts();
  const [selected, setSelected] = useQueryState("product", parseAsString);
  const [when, setWhen] = useQueryState("as_of", parseAsStringLiteral(["pin", "today"] as const).withDefault("today"));
  const product: Product | undefined = products.data?.items.find((p) => p.id === selected) ?? products.data?.items[0];
  const exposure = useExposure(product?.id ?? null, product ? (when === "pin" ? "pin" : null) : null);

  return (
    <>
      <PageHead title="Products">
        The six products of Velloran Systems, a fictional customer. Public open source repositories stand in for them, each pinned to one commit.
      </PageHead>
      <Region id="stand-ins" title="The stand-ins" note="Chosen by the rule in config/products.yaml, read on the day each was pinned">
        <QueryRegion
          query={products}
          what="The products"
          loading={<SkeletonTable rows={6} cols={6} />}
          isEmpty={(d) => d.items.length === 0}
          empty={{ title: "No product is loaded yet", body: "The stand-ins are chosen and pinned at step eight of the build, then synced into the API with their SBOMs.", action: { label: "Open the data page", href: "/app/data" } }}
        >
          {(d) => (
            <Table label="The stand-in products">
              <TableHeader>
                <TableRow>
                  <TableHead>Velloran product</TableHead>
                  <TableHead>Stand-in repository</TableHead>
                  <TableHead>Ecosystem</TableHead>
                  <TableHead>Pinned commit</TableHead>
                  <TableHead>Licence</TableHead>
                  <TableHead className="num">Stars, when read</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {d.items.map((p) => (
                  <TableRow key={p.id} data-active={p.id === product?.id}>
                    <TableCell className="lead">
                      <button type="button" className="sort-key underline decoration-line-strong underline-offset-4" onClick={() => void setSelected(p.id)} aria-pressed={p.id === product?.id}>
                        {p.name}
                      </button>
                    </TableCell>
                    <TableCell>
                      {p.repository_url ? (
                        <a href={p.repository_url} className="mono">
                          {p.stand_in}
                        </a>
                      ) : (
                        <span className="mono">{p.stand_in}</span>
                      )}
                    </TableCell>
                    <TableCell>{p.ecosystem}</TableCell>
                    <TableCell className="mono">
                      {p.commit ? p.commit.replace(/^sha256:/, "").slice(0, 12) : "not pinned"}{" "}
                      {p.pinned_on ? <span className="text-fg-muted">({formatDate(p.pinned_on)})</span> : null}
                    </TableCell>
                    <TableCell>{p.licence ?? <span className="text-fg-muted">{p.kind === "image" ? "image, per package" : "not read"}</span>}</TableCell>
                    <TableCell className="num">
                      {p.stars != null ? formatInt(p.stars) : ""} {p.read_on ? <span className="text-fg-muted">({formatDate(p.read_on)})</span> : null}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </QueryRegion>
      </Region>
      {product ? (
        <Region
          id="exposure"
          title={`Exposure of ${product.name}`}
          note={`${product.stand_in} stands in for it. Matched by package URL and version range, then checked by osv-scanner.`}
          tools={
            <ToggleGroup type="single" value={when} onValueChange={(v) => v && void setWhen(v as "pin" | "today")} aria-label="Exposure as of">
              <ToggleGroupItem value="pin">On the pin date</ToggleGroupItem>
              <ToggleGroupItem value="today">Today</ToggleGroupItem>
            </ToggleGroup>
          }
        >
          <QueryRegion
            query={exposure}
            what="The exposure"
            loading={<SkeletonTable rows={8} cols={7} />}
            isEmpty={(e) => e.findings.length === 0}
            empty={{ title: "No advisory range matches this SBOM", body: `Neither OSV nor the GitHub Advisory Database had a range covering a component of ${product.stand_in} on that day.` }}
          >
            {(e) => (
              <>
                <ExposureSummary e={e} />
                <FindingsTable findings={e.findings} />
              </>
            )}
          </QueryRegion>
        </Region>
      ) : null}
    </>
  );
}
