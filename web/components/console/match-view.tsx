"use client";

import { FileJsonIcon, UploadIcon } from "lucide-react";
import Link from "next/link";
import { useRef, useState, type DragEvent } from "react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { MATCH_LIMIT_BYTES, type MatchResult } from "@/lib/api/client";
import { useMatch } from "@/lib/api/queries";
import { formatBytes, formatDateTime, formatInt } from "@/lib/format";
import { PageHead } from "./page-head";
import { EmptyState, ErrorState, Loading, Region, SkeletonTable } from "./region";

type Picked = { name: string; size: number; format: string; components: number; digest: string; body: Record<string, unknown> };

async function sha256(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Reads the file in the browser: the size limit, JSON, and which SBOM format it is, before anything is sent. */
async function inspect(file: File): Promise<Picked> {
  if (file.size > MATCH_LIMIT_BYTES) throw new Error(`${file.name} is ${formatBytes(file.size)}; the API takes SBOMs up to 2 MB.`);
  const text = await file.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`${file.name} is not JSON. Export the SBOM as CycloneDX JSON or SPDX JSON.`);
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) throw new Error(`${file.name} is JSON but not an SBOM document.`);
  const doc = body as Record<string, unknown>;
  let format: string;
  let components: number;
  if (doc.bomFormat === "CycloneDX") {
    format = `CycloneDX ${typeof doc.specVersion === "string" ? doc.specVersion : ""}`.trim();
    components = Array.isArray(doc.components) ? doc.components.length : 0;
  } else if (typeof doc.spdxVersion === "string") {
    format = doc.spdxVersion;
    components = Array.isArray(doc.packages) ? doc.packages.length : 0;
  } else {
    throw new Error(`${file.name} is neither CycloneDX (bomFormat) nor SPDX (spdxVersion).`);
  }
  return { name: file.name, size: file.size, format, components, digest: await sha256(text), body: doc };
}

function Results({ r, local }: { r: MatchResult; local: Picked }) {
  return (
    <>
      <p className="mb-md text-app-sm text-fg-2">
        {formatInt(r.components)} components in {r.format}; {formatInt(r.findings.length)} findings. The API kept the digest{" "}
        <span className="mono">{r.sbom_digest}</span> and the counts, not the file
        {r.sbom_digest.replace(/^sha256:/, "") === local.digest ? ", and it matches the digest this browser computed." : "."}{" "}
        Each CVE opens its record, with its NVD status and its KEV listing.
      </p>
      {r.findings.length === 0 ? (
        <EmptyState title="No advisory range matched" body={`None of the ${formatInt(r.components)} components falls in an OSV or GitHub advisory range. Components without a package URL cannot be matched.`} />
      ) : (
        <Table label="Findings for this SBOM">
          <TableHeader>
            <TableRow>
              <TableHead>Component</TableHead>
              <TableHead>Version</TableHead>
              <TableHead>Advisories</TableHead>
              <TableHead>Matched range</TableHead>
              <TableHead>Fixed in</TableHead>
              <TableHead>Advisory known since</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {r.findings.map((f, i) => (
              <TableRow key={`${f.purl ?? f.component}-${i}`}>
                <TableCell className="lead">{f.component}</TableCell>
                <TableCell className="mono">{f.version}</TableCell>
                <TableCell>
                  {[...f.cve_ids, ...f.advisory_ids.filter((a) => !f.cve_ids.includes(a))].map((id) =>
                    id.startsWith("CVE-") ? (
                      <Link key={id} href={`/app/cves/${id}`} className="mono mr-xs">
                        {id}
                      </Link>
                    ) : (
                      <span key={id} className="mono mr-xs">
                        {id}
                      </span>
                    ),
                  )}
                </TableCell>
                <TableCell className="mono">{f.matched_range ?? "listed version"}</TableCell>
                <TableCell className="mono">{f.fixed.length ? f.fixed.join(", ") : "no fix"}</TableCell>
                <TableCell>{formatDateTime(f.advisory_known_from)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </>
  );
}

export function MatchView() {
  const input = useRef<HTMLInputElement>(null);
  const [picked, setPicked] = useState<Picked | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [over, setOver] = useState(false);
  const match = useMatch();

  const take = async (file: File | undefined) => {
    if (!file) return;
    setProblem(null);
    match.reset();
    try {
      const p = await inspect(file);
      setPicked(p);
      match.mutate(p.body);
    } catch (e) {
      setPicked(null);
      setProblem(e instanceof Error ? e.message : "That file could not be read.");
    }
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    void take(e.dataTransfer.files[0]);
  };

  return (
    <>
      <PageHead title="Match">
        Match a CycloneDX or SPDX JSON SBOM against every OSV and GitHub advisory range. The API keeps the file&apos;s digest and the counts, never the file.
      </PageHead>
      <div
        className="drop mb-xl"
        data-over={over}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={onDrop}
      >
        <FileJsonIcon aria-hidden="true" className="size-6 text-fg-muted" />
        <p className="text-app-md">Drop an SBOM here, or choose the file.</p>
        <p className="text-app-xs text-fg-muted">CycloneDX 1.6 JSON or SPDX JSON, up to 2 MB. Components need a package URL to be matched.</p>
        <input
          ref={input}
          id="sbom"
          type="file"
          accept="application/json,.json"
          className="visually-hidden file-input"
          aria-describedby="sbom-help"
          onChange={(e) => void take(e.target.files?.[0])}
        />
        <label htmlFor="sbom" className="key key--primary">
          <UploadIcon aria-hidden="true" />
          Choose an SBOM
        </label>
        <p id="sbom-help" className="help" data-tone={problem ? "error" : undefined} aria-live="polite">
          {problem ?? (picked ? `${picked.name}, ${formatBytes(picked.size)}, ${picked.format}, ${formatInt(picked.components)} components, SHA-256 ${picked.digest.slice(0, 16)}` : "")}
        </p>
      </div>
      <Region id="findings" title="Findings">
        {!picked ? (
          <EmptyState title="No SBOM matched yet" body="The findings for one SBOM appear here: each component and version, the advisory and its range, the fixed version, and what the NVD and KEV say about the CVE." />
        ) : match.isPending ? (
          <Loading label="the findings">
            <SkeletonTable rows={6} cols={7} />
          </Loading>
        ) : match.isError ? (
          <ErrorState error={match.error} what="The match" onRetry={() => match.mutate(picked.body)} />
        ) : match.data ? (
          <Results r={match.data} local={picked} />
        ) : null}
      </Region>
    </>
  );
}
