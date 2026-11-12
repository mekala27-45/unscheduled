"use client";

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toFreshness } from "@/lib/api/adapt";
import type { Meta } from "@/lib/api/client";
import { useMeta } from "@/lib/api/queries";
import { formatDateTime, formatInt, shortDigest } from "@/lib/format";
import { SOURCES } from "@/lib/sources";
import { PageHead } from "./page-head";
import { QueryRegion, Region, SkeletonTable } from "./region";
import { StatusText } from "./status-text";

function SourcesTable({ meta }: { meta: Meta }) {
  const fresh = toFreshness(meta.locks);
  const known = new Set(SOURCES.map((s) => s.id as string));
  const rows = [...SOURCES.map((s) => ({ id: s.id as string, name: s.name, publisher: s.publisher, terms: s.terms })), ...meta.locks.filter((l) => !known.has(l.source)).map((l) => ({ id: l.source, name: l.source, publisher: "", terms: "see data/PROVENANCE.md" }))];
  return (
    <Table label="Sources and locks">
      <TableHeader>
        <TableRow>
          <TableHead>Source</TableHead>
          <TableHead>Licence or terms</TableHead>
          <TableHead className="num">Raw files</TableHead>
          <TableHead className="num">Rows</TableHead>
          <TableHead>Lock digest</TableHead>
          <TableHead>Lock written</TableHead>
          <TableHead>Freshness</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((s) => {
          const lock = meta.locks.find((l) => l.source === s.id);
          const f = fresh.find((x) => x.source === s.id);
          return (
            <TableRow key={s.id}>
              <TableCell className="lead">
                {s.name} {s.publisher ? <span className="text-fg-muted">({s.publisher})</span> : null}
              </TableCell>
              <TableCell>{s.terms}</TableCell>
              <TableCell className="num">{lock ? formatInt(lock.files) : ""}</TableCell>
              <TableCell className="num">{lock ? formatInt(lock.rows) : ""}</TableCell>
              <TableCell className="mono">{lock ? shortDigest(lock.digest) : <span className="text-fg-muted">no lock</span>}</TableCell>
              <TableCell>{lock?.fetched_at ? formatDateTime(lock.fetched_at) : <span className="text-fg-muted">not fetched</span>}</TableCell>
              <TableCell>
                {!f ? (
                  <StatusText tone="quiet">No reading</StatusText>
                ) : f.stale ? (
                  <StatusText tone="warning">Older than its cadence ({f.cadence})</StatusText>
                ) : (
                  <StatusText tone="good">Within its cadence ({f.cadence})</StatusText>
                )}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

export function DataView() {
  const meta = useMeta();
  return (
    <>
      <PageHead title="Data" meta={meta.data ? <span>Data version {meta.data.data_version}</span> : undefined}>
        Every source with its licence, its lock and when it was fetched; the run ledger; and the rows each quarantine rule held back.
      </PageHead>
      <Region id="sources" title="Sources and locks" note="Fetched in GitHub Actions and locked by digest; nothing is fetched from this page">
        <QueryRegion
          query={meta}
          what="The source locks"
          loading={<SkeletonTable rows={9} cols={6} />}
          isEmpty={(m) => m.locks.length === 0}
          empty={{ title: "No data release is loaded yet", body: "The locks of every source come with the serving bundle. Until the API has synced one, there is nothing to list.", action: { label: "Open the status page", href: "/status" } }}
        >
          {(m) => <SourcesTable meta={m} />}
        </QueryRegion>
      </Region>
      <Region id="ledger" title="The run ledger" note="One row per fetch or build run: the window, the rows in and changed, the digest">
        <QueryRegion
          query={meta}
          what="The run ledger"
          loading={<SkeletonTable rows={6} cols={6} />}
          isEmpty={(m) => m.run_ledger.length === 0}
          empty={{ title: "No run is recorded yet", body: "A run writes its row when a fetch or a build finishes, whether it passed or failed." }}
        >
          {(m) => (
            <Table label="The run ledger">
              <TableHeader>
                <TableRow>
                  <TableHead>Finished</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Window</TableHead>
                  <TableHead className="num">Rows in</TableHead>
                  <TableHead className="num">Rows changed</TableHead>
                  <TableHead className="num">Seconds</TableHead>
                  <TableHead>Digest</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {m.run_ledger.map((r, i) => (
                  <TableRow key={`${r.source}-${r.finished_at}-${i}`}>
                    <TableCell>{formatDateTime(r.finished_at)}</TableCell>
                    <TableCell className="lead">{r.source}</TableCell>
                    <TableCell className="mono wrap">{r.window}</TableCell>
                    <TableCell className="num">{formatInt(r.rows_in)}</TableCell>
                    <TableCell className="num">{formatInt(r.rows_changed)}</TableCell>
                    <TableCell className="num">{r.duration_s.toFixed(1)}</TableCell>
                    <TableCell className="mono">{shortDigest(r.digest)}</TableCell>
                    <TableCell>{r.status === "ok" ? <StatusText tone="good">ok</StatusText> : <StatusText tone="serious">{r.status}</StatusText>}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </QueryRegion>
      </Region>
      <Region id="quarantine" title="Quarantine" note="Rows that failed a named rule are held back with the rule, never dropped">
        <QueryRegion
          query={meta}
          what="The quarantine counts"
          loading={<SkeletonTable rows={8} cols={3} />}
          isEmpty={(m) => m.quarantine.length === 0}
          empty={{ title: "No quarantine count yet", body: "Rules Q01 to Q08 count their rows when the warehouse builds. A rule with nothing to hold reports zero, not silence." }}
        >
          {(m) => (
            <Table label="Quarantine counts">
              <TableHeader>
                <TableRow>
                  <TableHead>Rule</TableHead>
                  <TableHead>What it holds back</TableHead>
                  <TableHead className="num">Rows</TableHead>
                  <TableHead className="num">CVEs</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {m.quarantine.map((q) => (
                  <TableRow key={q.rule}>
                    <TableCell className="lead mono">{q.rule}</TableCell>
                    <TableCell className="wrap">{q.description}</TableCell>
                    <TableCell className="num">{formatInt(q.rows)}</TableCell>
                    <TableCell className="num">{q.cves == null ? "" : formatInt(q.cves)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </QueryRegion>
      </Region>
    </>
  );
}
