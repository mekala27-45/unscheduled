"use client";

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { Health, Meta } from "@/lib/api/client";
import { useHealth, useMeta } from "@/lib/api/queries";
import { formatBytes, formatDate, formatDateTime, formatInt, shortDigest } from "@/lib/format";
import { SOURCES } from "@/lib/sources";
import { PageHead } from "./page-head";
import { QueryRegion, Region, SkeletonTable } from "./region";
import { StatusText } from "./status-text";

function SourcesTable({ meta, health }: { meta: Meta; health: Health | undefined }) {
  return (
    <Table label="Sources and locks">
      <TableHeader>
        <TableRow>
          <TableHead>Source</TableHead>
          <TableHead>Licence or terms</TableHead>
          <TableHead>Terms read</TableHead>
          <TableHead>Lock digest</TableHead>
          <TableHead className="num">Size</TableHead>
          <TableHead>Fetched</TableHead>
          <TableHead>Freshness</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {SOURCES.map((s) => {
          const lock = meta.locks.find((l) => l.source === s.id);
          const fresh = health?.sources?.find((f) => f.source === s.id);
          return (
            <TableRow key={s.id}>
              <TableCell className="lead">
                {s.name} <span className="text-fg-muted">({s.publisher})</span>
              </TableCell>
              <TableCell>{lock?.licence ?? s.terms}</TableCell>
              <TableCell>{lock ? formatDate(lock.terms_read) : <span className="text-fg-muted">not read yet</span>}</TableCell>
              <TableCell className="mono">{lock ? shortDigest(lock.digest) : <span className="text-fg-muted">no lock</span>}</TableCell>
              <TableCell className="num">{lock ? formatBytes(lock.size_bytes) : ""}</TableCell>
              <TableCell>{lock ? formatDateTime(lock.fetched_at) : <span className="text-fg-muted">not fetched</span>}</TableCell>
              <TableCell>
                {!fresh ? (
                  <StatusText tone="quiet">No reading</StatusText>
                ) : fresh.stale ? (
                  <StatusText tone="warning">Stale past its cadence ({fresh.cadence})</StatusText>
                ) : (
                  <StatusText tone="good">Within its cadence ({fresh.cadence})</StatusText>
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
  const health = useHealth();
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
          empty={{ title: "No source has been fetched yet", body: "Each fetcher writes a lock with its digest, size, address and fetch time. They run at step three of the build.", action: { label: "Open the status page", href: "/status" } }}
        >
          {(m) => <SourcesTable meta={m} health={health.data} />}
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
                    <TableCell className="mono">{r.window}</TableCell>
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
                </TableRow>
              </TableHeader>
              <TableBody>
                {m.quarantine.map((q) => (
                  <TableRow key={q.rule}>
                    <TableCell className="lead mono">{q.rule}</TableCell>
                    <TableCell className="wrap">{q.description}</TableCell>
                    <TableCell className="num">{formatInt(q.rows)}</TableCell>
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
