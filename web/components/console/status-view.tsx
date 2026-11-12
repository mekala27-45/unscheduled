"use client";

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { API_BASE } from "@/lib/api/client";
import { useHealth } from "@/lib/api/queries";
import { formatDateTime } from "@/lib/format";
import { SOURCES } from "@/lib/sources";
import { PageHead } from "./page-head";
import { QueryRegion, Region, SkeletonLines, SkeletonTable } from "./region";
import { StatusText, type Tone } from "./status-text";

const OVERALL: Record<string, [Tone, string]> = {
  ok: ["good", "Answering"],
  degraded: ["warning", "Answering, with stale sources"],
  down: ["critical", "Not serving"],
};

export function StatusView() {
  const health = useHealth(true);
  const name = (id: string) => SOURCES.find((s) => s.id === id)?.name ?? id;
  return (
    <>
      <PageHead title="Status" meta={<span>Read from {API_BASE ? `${API_BASE}/health` : "no API address in this build"}, every minute while this page is open</span>}>
        Whether the API answers, whether its database is reachable, which release it serves, and how fresh each source is.
      </PageHead>
      <Region id="service" title="The service">
        <QueryRegion query={health} what="The health check" loading={<SkeletonLines lines={3} />} empty={{ title: "", body: "" }}>
          {(h) => {
            const [tone, word] = OVERALL[h.status] ?? ["quiet", h.status];
            return (
              <dl className="facts">
                <dt>API</dt>
                <dd>
                  <StatusText tone={tone}>{word}</StatusText>
                </dd>
                <dt>Database</dt>
                <dd>
                  {h.database === "ok" ? (
                    <StatusText tone="good">Reachable</StatusText>
                  ) : h.database === "unreachable" ? (
                    <StatusText tone="critical">Unreachable</StatusText>
                  ) : (
                    <StatusText tone="quiet">{h.database}</StatusText>
                  )}
                </dd>
                <dt>Release served</dt>
                <dd>{h.release ? <span className="mono">{h.release}</span> : <StatusText tone="quiet">No release loaded yet</StatusText>}</dd>
                <dt>Last sync</dt>
                <dd>{h.synced_at ? formatDateTime(h.synced_at) : "Never synced"}</dd>
                <dt>Version</dt>
                <dd className="mono">{h.data_version ?? h.version ?? "not reported"}</dd>
              </dl>
            );
          }}
        </QueryRegion>
      </Region>
      <Region id="freshness" title="Freshness per source" note="A source is stale once its last fetch is older than its cadence">
        <QueryRegion
          query={health}
          what="The freshness readings"
          loading={<SkeletonTable rows={9} cols={3} />}
          isEmpty={(h) => (h.sources ?? []).length === 0}
          empty={{ title: "No source has a reading yet", body: "Freshness is read from the release the API serves. Until a release is loaded, there is nothing to date.", action: { label: "Open the data page", href: "/app/data" } }}
        >
          {(h) => (
            <Table label="Freshness per source">
              <TableHeader>
                <TableRow>
                  <TableHead>Source</TableHead>
                  <TableHead>Last fetch</TableHead>
                  <TableHead>Cadence</TableHead>
                  <TableHead>Freshness</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(h.sources ?? []).map((s) => (
                  <TableRow key={s.source}>
                    <TableCell className="lead">{name(s.source)}</TableCell>
                    <TableCell>{s.fetched_at ? formatDateTime(s.fetched_at) : "never"}</TableCell>
                    <TableCell>{s.cadence}</TableCell>
                    <TableCell>{s.stale ? <StatusText tone="warning">Stale</StatusText> : <StatusText tone="good">Fresh</StatusText>}</TableCell>
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
