"use client";

import Link from "next/link";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useRuns } from "@/lib/api/queries";
import { formatDate, formatDateTime, shortDigest } from "@/lib/format";
import { PageHead } from "./page-head";
import { EmptyState, QueryRegion, Region, SkeletonTable } from "./region";

export function InboxView() {
  const runs = useRuns();
  return (
    <>
      <PageHead title="Inbox">
        What waits for a person. Anyone can read it; deciding needs the approver&apos;s token, which only Ajay holds. A decision names the hash of the draft it was shown.
      </PageHead>
      <Region id="waiting" title="Drafts that wait" note="At most 100 runs wait at once (ADR 0011); the oldest first">
        <QueryRegion
          query={runs}
          what="The runs that wait"
          loading={<SkeletonTable rows={5} cols={5} />}
          isEmpty={(d) => !d.runs.some((r) => r.status === "waiting")}
          empty={{ title: "Nothing waits for a person", body: "Every run started so far is decided or failed. A new run waits here once its first draft is checked.", action: { label: "Open the runs", href: "/app/runs" } }}
        >
          {(d) => (
            <Table label="Runs whose draft waits for a person, oldest first">
              <TableHeader>
                <TableRow>
                  <TableHead>CVE</TableHead>
                  <TableHead>As of</TableHead>
                  <TableHead>What waits</TableHead>
                  <TableHead>Waiting since</TableHead>
                  <TableHead>Run</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {d.runs
                  .filter((r) => r.status === "waiting")
                  .reverse()
                  .map((r) => (
                    <TableRow key={r.run_id}>
                      <TableCell className="lead">
                        <Link href={`/app/cves/${r.cve_id}`} className="mono">
                          {r.cve_id}
                        </Link>
                      </TableCell>
                      <TableCell>{formatDate(r.as_of)}</TableCell>
                      <TableCell>
                        {r.warning_sha256 ? "The early warning" : "The patch plan"}{" "}
                        <span className="mono text-fg-muted">{shortDigest(r.warning_sha256 ?? r.plan_sha256 ?? "", 12)}</span>
                      </TableCell>
                      <TableCell>{formatDateTime(r.created_at)}</TableCell>
                      <TableCell>
                        <Link href={`/app/runs/${r.run_id}#decision`} className="mono">
                          {r.run_id.slice(0, 12)}
                        </Link>
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          )}
        </QueryRegion>
      </Region>
      <Region id="labels" title="Drafts to label for the judge" note="Forty drafts from the development window, each marked usable or not, with a reason">
        <EmptyState
          title="The drafts to label come with the agent evals"
          body="The judge is calibrated against forty labels from Ajay. The drafts are cut from the development runs of the agent evals; until those run, there is nothing to label."
        />
      </Region>
    </>
  );
}
