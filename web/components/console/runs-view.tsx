"use client";

import { PlayIcon } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { RunSummary } from "@/lib/api/client";
import { useRuns, useTriage } from "@/lib/api/queries";
import { normalizeCveId } from "@/lib/cve";
import { formatDate, formatDateTime, isoDay, shortDigest } from "@/lib/format";
import { PageHead } from "./page-head";
import { ErrorState, QueryRegion, Region, SkeletonTable } from "./region";
import { StatusText, type Tone } from "./status-text";

/** The words and tone of a run's status: waiting is a person's turn, decided is done, failed is an error. */
export const RUN_STATUS: Record<string, { tone: Tone; label: string }> = {
  waiting: { tone: "warning", label: "Waits for a person" },
  decided: { tone: "good", label: "Decided" },
  running: { tone: "quiet", label: "Running" },
  failed: { tone: "critical", label: "Failed" },
};

export function RunStatus({ status }: { status: string }) {
  const s = RUN_STATUS[status] ?? { tone: "quiet" as Tone, label: status };
  return <StatusText tone={s.tone}>{s.label}</StatusText>;
}

function StartRun() {
  const router = useRouter();
  const triage = useTriage();
  const [cve, setCve] = useState("");
  const [asOf, setAsOf] = useState("");
  const [invalid, setInvalid] = useState<string | null>(null);
  const yesterday = isoDay(new Date(Date.now() - 86_400_000));

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const id = normalizeCveId(cve.trim());
    if (!id) {
      setInvalid("A CVE id is CVE, the year and a number of four digits or more.");
      return;
    }
    setInvalid(null);
    const run = await triage.mutateAsync({ cveId: id, asOf: asOf || null }).catch(() => null);
    if (run) router.push(`/app/runs/${run.run_id}`);
  }

  return (
    <form className="run-form" onSubmit={(e) => void submit(e)} aria-describedby="run-form-help">
      <div className="run-form__field">
        <Label htmlFor="run-cve">CVE</Label>
        <Input
          id="run-cve"
          className="field--mono"
          value={cve}
          onChange={(e) => setCve(e.target.value)}
          placeholder="CVE-2024-23897"
          autoComplete="off"
          spellCheck={false}
          aria-invalid={invalid ? true : undefined}
          aria-describedby={invalid ? "run-cve-error" : undefined}
        />
      </div>
      <div className="run-form__field">
        <Label htmlFor="run-as-of">As of (optional)</Label>
        <Input id="run-as-of" type="date" value={asOf} max={yesterday} onChange={(e) => setAsOf(e.target.value)} />
      </div>
      <Button type="submit" disabled={triage.isPending}>
        <PlayIcon aria-hidden="true" />
        {triage.isPending ? "Running the graph" : "Start a run"}
      </Button>
      <p id="run-form-help" className="run-form__help">
        A run reads only what was known at the end of the day you give, or now. It drafts and checks; it approves nothing.
      </p>
      {invalid ? (
        <p id="run-cve-error" className="run-form__error" role="alert">
          {invalid}
        </p>
      ) : null}
      {triage.isError ? <ErrorState error={triage.error} what="The run" /> : null}
    </form>
  );
}

function RunsTable({ runs }: { runs: RunSummary[] }) {
  return (
    <Table label="Triage runs, newest first">
      <TableHeader>
        <TableRow>
          <TableHead>Run</TableHead>
          <TableHead>CVE</TableHead>
          <TableHead>As of</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Plan draft</TableHead>
          <TableHead>Warning draft</TableHead>
          <TableHead>Started</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {runs.map((r) => (
          <TableRow key={r.run_id}>
            <TableCell className="lead">
              <Link href={`/app/runs/${r.run_id}`} className="mono">
                {r.run_id.slice(0, 12)}
              </Link>
            </TableCell>
            <TableCell>
              <Link href={`/app/cves/${r.cve_id}`} className="mono">
                {r.cve_id}
              </Link>
            </TableCell>
            <TableCell>{formatDate(r.as_of)}</TableCell>
            <TableCell>
              <RunStatus status={r.status} />
            </TableCell>
            <TableCell className="mono">{r.plan_sha256 ? shortDigest(r.plan_sha256) : <span className="text-fg-muted">none</span>}</TableCell>
            <TableCell className="mono">{r.warning_sha256 ? shortDigest(r.warning_sha256) : <span className="text-fg-muted">none</span>}</TableCell>
            <TableCell>{formatDateTime(r.created_at)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function RunsView() {
  const runs = useRuns();
  return (
    <>
      <PageHead title="Triage runs">
        Each run follows one CVE through the graph: what was known by its time, the match, the fixed version, the exploitation evidence, a drafted patch plan and, for a listed
        or exploited CVE, an early warning. Every claim is checked against its source before a person sees it.
      </PageHead>
      <Region id="start" title="Start a run" note="Free models while their daily budgets last, then the no model floor; the run says which drafted">
        <StartRun />
      </Region>
      <Region id="runs" title="The runs" note="Newest first. A run keeps its checkpoints while it waits; past the caps of ADR 0011 only its record stays">
        <QueryRegion
          query={runs}
          what="The runs"
          loading={<SkeletonTable rows={6} cols={7} />}
          isEmpty={(d) => d.runs.length === 0}
          empty={{ title: "No run yet", body: "Start one above with a CVE the API serves. The run answers when its first draft waits for a person." }}
        >
          {(d) => <RunsTable runs={d.runs} />}
        </QueryRegion>
      </Region>
    </>
  );
}
