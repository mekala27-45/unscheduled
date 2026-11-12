"use client";

import Link from "next/link";
import { parseAsArrayOf, parseAsString, useQueryState } from "nuqs";
import { BarChart, LineChart, SeriesTable } from "@/components/charts/series-chart";
import { Toggle } from "@/components/ui/toggle";
import type { BacklogQuestion } from "@/lib/api/client";
import { useBacklog } from "@/lib/api/queries";
import { PageHead } from "./page-head";
import { EmptyState, ErrorState, Loading, Region, SkeletonChart } from "./region";

/** The six questions of the Phase 1 plan the console draws; Q7 lives on Products and Q8 in the report. */
export const QUESTIONS = [
  { id: "q1", title: "The analysis delay", ask: "How many CVEs a month reached NVD analysis within 7, 30 and 90 days, since January 2020" },
  { id: "q2", title: "After the change", ask: "New CVEs by NVD status since 15 April 2026, and the hours from KEV listing to NVD analysis" },
  { id: "q3", title: "What the filer gives instead", ask: "For CVEs without NVD analysis, the share with a filer CVSS, a CWE, versions and a CISA ADP value" },
  { id: "q4", title: "Can a filer score stand in for the NVD", ask: "Agreement on CVEs both scored, by filer type, in the train, development and shadow windows" },
  { id: "q5", title: "Exploited, and when", ask: "For KEV listed CVEs since 2021, days to listing and what the NVD had done by then" },
  { id: "q6", title: "Who files the flood", ask: "The share of monthly volume by filer and filer type since 2020" },
];

function useToggleSet(key: string) {
  const [list, setList] = useQueryState(key, parseAsArrayOf(parseAsString).withDefault([]));
  const toggle = (id: string, on: boolean) => {
    const next = on ? [...new Set([...list, id])] : list.filter((x) => x !== id);
    void setList(next.length ? next : null);
  };
  return [list, toggle] as const;
}

function Question({ q, table, sql, onTable, onSql }: { q: BacklogQuestion; table: boolean; sql: boolean; onTable: (on: boolean) => void; onSql: (on: boolean) => void }) {
  return (
    <div className="grid gap-md">
      <div className="flex flex-wrap items-start justify-between gap-sm">
        <p className="chart-title">{q.title}</p>
        <div className="flex gap-xs">
          <Toggle pressed={table} onPressedChange={onTable} aria-label={`Show ${q.id.toUpperCase()} as a table`}>
            Table
          </Toggle>
          <Toggle pressed={sql} onPressedChange={onSql} aria-label={`Show the SQL behind ${q.id.toUpperCase()}`}>
            SQL
          </Toggle>
        </div>
      </div>
      {table ? <SeriesTable q={q} /> : q.kind === "line" ? <LineChart q={q} /> : <BarChart q={q} />}
      <p className="chart-source">
        {q.source}, {q.window}
      </p>
      {sql ? (
        <figure className="code">
          <figcaption className="code__head">
            <span>The query behind {q.id.toUpperCase()}</span>
          </figcaption>
          <pre className="code__body">{q.sql}</pre>
        </figure>
      ) : null}
    </div>
  );
}

export function BacklogView() {
  const backlog = useBacklog();
  const [tables, toggleTable] = useToggleSet("table");
  const [sqls, toggleSql] = useToggleSet("sql");

  return (
    <>
      <PageHead title="Backlog" meta={backlog.data ? <span>Data version {backlog.data.data_version}</span> : undefined}>
        What the NVD stopped analyzing, measured six ways. Every chart has its table and its SQL; every title is rendered from the manifest.
      </PageHead>
      {backlog.isError ? <ErrorState error={backlog.error} what="The backlog" onRetry={() => void backlog.refetch()} /> : null}
      {QUESTIONS.map((meta) => {
        const q = backlog.data?.questions.find((x) => x.id === meta.id);
        return (
          <Region key={meta.id} id={meta.id} title={`${meta.id.toUpperCase()}. ${meta.title}`} note={meta.ask}>
            {backlog.isPending ? (
              <Loading label={meta.title}>
                <SkeletonChart />
              </Loading>
            ) : backlog.isError ? (
              <p className="text-app-sm text-fg-muted">Not drawn: the backlog request above failed.</p>
            ) : q ? (
              <Question q={q} table={tables.includes(q.id)} sql={sqls.includes(q.id)} onTable={(on) => toggleTable(q.id, on)} onSql={(on) => toggleSql(q.id, on)} />
            ) : (
              <EmptyState
                title={`${meta.id.toUpperCase()} is not in this data release`}
                body="The analysis step writes each question into the manifest; this one has not been computed yet."
                action={{ label: "Open the data page", href: "/app/data" }}
              />
            )}
          </Region>
        );
      })}
      <p className="mt-xl text-app-sm text-fg-2">
        Filer scores are labels from parties with incentives, NVD labels after April 2026 are a selected sample, and KEV is a lower bound.{" "}
        <Link href="/app/limits">The limits page says what each chart cannot show.</Link>
      </p>
    </>
  );
}
