"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { parseAsString, useQueryState } from "nuqs";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import type { CveQuery, CveSummary } from "@/lib/api/client";
import { useCveList, useHealth } from "@/lib/api/queries";
import { normalizeCveId, normalizeCweId } from "@/lib/cve";
import { formatDate } from "@/lib/format";
import { PageHead } from "./page-head";
import { QueryRegion, SkeletonLines } from "./region";
import { StatusText } from "./status-text";

/** The UTC day n days before the given one, as YYYY-MM-DD. */
function daysBefore(day: string, n: number): string {
  return new Date(Date.parse(`${day}T00:00:00Z`) - n * 86_400_000).toISOString().slice(0, 10);
}

function CveList({ items, empty }: { items: CveSummary[]; empty: string }) {
  if (items.length === 0) return <p className="text-app-sm text-fg-muted">{empty}</p>;
  return (
    <ul className="grid">
      {items.map((c) => (
        <li key={c.id} className="grid gap-3xs border-t border-line py-xs">
          <Link href={`/app/cves/${c.id}`} className="mono text-app-sm text-fg">
            {c.id}
          </Link>
          <span className="text-app-xs text-fg-muted">
            {c.filer}, {c.nvd_status ?? "no NVD status"}
            {c.kev_listed ? ", " : ""}
            {c.kev_listed ? <StatusText tone="critical">in KEV</StatusText> : null}
          </span>
        </li>
      ))}
    </ul>
  );
}

function Column({ title, query, empty }: { title: string; query: CveQuery; empty: string }) {
  const q = useCveList({ ...query, limit: 12 });
  return (
    <section aria-labelledby={`h-${title}`} className="min-w-0">
      <h3 id={`h-${title}`} className="mb-sm font-sans text-app-md font-medium tracking-normal">
        {title}
      </h3>
      <QueryRegion query={q} what={title} compact loading={<SkeletonLines lines={5} />} empty={{ title: "", body: "" }}>
        {(d) => <CveList items={d.items} empty={empty} />}
      </QueryRegion>
    </section>
  );
}

/** The console home: a search field set large, then what is newest in the loaded release. No greeting, no stat cards. */
export function SearchHome() {
  const router = useRouter();
  const [q] = useQueryState("q", parseAsString);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const health = useHealth();
  const cut = health.data?.generated_at ? health.data.generated_at.slice(0, 10) : null;

  useEffect(() => {
    if (!q) return;
    const id = normalizeCveId(q);
    if (id) router.replace(`/app/cves/${id}`);
    else {
      setValue(q);
      setError("That is not a CVE id. Write it as CVE, the year and the number, for example CVE-YYYY-NNNNN.");
    }
  }, [q, router]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const id = normalizeCveId(value);
    if (id) return router.push(`/app/cves/${id}`);
    const cwe = normalizeCweId(value);
    if (cwe) return router.push(`/app/cves?cwe=${cwe}`);
    setError("That is not a CVE id or a CWE. Write a CVE as CVE-YYYY-NNNNN and a CWE as CWE-79.");
  };

  const queries = useMemo(() => {
    if (!cut) return [];
    const day = daysBefore(cut, 1);
    const week = daysBefore(cut, 7);
    return [
      { title: `Published since ${formatDate(day)}`, query: { published_from: day }, empty: "No CVE was published in those days." },
      { title: `Added to KEV since ${formatDate(week)}`, query: { kev_added_from: week }, empty: "CISA added no CVE to KEV in that week." },
      { title: `Analyzed by the NVD since ${formatDate(day)}`, query: { analyzed_from: day }, empty: "The NVD analyzed no CVE in those days." },
    ];
  }, [cut]);

  return (
    <>
      <PageHead title="Search">Look up any CVE with its full history, or filter the table by a CWE.</PageHead>
      <form onSubmit={submit} className="mb-2xl grid max-w-[44rem] gap-xs" role="search" aria-label="Look up a CVE">
        <label htmlFor="lookup" className="label">
          CVE id or CWE
        </label>
        <div className="flex gap-xs">
          <input
            id="lookup"
            data-search
            className="field field--lg field--mono"
            name="q"
            type="search"
            autoComplete="off"
            spellCheck={false}
            placeholder="CVE-YYYY-NNNNN"
            value={value}
            aria-invalid={error ? true : undefined}
            aria-describedby="lookup-help"
            onChange={(e) => {
              setValue(e.target.value);
              setError(null);
            }}
          />
          <Button type="submit" variant="primary" className="min-h-[52px] px-lg">
            Look up
          </Button>
        </div>
        <p id="lookup-help" className="help" data-tone={error ? "error" : undefined} aria-live="polite">
          {error ?? "Press / from anywhere in the console to come back to this field."}
        </p>
      </form>
      <section className="region" aria-labelledby="last-24">
        <div className="region__head">
          <div>
            <h2 id="last-24">The newest in this data release</h2>
            <p>{cut ? `Counted back from ${formatDate(cut, "long")}, the day the release was built, in UTC.` : "Counted back from the day the data release was built, in UTC."}</p>
          </div>
        </div>
        <div className="grid grid-cols-1 gap-xl wide:grid-cols-3">
          {health.data && !cut ? (
            <p className="text-app-sm text-fg-muted wide:col-span-3">No data release is loaded yet, so there is nothing new to list. The status page says when the API last synced.</p>
          ) : queries.length === 0 ? (
            ["Newly published", "Newly listed in KEV", "Newly analyzed by the NVD"].map((t) => (
              <section key={t} className="min-w-0">
                <h3 className="mb-sm font-sans text-app-md font-medium tracking-normal">{t}</h3>
                <SkeletonLines lines={5} />
              </section>
            ))
          ) : (
            queries.map((c) => <Column key={c.title} title={c.title} query={c.query} empty={c.empty} />)
          )}
        </div>
      </section>
    </>
  );
}
