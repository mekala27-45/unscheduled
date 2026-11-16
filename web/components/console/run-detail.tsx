"use client";

import { useQueryClient } from "@tanstack/react-query";
import { CheckIcon, XIcon } from "lucide-react";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { GRAPH_ORDER } from "@/lib/api/adapt";
import type { Draft, Run } from "@/lib/api/client";
import { useDecide, useRun } from "@/lib/api/queries";
import { formatDate, formatDateTime, formatInt, shortDigest } from "@/lib/format";
import { PageHead } from "./page-head";
import { ErrorState, QueryRegion, Region, SkeletonLines } from "./region";
import { RunStatus } from "./runs-view";
import { StatusText, type Tone } from "./status-text";

const DRAFT_STATUS: Record<string, { tone: Tone; label: string }> = {
  waiting: { tone: "warning", label: "Waits for a person" },
  approved: { tone: "good", label: "Approved by a person" },
  ready: { tone: "good", label: "Ready, approved by a person" },
  rejected: { tone: "serious", label: "Rejected by a person" },
  blocked: { tone: "critical", label: "Blocked by the verifier" },
  absent: { tone: "quiet", label: "Not drafted" },
};

const DRAFT_TITLE: Record<Draft["kind"], string> = { plan: "Draft patch plan", warning: "Draft early warning" };

const NODE_WORDS: Record<string, string> = {
  intake: "Read the CVE as known then",
  match: "Match a product and find the fix",
  fill: "Fill what the record lacks",
  rank: "Read the exploitation signals",
  retrieve: "Retrieve advisory chunks",
  plan: "Draft the patch plan",
  verify: "Check every claim of the plan",
  approve: "Wait for a person on the plan",
  warn: "Draft the early warning",
  verify_warning: "Check every claim of the warning",
  approve_warning: "Wait for a person on the warning",
  done: "Done",
};

/** The fields a claim can state, in the words of the page; the key stays in the API's answer. */
const CLAIM_FIELDS: Record<string, string> = {
  cve_id: "CVE",
  product: "Product",
  component: "Component",
  installed_version: "Installed version",
  fixed_version: "Fixed version",
  no_fixed_version: "No fixed version",
  action: "Action",
  vulnerability: "Vulnerability",
  exploitation_evidence: "Evidence of exploitation",
  exploitation: "Exploitation",
  member_states: "Member states",
};

const STATE_SECTIONS: Record<string, string> = {
  cve_id: "the CVE id",
  product: "the matched product",
  component: "the matched component",
  installed_version: "the installed version",
  fixed_versions: "the fixed versions found",
  exploits: "the exploit signals",
  kev: "the KEV listing",
  member_states: "the member states",
  description: "the CVE description",
};

const KIND_WORDS: Record<string, string> = { plan: "Patch plan", warning: "Early warning" };
const DECISION_WORDS: Record<string, string> = { approve: "Approve", reject: "Reject" };

const REASONS: Record<string, string> = {
  missing_source: "the cited source is not in the corpus",
  unknown_at_run_time: "the cited version was not known at the run time",
  no_such_section: "the cited section does not exist",
  not_in_source: "the value is not in the cited text",
  state_mismatch: "the value differs from the run's own state",
};

function usd(n: number): string {
  return n === 0 ? "0" : n < 0.0001 ? "<0.0001" : n.toFixed(4);
}

/** The API's note as a sentence: a capital first letter and a full stop. */
function sentence(s: string): string {
  const t = s.trim();
  if (!t) return t;
  const capital = t[0].toUpperCase() + t.slice(1);
  return /[.!?]$/.test(capital) ? capital : `${capital}.`;
}

/** A cited version in words: an advisory's modified time reads as a date, a catalog version as itself. */
function versionWords(v: string): string {
  return /^\d{4}-\d{2}-\d{2}T/.test(v) ? `the version of ${formatDate(v)}` : `version ${v}`;
}

/** Who wrote a draft, in words: the floor is the no model floor, anything else a model id. */
function writer(by: string): string {
  return by === "floor" ? "the no model floor" : by;
}

/** A drafting node's calls, tokens and shadow price, or nothing for a node that called no model. */
function callWords(n: { calls: number; tokens_in: number; tokens_out: number; shadow_usd: number }): string {
  if (!n.calls) return "";
  const calls = `${formatInt(n.calls)} ${n.calls === 1 ? "call" : "calls"}`;
  const tokens = n.tokens_in || n.tokens_out ? `${formatInt(n.tokens_in)} tokens in, ${formatInt(n.tokens_out)} tokens out` : "no tokens";
  return `; ${calls}, ${tokens}, shadow price ${usd(n.shadow_usd)} USD`;
}

function DraftStatus({ status }: { status: string }) {
  const s = DRAFT_STATUS[status] ?? { tone: "quiet" as Tone, label: status };
  return <StatusText tone={s.tone}>{s.label}</StatusText>;
}

/** The claims of a draft with their citations in words, and the verifier's result unless checks is false. */
export function ClaimsTable({ draft, checks = true, label }: { draft: Draft; checks?: boolean; label?: string }) {
  return (
    <Table className="claims" label={label ?? `The claims of the ${draft.kind === "plan" ? "plan" : "warning"}${checks ? " and their checks" : ""}`}>
      <TableHeader>
        <TableRow>
          <TableHead>Field</TableHead>
          <TableHead>Claim</TableHead>
          <TableHead>Cited</TableHead>
          {checks ? <TableHead>Check</TableHead> : null}
        </TableRow>
      </TableHeader>
      <TableBody>
        {draft.claims.map((c, i) => (
          <TableRow key={`${c.field}-${i}`}>
            <TableCell className="lead">{CLAIM_FIELDS[c.field] ?? c.field.replace(/_/g, " ")}</TableCell>
            <TableCell className="wrap">{c.text}</TableCell>
            <TableCell className="wrap">
              {c.citations.map((x, j) =>
                x.source === "state" ? (
                  <span key={j} className="block">
                    The run&apos;s own state: {STATE_SECTIONS[x.section] ?? x.section.replace(/_/g, " ")}
                  </span>
                ) : (
                  <span key={j} className="block">
                    <span className="mono">{x.source}</span>, section {x.section.replace(/_/g, " ")}
                    {x.version ? <span className="text-fg-muted"> ({versionWords(x.version)})</span> : null}
                  </span>
                ),
              )}
            </TableCell>
            {checks ? (
              <TableCell className="wrap">
                {c.failures.length ? (
                  <StatusText tone="critical">{c.failures.map((f) => REASONS[f] ?? f).join("; ")}</StatusText>
                ) : (
                  <StatusText tone="good">Holds in its source</StatusText>
                )}
              </TableCell>
            ) : null}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function DraftCard({ draft }: { draft: Draft }) {
  return (
    <article className="draft" aria-labelledby={`draft-${draft.kind}`}>
      <header className="draft__head">
        <h3 id={`draft-${draft.kind}`}>{DRAFT_TITLE[draft.kind]}</h3>
        <DraftStatus status={draft.status} />
      </header>
      <p className="draft__meta">
        Written by {draft.by === "floor" ? "the no model floor, from templates" : (draft.by ?? "an unnamed writer")}
        {draft.replacedByFloor ? "; the model's draft failed its checks, so the floor's replaced it" : ""}. {formatInt(draft.claimsVerified)} of{" "}
        {formatInt(draft.claimsDrafted)} claims hold
        {draft.claimsRemoved ? `, ${formatInt(draft.claimsRemoved)} removed` : ""}. Hash <span className="mono">{draft.sha256 ? shortDigest(draft.sha256, 16) : "none"}</span>
      </p>
      {draft.blocked ? (
        <p className="draft__blocked" role="note">
          The verifier blocked this draft: {draft.reasons.join("; ") || "a claim could not be held to its source"}. A blocked draft cannot be approved.
        </p>
      ) : null}
      {draft.fields.length ? (
        <dl className="facts draft__fields">
          {draft.fields.map((f) => (
            <div key={f.label} className="contents">
              <dt>{f.label}</dt>
              <dd className={f.label === "Installed" || f.label === "Fixed in" ? "mono" : undefined}>{f.value}</dd>
            </div>
          ))}
        </dl>
      ) : null}
      {draft.steps.length ? (
        <ol className="draft__steps">
          {draft.steps.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
      ) : null}
      <ClaimsTable draft={draft} />
    </article>
  );
}

function DecisionForm({ run }: { run: Run }) {
  const decide = useDecide();
  const client = useQueryClient();
  const [token, setToken] = useState("");
  const waiting = run.waiting;
  if (!waiting) return null;
  const draft = run.drafts.find((d) => d.kind === waiting.kind);

  async function send(decision: "approve" | "reject") {
    if (!waiting || !token) return;
    const body = { run_id: run.run_id, kind: waiting.kind, sha256: waiting.sha256, decision, by: "ajay" };
    const next = await decide.mutateAsync({ body, token }).catch(() => null);
    setToken("");
    if (next) client.setQueryData(["run", run.run_id], next);
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void send("approve");
  }

  return (
    <form className="decision" onSubmit={submit}>
      <p>
        The {waiting.kind === "plan" ? "patch plan" : "early warning"} waits for a person. A decision names the hash of the draft shown here,{" "}
        <span className="mono">{shortDigest(waiting.sha256, 16)}</span>, so a draft changed after it was shown counts for nothing.
        {draft?.blocked ? " This draft is blocked; approving it records nothing that counts." : ""}
      </p>
      <div className="decision__row">
        <div className="run-form__field">
          <Label htmlFor="approver-token">Approver token</Label>
          <Input
            id="approver-token"
            type="password"
            autoComplete="off"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            aria-describedby="approver-token-help"
          />
        </div>
        <Button type="submit" disabled={!token || decide.isPending}>
          <CheckIcon aria-hidden="true" />
          Approve this draft
        </Button>
        <Button type="button" variant="quiet" disabled={!token || decide.isPending} onClick={() => void send("reject")}>
          <XIcon aria-hidden="true" />
          Reject this draft
        </Button>
      </div>
      <p id="approver-token-help" className="run-form__help">
        Only the approver holds the token. The API keeps its hash, compares in constant time and logs neither; this page sends it once and forgets it. Without it, nothing
        is recorded.
      </p>
      {decide.isError ? <ErrorState error={decide.error} what="The decision" /> : null}
    </form>
  );
}

function Graph({ run }: { run: Run }) {
  const ran = new Map(run.nodes.map((n) => [n.name, n]));
  return (
    <ol className="graph" aria-label="The nodes of the triage graph, in order">
      {GRAPH_ORDER.map((name) => {
        const n = ran.get(name);
        return (
          <li key={name} className="graph__node" data-ran={n ? "true" : "false"}>
            <span className="graph__name mono">{name}</span>
            <span className="graph__words">{NODE_WORDS[name]}</span>
            {n ? (
              <span className="graph__cost num">
                {n.ms.toFixed(1)} ms
                {callWords(n)}
              </span>
            ) : (
              <span className="graph__cost text-fg-muted">not reached</span>
            )}
          </li>
        );
      })}
    </ol>
  );
}

function Facts({ run }: { run: Run }) {
  const f = run.facts;
  const rows: [string, string][] = [
    ["Product", f.product ?? "no stand-in product carries it"],
    ["Component", [f.ecosystem, f.component].filter(Boolean).join(" / ") || "not matched"],
    ["Installed", f.installed ?? "not known"],
    ["Fixed in", f.fixed.length ? f.fixed.map((x) => `${x.version} (${x.source})`).join(", ") : "no advisory known then gives one"],
    ["KEV", f.kev ? `listed${f.kev.date_added ? ` on ${formatDate(f.kev.date_added)}` : ""}${f.kev.name ? `, ${f.kev.name}` : ""}` : "not listed by then"],
    ["Exploit code", f.exploits.length ? f.exploits.map((x) => `${x.source}, ${formatDate(x.first_seen)}`).join("; ") : "none seen by then"],
    ["EPSS", f.epss != null ? f.epss.toFixed(3) : "no score known then"],
  ];
  return (
    <>
      <dl className="facts">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
      {f.evidence.length ? (
        <div className="evidence">
          <h3>Retrieved advisory text, best first</h3>
          {f.evidence.map((e) => (
            <figure key={e.chunk_id} className="untrusted">
              <figcaption>
                <span className="mono">{e.doc_id}</span>, {e.sections.join(", ")}, known from {formatDate(e.known_from)}. Untrusted text: data from an advisory anyone can
                write.
              </figcaption>
              <blockquote>{e.text}</blockquote>
            </figure>
          ))}
        </div>
      ) : (
        <p className="text-app-sm text-fg-2">No advisory chunk known by the run time matched the CVE&apos;s description.</p>
      )}
    </>
  );
}

function Decisions({ run }: { run: Run }) {
  if (!run.decisions.length) return <p className="text-app-sm text-fg-2">No decision is recorded for this run.</p>;
  return (
    <Table label="Every decision recorded for this run">
      <TableHeader>
        <TableRow>
          <TableHead>Draft</TableHead>
          <TableHead>Decision</TableHead>
          <TableHead>On the hash</TableHead>
          <TableHead>By</TableHead>
          <TableHead>At</TableHead>
          <TableHead>Token</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {run.decisions.map((d, i) => (
          <TableRow key={i}>
            <TableCell>{KIND_WORDS[d.kind] ?? d.kind}</TableCell>
            <TableCell>{DECISION_WORDS[d.decision] ?? d.decision}</TableCell>
            <TableCell className="mono">{shortDigest(d.sha256, 16)}</TableCell>
            <TableCell>{d.by}</TableCell>
            <TableCell>{formatDateTime(d.at)}</TableCell>
            <TableCell>{d.token_ok ? <StatusText tone="good">Matched</StatusText> : <StatusText tone="critical">Did not match, counts for nothing</StatusText>}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function RunBody({ run }: { run: Run }) {
  const writers = [...new Set(run.drafts.map((d) => d.by).filter((b): b is string => Boolean(b)))].map(writer);
  const spent = `${formatInt(run.cost.tokens_in + run.cost.tokens_out)} tokens, ${usd(run.cost.shadow_usd)} USD at list price.`;
  return (
    <>
      <PageHead
        title={`Run ${run.run_id.slice(0, 12)}`}
        meta={
          <>
            {run.cve_id ? (
              <Link href={`/app/cves/${run.cve_id}`} className="mono">
                {run.cve_id}
              </Link>
            ) : null}
            <span>as known on {formatDate(run.as_of)}</span>
            <RunStatus status={run.status} />
          </>
        }
      >
        {run.note ? `${sentence(run.note)} ${spent}` : `Drafted by ${writers.join(" and ") || "nobody yet"}. ${spent}`}
      </PageHead>
      <p className="untrusted-note" role="note">
        {run.untrusted}
      </p>
      {run.waiting ? (
        <Region id="decision" title="What waits for a person" note="Approving records a decision; nothing here applies a plan or files a warning">
          <DecisionForm run={run} />
        </Region>
      ) : null}
      <Region id="drafts" title="The drafts" note="Drafts until a person approves them by hash">
        {run.drafts.length ? run.drafts.map((d) => <DraftCard key={d.kind} draft={d} />) : <p className="text-app-sm text-fg-2">This run drafted nothing it kept.</p>}
      </Region>
      <Region id="graph" title="The graph" note="Each node with its time; the drafting nodes with their calls, tokens and shadow price from the locked book">
        <Graph run={run} />
      </Region>
      <Region id="facts" title="What the run read" note="Every value as it was known at the run time, never later">
        <Facts run={run} />
      </Region>
      <Region id="decisions" title="Decisions recorded" note="Only ever added; a decision without the token is kept and counts for nothing">
        <Decisions run={run} />
      </Region>
    </>
  );
}

export function RunDetail({ id }: { id: string }) {
  const run = useRun(id);
  return (
    <QueryRegion
      query={run}
      what={`Run ${id.slice(0, 12)}`}
      loading={<SkeletonLines lines={8} />}
      empty={{ title: "No such run", body: "The API has no run with this id.", action: { label: "Back to the runs", href: "/app/runs" } }}
    >
      {(r) => <RunBody run={r} />}
    </QueryRegion>
  );
}
