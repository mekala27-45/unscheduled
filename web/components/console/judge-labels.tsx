"use client";

import { useQueryClient } from "@tanstack/react-query";
import { ThumbsDownIcon, ThumbsUpIcon } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { LabelDraft, LabelList } from "@/lib/api/client";
import { useLabel, useLabels } from "@/lib/api/queries";
import { formatDate, formatDateTime, formatInt, shortDigest } from "@/lib/format";
import { ErrorState, QueryRegion, SkeletonLines } from "./region";
import { ClaimsTable } from "./run-detail";
import { StatusText } from "./status-text";

const REASON_MAX = 280;

function LabelStatus({ item }: { item: LabelDraft }) {
  if (!item.label) return <StatusText tone="quiet">Not labelled</StatusText>;
  return <StatusText tone={item.label.usable ? "good" : "serious"}>{item.label.usable ? "Labelled usable" : "Labelled not usable"}</StatusText>;
}

function LabelCard({ index, item, token }: { index: number; item: LabelDraft; token: string }) {
  const label = useLabel();
  const client = useQueryClient();
  const [reason, setReason] = useState("");
  const said = reason.trim();
  const id = `judge-${item.draft_id}`;

  async function send(usable: boolean) {
    if (!token || !said) return;
    const body = { draft_id: item.draft_id, sha256: item.sha256, usable, reason: said, by: "ajay" };
    const result = await label.mutateAsync({ body, token }).catch(() => null);
    if (!result) return;
    client.setQueryData<LabelList>(["labels"], (old) =>
      old ? { ...old, labelled: result.labelled, total: result.total, drafts: old.drafts.map((d) => (d.draft_id === result.draft.draft_id ? result.draft : d)) } : old,
    );
    setReason("");
  }

  return (
    <li className="judge-draft" aria-labelledby={id}>
      <header className="draft__head">
        <h3 id={id}>
          Draft {index}: {item.kind === "plan" ? "a patch plan" : "an early warning"} for <span className="mono">{item.cve_id}</span>
        </h3>
        <LabelStatus item={item} />
      </header>
      <p className="draft__meta">
        Written as known on {formatDate(item.as_of)}. Hash <span className="mono">{shortDigest(item.sha256, 16)}</span>
      </p>
      {item.draft.fields.length ? (
        <dl className="facts draft__fields">
          {item.draft.fields.map((f) => (
            <div key={f.label} className="contents">
              <dt>{f.label}</dt>
              <dd>{f.value}</dd>
            </div>
          ))}
        </dl>
      ) : null}
      {item.draft.steps.length ? (
        <ol className="draft__steps">
          {item.draft.steps.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
      ) : null}
      {item.draft.claims.length ? <ClaimsTable draft={item.draft} checks={false} label={`The claims of draft ${index}`} /> : null}
      {item.label ? (
        <p className="judge-draft__given">
          {item.label.by} said {item.label.usable ? "usable" : "not usable"} on {formatDateTime(item.label.at)}: {item.label.reason}
        </p>
      ) : null}
      <div className="judge-draft__form">
        <div className="run-form__field judge-draft__reason">
          <Label htmlFor={`${id}-reason`}>{item.label ? "A new label, and why" : "Why, in a sentence"}</Label>
          <Input id={`${id}-reason`} value={reason} maxLength={REASON_MAX} autoComplete="off" onChange={(e) => setReason(e.target.value)} />
        </div>
        <Button type="button" disabled={!token || !said || label.isPending} onClick={() => void send(true)}>
          <ThumbsUpIcon aria-hidden="true" />
          Usable
        </Button>
        <Button type="button" variant="quiet" disabled={!token || !said || label.isPending} onClick={() => void send(false)}>
          <ThumbsDownIcon aria-hidden="true" />
          Not usable
        </Button>
      </div>
      {label.isError ? <ErrorState error={label.error} what="The label" /> : null}
    </li>
  );
}

/**
 * The drafts the judge is calibrated against: forty development drafts, half from the floor and half
 * from the models, shown without what wrote each. Anyone can read them; a label needs the approver's
 * token, kept in this tab while it is open and sent in the header of each label.
 */
export function JudgeLabels() {
  const labels = useLabels();
  const [token, setToken] = useState("");
  return (
    <QueryRegion
      query={labels}
      what="The drafts to label"
      loading={<SkeletonLines lines={6} />}
      isEmpty={(d) => d.total === 0}
      empty={{
        title: "The drafts to label come with the agent evals",
        body: "The judge is calibrated against forty labels from Ajay. The drafts are cut from the development runs of the agent evals; until those run, there is nothing to label.",
      }}
    >
      {(d) => (
        <div className="judge">
          <p className="judge__progress">
            {formatInt(d.labelled)} of {formatInt(d.total)} labelled. Each draft is shown without the configuration that wrote it; the newest label on its hash is the one that
            counts.
          </p>
          <div className="judge__token">
            <div className="run-form__field">
              <Label htmlFor="judge-token">Approver token</Label>
              <Input id="judge-token" type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} aria-describedby="judge-token-help" />
            </div>
            <Button type="button" variant="quiet" disabled={!token} onClick={() => setToken("")}>
              Forget the token
            </Button>
            <p id="judge-token-help" className="run-form__help">
              Only the approver labels. The token stays in this tab while you label and goes in the header of each label; it is never stored, and leaving the page forgets it.
            </p>
          </div>
          <ol className="judge__drafts">
            {d.drafts.map((item, i) => (
              <LabelCard key={item.draft_id} index={i + 1} item={item} token={token} />
            ))}
          </ol>
        </div>
      )}
    </QueryRegion>
  );
}
