"use client";

import { SearchIcon } from "lucide-react";
import { parseAsString, useQueryState } from "nuqs";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useSearch } from "@/lib/api/queries";
import { formatDate, isoDay } from "@/lib/format";
import { PageHead } from "./page-head";
import { QueryRegion, Region, SkeletonLines } from "./region";

export function AdvisorySearch() {
  const yesterday = isoDay(new Date(Date.now() - 86_400_000));
  const [q, setQ] = useQueryState("q", parseAsString.withDefault(""));
  const [asOf, setAsOf] = useQueryState("as_of", parseAsString.withDefault(yesterday));
  const [draft, setDraft] = useState(q);
  const [day, setDay] = useState(asOf);
  const search = useSearch(q, asOf, q.trim().length > 0);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void setQ(draft.trim() || null);
    void setAsOf(day || null);
  }

  return (
    <>
      <PageHead title="Advisory search">
        The advisory corpus as it was known at the end of a day: GitHub and OSV advisories for the products&apos; CVEs, every KEV entry and every CWE weakness. A version
        published after that day is not searched.
      </PageHead>
      <Region id="query" title="Search">
        <form className="run-form" onSubmit={submit} role="search">
          <div className="run-form__field run-form__field--wide">
            <Label htmlFor="advisory-q">Words</Label>
            <Input id="advisory-q" value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="deserialization in a logging library" maxLength={2000} />
          </div>
          <div className="run-form__field">
            <Label htmlFor="advisory-as-of">As of</Label>
            <Input id="advisory-as-of" type="date" value={day} max={yesterday} onChange={(e) => setDay(e.target.value)} />
          </div>
          <Button type="submit">
            <SearchIcon aria-hidden="true" />
            Search
          </Button>
        </form>
      </Region>
      {q ? (
        <Region id="results" title={`What was known on ${formatDate(asOf)}`} note="Ranked by the lexical floor until the retrieval evaluation freezes a configuration">
          <QueryRegion
            query={search}
            what="The search"
            loading={<SkeletonLines lines={6} />}
            isEmpty={(d) => d.results.length === 0}
            empty={{ title: "Nothing known then matches", body: `No chunk of an advisory version known by the end of ${formatDate(asOf)} holds these words. A later day may.` }}
          >
            {(d) => (
              <ol className="hits">
                {d.results.map((h) => (
                  <li key={h.chunk_id}>
                    <figure className="untrusted">
                      <figcaption>
                        <span className="mono">{h.doc_id}</span>, {h.sections.join(", ")}, version <span className="mono">{h.version}</span>, known from{" "}
                        {formatDate(h.known_from)}. Score <span className="num">{h.score.toFixed(3)}</span>. Untrusted text: data from an advisory anyone can write.
                      </figcaption>
                      <blockquote>{h.text}</blockquote>
                    </figure>
                  </li>
                ))}
              </ol>
            )}
          </QueryRegion>
        </Region>
      ) : null}
    </>
  );
}
