"use client";

import type { UseQueryResult } from "@tanstack/react-query";
import { CircleDashedIcon, OctagonAlertIcon, RefreshCwIcon } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { describeError } from "@/lib/api/client";

/** A ruled region: one head, then a body that is loading, empty, in error or full. */
export function Region({ id, title, note, tools, children }: { id?: string; title: string; note?: ReactNode; tools?: ReactNode; children: ReactNode }) {
  const headingId = id ? `${id}-title` : undefined;
  return (
    <section className="region" id={id} aria-labelledby={headingId}>
      <div className="region__head">
        <div>
          <h2 id={headingId}>{title}</h2>
          {note ? <p>{note}</p> : null}
        </div>
        {tools ? <div className="region__tools">{tools}</div> : null}
      </div>
      {children}
    </section>
  );
}

export type EmptySpec = { title: string; body: string; action?: { label: string; href?: string; onClick?: () => void } };

export function EmptyState({ title, body, action }: EmptySpec) {
  return (
    <div className="well state" data-kind="empty">
      <h3>
        <CircleDashedIcon aria-hidden="true" />
        {title}
      </h3>
      <p>{body}</p>
      {action ? (
        <div className="state__actions">
          {action.href ? (
            <Button asChild size="sm">
              <Link href={action.href}>{action.label}</Link>
            </Button>
          ) : (
            <Button size="sm" onClick={action.onClick}>
              {action.label}
            </Button>
          )}
        </div>
      ) : null}
    </div>
  );
}

export function ErrorState({ error, onRetry, what, compact = false }: { error: unknown; onRetry?: () => void; what: string; compact?: boolean }) {
  const e = describeError(error);
  return (
    <div className="well state" data-kind="error" role="alert" aria-label={`${what}: ${e.title}`}>
      <h3>
        <OctagonAlertIcon aria-hidden="true" />
        {e.title}
      </h3>
      {compact ? null : <p>{e.body}</p>}
      {e.detail ? <p className="state__detail mono">{e.detail}</p> : null}
      <div className="state__actions">
        {e.retry && onRetry ? (
          <Button size="sm" onClick={onRetry}>
            <RefreshCwIcon aria-hidden="true" />
            Try again
          </Button>
        ) : null}
        <Button asChild size="sm" variant="quiet">
          <Link href="/status">Open the status page</Link>
        </Button>
      </div>
    </div>
  );
}

export function Loading({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div aria-busy="true">
      <span className="visually-hidden" role="status">
        Loading {label}
      </span>
      {children}
    </div>
  );
}

/** Rows and columns of placeholders, the shape of the table that is coming. */
export function SkeletonTable({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="grid gap-sm" aria-hidden="true">
      <div className="grid gap-md" style={{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }}>
        {Array.from({ length: cols }, (_, c) => (
          <Skeleton key={c} className="h-3 w-1/2" />
        ))}
      </div>
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="grid gap-md border-t border-line pt-sm" style={{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }}>
          {Array.from({ length: cols }, (_, c) => (
            <Skeleton key={c} className={c === 0 ? "h-4 w-4/5" : "h-4 w-3/5"} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function SkeletonLines({ lines = 4 }: { lines?: number }) {
  return (
    <div className="grid gap-sm" aria-hidden="true">
      {Array.from({ length: lines }, (_, i) => (
        <Skeleton key={i} className={i % 3 === 2 ? "h-4 w-2/5" : "h-4 w-4/5"} />
      ))}
    </div>
  );
}

export function SkeletonChart() {
  return (
    <div className="grid gap-sm" aria-hidden="true">
      <Skeleton className="h-4 w-3/5" />
      <div className="grid h-[220px] grid-rows-4 border-b border-line-strong">
        {Array.from({ length: 4 }, (_, i) => (
          <span key={i} className="border-t border-line" />
        ))}
      </div>
      <Skeleton className="h-3 w-2/5" />
    </div>
  );
}

/** The four states of one region that reads one query. */
export function QueryRegion<T>({
  query,
  what,
  loading,
  isEmpty,
  empty,
  compact,
  children,
}: {
  query: UseQueryResult<T>;
  what: string;
  loading: ReactNode;
  isEmpty?: (data: T) => boolean;
  empty: EmptySpec;
  compact?: boolean;
  children: (data: T) => ReactNode;
}) {
  if (query.isPending) return <Loading label={what}>{loading}</Loading>;
  if (query.isError) return <ErrorState error={query.error} what={what} compact={compact} onRetry={() => void query.refetch()} />;
  if (isEmpty?.(query.data)) return <EmptyState {...empty} />;
  return <>{children(query.data)}</>;
}
