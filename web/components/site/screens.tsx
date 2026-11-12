"use client";

import Link from "next/link";
import { useRef, useState, type KeyboardEvent } from "react";
import type { Screen, ScreenName } from "@/lib/build-data";

const MOMENTS: { name: ScreenName; label: string; caption: string; href: string; open: string }[] = [
  { name: "ruler", label: "The ruler", caption: "One CVE's events in real time", href: "/app/cves", open: "Open a CVE" },
  { name: "backlog", label: "The backlog", caption: "Six questions, with tables and SQL", href: "/app/backlog", open: "Open the backlog" },
  { name: "exposure", label: "The exposure", caption: "Findings by NVD status", href: "/app/products", open: "Open the products" },
  { name: "match", label: "The match", caption: "An SBOM in, findings out", href: "/app/match", open: "Open the match" },
];

/**
 * Four named moments behind a tray of keys, each a capture of the console. Until the first capture
 * exists the moments are an index with a link to each live screen, never four empty frames. Without
 * script every panel shows, in order.
 */
export function Screens({ screens }: { screens: Record<ScreenName, Screen> }) {
  const [active, setActive] = useState<ScreenName>("ruler");
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  if (!MOMENTS.some((m) => screens[m.name].light)) {
    return (
      <ol className="moments" aria-label="Four screens from the console">
          {MOMENTS.map((m) => (
            <li key={m.name}>
              <Link href={m.href} className="moments__name">
                {m.label}
              </Link>
              <p>{m.caption}</p>
            </li>
        ))}
      </ol>
    );
  }

  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = MOMENTS.findIndex((m) => m.name === active);
    const next = e.key === "ArrowRight" ? (i + 1) % MOMENTS.length : e.key === "ArrowLeft" ? (i - 1 + MOMENTS.length) % MOMENTS.length : -1;
    if (next < 0) return;
    e.preventDefault();
    setActive(MOMENTS[next].name);
    tabs.current[next]?.focus();
  };

  return (
    <div>
      <div className="tray screens__tabs" role="tablist" aria-label="Console screens" onKeyDown={onKey}>
        {MOMENTS.map((m, i) => (
          <button
            key={m.name}
            ref={(el) => {
              tabs.current[i] = el;
            }}
            type="button"
            role="tab"
            id={`tab-${m.name}`}
            aria-selected={active === m.name}
            aria-controls={`panel-${m.name}`}
            tabIndex={active === m.name ? 0 : -1}
            className="key"
            onClick={() => setActive(m.name)}
          >
            {m.label}
          </button>
        ))}
      </div>
      {MOMENTS.map((m) => {
        const shot = screens[m.name];
        return (
          <section
            key={m.name}
            id={`panel-${m.name}`}
            role="tabpanel"
            aria-labelledby={`tab-${m.name}`}
            className="screens__panel"
            data-active={active === m.name}
          >
            {shot.light ? (
              <figure className="shot">
                <img className="shot__light" src={shot.light} width={shot.width} height={shot.height} alt={`${m.label} in the console`} loading="lazy" />
                {shot.dark ? <img className="shot__dark" src={shot.dark} width={shot.width} height={shot.height} alt={`${m.label} in the console`} loading="lazy" /> : null}
                <figcaption className="chart-source">{m.caption}</figcaption>
              </figure>
            ) : (
              <div className="slot">
                <strong>{m.label}</strong>
                <p>{m.caption}</p>
                <p className="text-fg-muted">
                  The screenshot is taken from the live console once the first data release is loaded. Until then the screen itself shows its empty
                  state. <Link href={m.href}>{m.open}</Link>
                </p>
              </div>
            )}
          </section>
        );
      })}
    </div>
  );
}
