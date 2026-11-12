"use client";

import { MenuIcon } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { REPO_URL } from "@/lib/nav";

const LINKS = [
  { href: "/app", label: "Console" },
  { href: "/status", label: "Status" },
  { href: "/design", label: "Design system" },
];

/**
 * A banner over a bar that retracts on scroll: the bar slides away while the reader scrolls down and
 * returns on the way up or when anything in it takes focus. Without script it simply stays.
 */
export function SiteNav({ banner }: { banner: ReactNode }) {
  const [hidden, setHidden] = useState(false);
  const bar = useRef<HTMLElement>(null);

  useEffect(() => {
    let last = window.scrollY;
    let ticking = false;
    const onScroll = () => {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(() => {
        const y = window.scrollY;
        // A scroll event that did not move the page (the end of a fling, the foot of the page)
        // says nothing about direction, so it leaves the bar as it is.
        if (y !== last) {
          const focused = bar.current?.contains(document.activeElement);
          setHidden(!focused && y > last && y > 160);
          last = y;
        }
        ticking = false;
      });
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <>
      <div className="site-banner">
        <div className="container">{banner}</div>
      </div>
      <header ref={bar} className="site-bar" data-hidden={hidden} onFocusCapture={() => setHidden(false)}>
        <div className="container">
          <Link href="/" className="wordmark" aria-label="unscheduled, home">
            <span className="wordmark__mark" aria-hidden="true" />
            unscheduled
          </Link>
          <nav className="site-links" aria-label="Main">
            {LINKS.map((l) => (
              <Link key={l.href} href={l.href}>
                {l.label}
              </Link>
            ))}
            <a href={REPO_URL}>GitHub</a>
            <Link href="/app" className="key">
              Look up a CVE
            </Link>
          </nav>
          <details className="site-menu">
            <summary className="key key--icon" aria-label="Menu">
              <MenuIcon aria-hidden="true" />
            </summary>
            <nav className="site-menu__panel" aria-label="Main">
              <Link href="/app">Look up a CVE</Link>
              {LINKS.map((l) => (
                <Link key={l.href} href={l.href}>
                  {l.label}
                </Link>
              ))}
              <a href={REPO_URL}>GitHub</a>
            </nav>
          </details>
        </div>
      </header>
    </>
  );
}
