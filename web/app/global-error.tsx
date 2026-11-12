"use client";

import "./globals.css";
import { STATEMENT } from "@/lib/statement";

/** Replaces the whole document when the root layout itself fails, so it carries the statement on its own. */
export default function GlobalError({ reset }: { error: Error; reset: () => void }) {
  return (
    <html lang="en">
      <body>
        <main className="container design">
          <header className="design__head">
            <h1>This page failed while loading</h1>
            <p className="lead">Try again. If it fails twice, the status page says which part is down.</p>
          </header>
          <p className="flex flex-wrap gap-sm">
            <button type="button" className="key key--primary key--lg" onClick={() => reset()}>
              Try again
            </button>
            <a href="/status" className="key key--lg">
              Open the status page
            </a>
          </p>
          <p className="mt-2xl max-w-[75ch] text-app-sm text-fg-2">{STATEMENT}</p>
        </main>
      </body>
    </html>
  );
}
