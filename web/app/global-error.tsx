"use client";

import { STATEMENT } from "@/lib/statement";

export default function GlobalError({ reset }: { error: Error; reset: () => void }) {
  return (
    <html lang="en">
      <body>
        <main style={{ maxWidth: "70ch", margin: "64px auto", padding: "0 16px", lineHeight: 1.5 }}>
          <h1>Something broke on this page</h1>
          <p>The page failed while loading. Try again; if it fails twice, the status page says which part is down.</p>
          <button type="button" onClick={() => reset()}>Try again</button>
          <p>{STATEMENT}</p>
        </main>
      </body>
    </html>
  );
}
