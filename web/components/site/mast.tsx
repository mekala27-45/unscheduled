import Link from "next/link";
import { GHSA_ATTRIBUTION, NVD_NOTICE, STATEMENT } from "@/lib/statement";
import { formatDate } from "@/lib/format";
import { REPO_URL } from "@/lib/nav";

/**
 * The statement printed so the NVD notice stands as its own line while the full statement stays one
 * unbroken run of text for the statement gate. If the statement ever stops ending with the notice,
 * both are printed whole.
 */
function statementParts(): { body: string; notice: string } {
  if (STATEMENT.endsWith(NVD_NOTICE)) return { body: STATEMENT.slice(0, STATEMENT.length - NVD_NOTICE.length).trim(), notice: NVD_NOTICE };
  return { body: STATEMENT, notice: NVD_NOTICE };
}

function Attribution() {
  const m = /\((https?:\/\/[^)]+)\)/.exec(GHSA_ATTRIBUTION);
  if (!m) return <p>{GHSA_ATTRIBUTION}</p>;
  const [before, after] = [GHSA_ATTRIBUTION.slice(0, m.index), GHSA_ATTRIBUTION.slice(m.index + m[0].length)];
  return (
    <p>
      {before}(<a href={m[1]}>{m[1]}</a>){after}
    </p>
  );
}

/** Both fixed at build time by next.config.ts, so the footer reads no file at request time. */
function freshness(): string {
  const asOf = process.env.UNSCHED_DATA_AS_OF ?? "";
  if (asOf === "unreadable") return "results/manifest.json is present but unreadable; no figure is shown from it";
  if (asOf) return `Data as of ${formatDate(asOf, "long")}, from results/manifest.json`;
  return "No data release is loaded yet";
}

const LINKS = [
  { href: "/app", label: "Console" },
  { href: "/report", label: "Report" },
  { href: "/docs", label: "Docs" },
  { href: "/status", label: "Status" },
  { href: "/app/limits", label: "Limits" },
  { href: "/design", label: "Design system" },
];

export function Mast({ variant = "page" }: { variant?: "page" | "app" }) {
  const { body, notice } = statementParts();
  const version = process.env.UNSCHED_WEB_VERSION ?? "unknown";
  if (variant === "app") {
    return (
      <footer className="mast-app" aria-label="Statement and sources">
        <div className="mast-app__grid">
          <div>
            <Link href="/" className="wordmark" aria-label="unscheduled, home">
              <span className="wordmark__mark" aria-hidden="true" />
              unscheduled
            </Link>
            <nav className="mast-app__links" aria-label="Footer">
              {LINKS.map((l) => (
                <Link key={l.href} href={l.href}>
                  {l.label}
                </Link>
              ))}
              <a href={REPO_URL}>GitHub</a>
            </nav>
          </div>
          <div className="mast-app__text" data-credits="notices">
            <p id="statement">{body} {notice}</p>
            <Attribution />
            <p className="mast-app__meta">
              <span>{freshness()}</span>
              <span>Web {version}</span>
            </p>
          </div>
        </div>
      </footer>
    );
  }
  return (
    <footer className="mast">
      <div className="container">
        <Link href="/" className="mast__word" aria-label="unscheduled, home">
          <span className="wordmark__mark" aria-hidden="true" />
          unscheduled
        </Link>
        <nav className="mast__links" aria-label="Footer">
          {LINKS.map((l) => (
            <Link key={l.href} href={l.href}>
              {l.label}
            </Link>
          ))}
          <a href={REPO_URL}>GitHub</a>
        </nav>
        <div className="mast__text">
          <div data-credits="notices">
            <p id="statement">{body}</p>
            <p>{notice}</p>
            <Attribution />
          </div>
          <dl className="mast__meta">
            <dt>Data</dt>
            <dd>{freshness()}</dd>
            <dt>Version</dt>
            <dd>Web {version}</dd>
          </dl>
        </div>
      </div>
    </footer>
  );
}
