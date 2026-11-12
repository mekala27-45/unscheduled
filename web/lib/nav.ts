/** The console's built destinations, in sidebar order. A destination is listed only once it is built. */
export type Destination = {
  href: string;
  label: string;
  /** Second key after g, from section 15: c, b, p, m or d. */
  go?: "c" | "b" | "p" | "m" | "d";
  summary: string;
};

export const DESTINATIONS: Destination[] = [
  { href: "/app", label: "Search", summary: "Look up a CVE; the newest in the release" },
  { href: "/app/cves", label: "CVEs", go: "c", summary: "Every CVE, filtered in the address bar" },
  { href: "/app/backlog", label: "Backlog", go: "b", summary: "Q1 to Q6, what the NVD no longer analyzes" },
  { href: "/app/products", label: "Products", go: "p", summary: "The stand-in products and their exposure" },
  { href: "/app/match", label: "Match", go: "m", summary: "Match an SBOM; only its digest is kept" },
  { href: "/app/data", label: "Data", go: "d", summary: "Sources, licences, locks, freshness" },
  { href: "/app/criteria", label: "Criteria", summary: "C1 to C9, signed before any result" },
  { href: "/status", label: "Status", summary: "Health and freshness per source, live" },
  { href: "/app/limits", label: "Limits", summary: "What a security or data lead would question" },
];

export const REPO_URL = "https://github.com/mekala27-45/unscheduled";

export function isCurrent(pathname: string, href: string): boolean {
  if (href === "/app") return pathname === "/app";
  return pathname === href || pathname.startsWith(`${href}/`);
}
