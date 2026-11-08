import { NVD_NOTICE, STATEMENT } from "@/lib/statement";

export default function Home() {
  return (
    <main style={{ maxWidth: "70ch", margin: "64px auto", padding: "0 16px", lineHeight: 1.5 }}>
      <h1>unscheduled</h1>
      <p>Triage for the CVEs the NVD no longer analyzes. The product is being built; this page is the
        first deploy.</p>
      <p>{STATEMENT}</p>
      <p>{NVD_NOTICE}</p>
    </main>
  );
}
