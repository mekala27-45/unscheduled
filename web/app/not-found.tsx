import { STATEMENT } from "@/lib/statement";

export default function NotFound() {
  return (
    <main style={{ maxWidth: "70ch", margin: "64px auto", padding: "0 16px", lineHeight: 1.5 }}>
      <h1>Page not found</h1>
      <p>There is no page at this address. Go back to the start page and search from there.</p>
      <p>{STATEMENT}</p>
    </main>
  );
}
