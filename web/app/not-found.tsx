import Link from "next/link";
import { Mast } from "@/components/site/mast";
import { SiteNav } from "@/components/site/site-nav";

export default function NotFound() {
  return (
    <div className="site">
      <SiteNav banner={<span>A portfolio demonstration with a fictional customer, not affiliated with NIST or the NVD.</span>} />
      <main id="main" className="container design">
        <header className="design__head">
          <h1>No page at this address</h1>
          <p className="lead">The link may be old or mistyped. A CVE lives at /app/cves/ followed by its id.</p>
        </header>
        <p className="flex flex-wrap gap-sm">
          <Link href="/app" className="key key--primary key--lg">
            Look up a CVE
          </Link>
          <Link href="/" className="key key--lg">
            Back to the start
          </Link>
        </p>
      </main>
      <Mast />
    </div>
  );
}
