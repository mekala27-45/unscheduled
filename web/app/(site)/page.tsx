import type { Metadata } from "next";
import Link from "next/link";
import { BeforeAfter } from "@/components/site/before-after";
import { HeroField } from "@/components/site/hero-field";
import { LookupForm } from "@/components/site/lookup-form";
import { Mast } from "@/components/site/mast";
import { Reads } from "@/components/site/reads";
import { RulerKey } from "@/components/site/ruler-key";
import { Screens } from "@/components/site/screens";
import { SiteNav } from "@/components/site/site-nav";
import { SystemMap } from "@/components/site/system-map";
import { readField, readLocks, readManifest, readScreens } from "@/lib/build-data";
import { NODES } from "@/lib/system-map";

export const metadata: Metadata = {
  title: { absolute: "unscheduled: triage for the CVEs the NVD no longer analyzes" },
  description: "What each source published about every CVE, dated, and matched against SBOMs. A portfolio demonstration with a fictional customer.",
};

export default function Landing() {
  const field = readField();
  const manifest = readManifest();
  const locks = readLocks();
  const screens = readScreens();

  return (
    <div className="site">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <SiteNav
        banner={
          <>
            <span>A portfolio demonstration with a fictional customer, not affiliated with NIST or the NVD.</span>
            <a href="#statement">Read the statement</a>
          </>
        }
      />
      <main id="main" tabIndex={-1}>
        <section className="hero" aria-labelledby="hero-title">
          <div className="container">
            <div className="hero__text">
              <h1 id="hero-title">The CVEs the NVD no longer analyzes</h1>
              <p className="lead">What each source published on every CVE, dated and matched to SBOMs.</p>
              <div className="hero__actions">
                <Link href="/app" className="key key--primary key--lg">
                  Look up a CVE
                </Link>
                <a href="#map" className="key key--lg">
                  See how it is built
                </a>
              </div>
            </div>
            <HeroField field={field} />
          </div>
        </section>

        <section id="map" className="sec sec--wide sec--rule" aria-labelledby="map-title">
          <div className="container">
            <div className="sec__head">
              <h2 id="map-title">Nine sources in, one dated record out</h2>
              <p className="lead">Solid is built this week; dashed comes later. Each name opens its page.</p>
            </div>
            <SystemMap />
            <ol className="map-list" aria-label="The system, in order">
              {NODES.map((n) => (
                <li key={n.id} data-later={n.week ? "true" : undefined}>
                  <strong>{n.week ? `Week ${n.week}: ${n.title}` : n.title}</strong>
                  <span>
                    {n.line}
                    {n.week ? ", not built yet" : ""}
                    {n.href ? (
                      <>
                        {". "}
                        <Link href={n.href}>{n.linkText}</Link>
                      </>
                    ) : null}
                  </span>
                </li>
              ))}
            </ol>

          </div>
        </section>

        <section className="sec" aria-labelledby="reads-title">
          <div className="container">
            <div className="sec__head">
              <h2 id="reads-title">Nine sources, each locked by digest</h2>
            </div>
            <Reads locks={locks} manifest={manifest} />
          </div>
        </section>

        <section className="sec sec--rule" aria-labelledby="screens-title">
          <div className="container">
            <div className="sec__head">
              <h2 id="screens-title">Four screens from the console</h2>
              <p className="lead">Live now; captures come with the first data.</p>
            </div>
            <Screens screens={screens} />
          </div>
        </section>

        <section className="sec sec--wide" aria-labelledby="ba-title">
          <div className="container">
            <div className="sec__head">
              <h2 id="ba-title">What a CPE matcher cannot see</h2>
              <p className="lead">No NVD analysis, no CPE, so no finding.</p>
            </div>
            <BeforeAfter />
          </div>
        </section>

        <section className="sec sec--rule closer" aria-labelledby="close-title">
          <div className="container">
            <div>
              <h2 id="close-title">Start from one CVE id</h2>
              <LookupForm />
            </div>
            {screens.ruler.light ? (
              <figure className="shot">
                <img className="shot__light" src={screens.ruler.light} width={screens.ruler.width} height={screens.ruler.height} alt="The ruler for one CVE in the console" loading="lazy" />
                {screens.ruler.dark ? <img className="shot__dark" src={screens.ruler.dark} width={screens.ruler.width} height={screens.ruler.height} alt="The ruler for one CVE in the console" loading="lazy" /> : null}
              </figure>
            ) : (
              <RulerKey />
            )}
          </div>
        </section>
      </main>
      <Mast />
    </div>
  );
}
