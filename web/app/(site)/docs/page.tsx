import type { Metadata } from "next";
import { DiagramFigure, DocList } from "@/components/site/doc-view";
import { Mast } from "@/components/site/mast";
import { SiteNav } from "@/components/site/site-nav";
import { architectureDiagram, DOC_SECTIONS, readDocs } from "@/lib/docs";

export const metadata: Metadata = {
  title: "Docs",
  description: "How unscheduled is built, the decisions behind it and how to run it, read from the repository.",
};

export default function DocsIndex() {
  const docs = readDocs();
  return (
    <div className="site">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <SiteNav banner={<span>Every page here is a file in the repository, rendered when this site was built.</span>} />
      <main id="main" tabIndex={-1} className="container docs">
        <div className="docs__head">
          <h1>Docs</h1>
          <p className="lead">How unscheduled is built, the decisions behind it and how to run it.</p>
        </div>
        <DiagramFigure diagram={architectureDiagram()} className="docs__diagram" />
        <div className="doc-groups">
          {DOC_SECTIONS.map((section) => {
            const inSection = docs.filter((d) => d.section === section);
            if (inSection.length === 0) return null;
            return (
              <section key={section} className="doc-group" aria-labelledby={`group-${section.replace(/\W+/g, "-")}`}>
                <h2 id={`group-${section.replace(/\W+/g, "-")}`}>{section}</h2>
                <DocList docs={inSection} base="/docs" />
              </section>
            );
          })}
        </div>
      </main>
      <Mast />
    </div>
  );
}
