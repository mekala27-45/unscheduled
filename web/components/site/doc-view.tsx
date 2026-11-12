import Link from "next/link";
import { DOC_DIAGRAMS, type Doc, type DocDiagram } from "@/lib/docs";
import { REPO_URL } from "@/lib/nav";
import { Mast } from "./mast";
import { SiteNav } from "./site-nav";

/**
 * One document in a reading column, its second level headings beside it as the contents. The HTML
 * comes from a file in this repository rendered at build time (lib/docs.ts), never from a visitor.
 */
export function DocView({ doc, back }: { doc: Doc; back: { href: string; label: string } }) {
  return (
    <div className="site">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <SiteNav banner={<span>{doc.file} in the repository, rendered when this site was built.</span>} />
      <main id="main" tabIndex={-1} className="container doc-page">
        <p className="doc-page__crumbs">
          <Link href={back.href}>{back.label}</Link>
        </p>
        <h1 className="doc-page__title">{doc.title}</h1>
        <div className="doc-page__body" data-toc={doc.toc.length > 1 ? "true" : undefined}>
          {doc.toc.length > 1 ? (
            <nav className="doc-toc" aria-label="Contents">
              <ol>
                {doc.toc.map((t) => (
                  <li key={t.id}>
                    <a href={`#${t.id}`}>{t.text}</a>
                  </li>
                ))}
              </ol>
            </nav>
          ) : null}
          <div className="doc-page__main">
            {DOC_DIAGRAMS[doc.slug] ? <DiagramFigure diagram={DOC_DIAGRAMS[doc.slug]} /> : null}
            <article className="doc" dangerouslySetInnerHTML={{ __html: doc.html }} />
          </div>
        </div>
        <p className="doc-page__source">
          Source: <a href={`${REPO_URL}/blob/main/${doc.file}`}>{doc.file}</a>
        </p>
      </main>
      <Mast />
    </div>
  );
}

/** An archify diagram in both themes, with a link to the page where it can be explored. */
export function DiagramFigure({ diagram, className = "doc-figure" }: { diagram: DocDiagram; className?: string }) {
  return (
    <figure className={`${className} shot`}>
      <img className="shot__light" src={diagram.light} width={diagram.width} height={diagram.height} alt={diagram.alt} />
      <img className="shot__dark" src={diagram.dark} width={diagram.width} height={diagram.height} alt={diagram.alt} />
      <figcaption>
        Drawn with archify from {diagram.source}. <a href={diagram.page}>Open the diagram you can explore</a>
      </figcaption>
    </figure>
  );
}

/** A list of documents, each its name and the first sentence of its text. */
export function DocList({ docs, base }: { docs: Doc[]; base: string }) {
  return (
    <ul className="doc-list">
      {docs.map((d) => (
        <li key={d.slug}>
          <Link href={`${base}/${d.slug}`}>{d.title}</Link>
          <p>{d.lead}</p>
        </li>
      ))}
    </ul>
  );
}
