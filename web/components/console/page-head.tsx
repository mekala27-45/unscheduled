import type { ReactNode } from "react";

/** One page head per console screen: what the screen is, in a line, and its tools. No greeting. */
export function PageHead({ title, children, tools, meta }: { title: ReactNode; children?: ReactNode; tools?: ReactNode; meta?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {children ? <p>{children}</p> : null}
        {meta ? <div className="page-meta">{meta}</div> : null}
      </div>
      {tools ? <div className="region__tools">{tools}</div> : null}
    </div>
  );
}
