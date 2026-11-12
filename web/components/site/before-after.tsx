const ROWS: { key: string; nvd: string; ours: string }[] = [
  { key: "match", nvd: "no CPE", ours: "package URL and range" },
  { key: "filer_cvss", nvd: "none", ours: "vector, filer, date" },
  { key: "kev", nvd: "none", ours: "the date CISA added it" },
  { key: "exploit_code", nvd: "none", ours: "first commit seen" },
  { key: "fixed_in", nvd: "none", ours: "first fixed version" },
];

/** One finding read two ways: by NVD CPE name, and by package URL. The counts wait for the manifest. */
export function BeforeAfter() {
  return (
    <>
      <div className="ba">
        <section className="ba__pane" aria-labelledby="ba-nvd">
          <div className="ba__head">
            <h3 id="ba-nvd">NVD only, by CPE name</h3>
          </div>
          <dl className="ba__rows">
            {ROWS.map((r) => (
              <div key={r.key} className="ba__row" data-miss="true">
                <dt>{r.key}</dt>
                <dd>{r.nvd}</dd>
              </div>
            ))}
          </dl>
        </section>
        <section className="ba__pane" aria-labelledby="ba-ours">
          <div className="ba__head">
            <h3 id="ba-ours">unscheduled, by package URL</h3>
          </div>
          <dl className="ba__rows">
            {ROWS.map((r) => (
              <div key={r.key} className="ba__row">
                <dt>{r.key}</dt>
                <dd>{r.ours}</dd>
              </div>
            ))}
          </dl>
        </section>
      </div>
      <p className="ba__count">
        Findings without NVD analysis in the first stand-in: <span className="fill">counted at step eight</span>
      </p>
    </>
  );
}
