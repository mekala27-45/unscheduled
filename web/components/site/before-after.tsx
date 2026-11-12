import type { Loaded, ManifestLite } from "@/lib/build-data";
import { formatShare } from "@/lib/format";

const ROWS: { key: string; nvd: string; ours: string }[] = [
  { key: "match", nvd: "no CPE", ours: "package URL and range" },
  { key: "filer_cvss", nvd: "none", ours: "vector, filer, date" },
  { key: "kev", nvd: "none", ours: "the date CISA added it" },
  { key: "exploit_code", nvd: "none", ours: "first commit seen" },
  { key: "fixed_in", nvd: "none", ours: "first fixed version" },
];

/** The manifest key for the share of today's findings whose CVE has no NVD CPE configuration. */
export const NO_CPE_KEY = "exposure.contrast.share_no_cpe";

/**
 * One finding read two ways: by NVD CPE name, and by package URL. The share under the panes comes
 * from the manifest; with no manifest value the line is left out rather than filled with a guess.
 */
export function BeforeAfter({ manifest }: { manifest: Loaded<ManifestLite> }) {
  const share = manifest.state === "ok" ? manifest.value.values[NO_CPE_KEY]?.value : undefined;
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
      {typeof share === "number" ? (
        <p className="ba__count">
          <strong className="mono">{formatShare(share, 1)}</strong> of the findings today in the six stand-in products have no NVD CPE configuration, so a
          matcher that reads CPE names could not have made them.
        </p>
      ) : null}
    </>
  );
}
