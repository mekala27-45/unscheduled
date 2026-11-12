import type { Loaded, LockLite, ManifestLite } from "@/lib/build-data";
import { formatDateTime, formatInt, shortDigest } from "@/lib/format";
import { ECOSYSTEMS, SBOM_FORMATS, SOURCES } from "@/lib/sources";

/**
 * What it reads, as a table that is the API: each source, its terms, its cadence, and, once fetched,
 * the time and digest from its lock and the rows from the manifest. One row, the NVD, on the wash.
 */
export function Reads({ locks, manifest }: { locks: Record<string, Loaded<LockLite>>; manifest: Loaded<ManifestLite> }) {
  const rowsOf = (id: string) => (manifest.state === "ok" ? manifest.value.values[`sources.${id}.rows`]?.value : undefined);
  // A column that would hold nothing but a missing fact is cut, not announced: Rows appears once the manifest counts them.
  const showRows = SOURCES.some((s) => typeof rowsOf(s.id) === "number");
  return (
    <>
      <table className="reads">
        <thead>
          <tr>
            <th scope="col">Source</th>
            <th scope="col">Terms</th>
            <th scope="col">Cadence</th>
            <th scope="col">Fetched</th>
            {showRows ? <th scope="col">Rows</th> : null}
          </tr>
        </thead>
        <tbody>
          {SOURCES.map((s) => {
            const lock = locks[s.id];
            const rows = rowsOf(s.id);
            return (
              <tr key={s.id} data-wash={s.id === "nvd" ? "true" : undefined}>
                <td>
                  <a href={s.url}>{s.name}</a>
                </td>
                <td data-label="Terms">{s.terms}</td>
                <td data-label="Cadence">{s.cadence}</td>
                <td data-label="Fetched">
                  {lock?.state === "ok" ? (
                    <span className="mono" title={`${formatDateTime(lock.value.fetched_at)}, sha256 ${lock.value.digest}`}>
                      {lock.value.fetched_at.slice(0, 10)} {shortDigest(lock.value.digest, 8)}
                    </span>
                  ) : lock?.state === "unreadable" ? (
                    <span className="absent">unreadable</span>
                  ) : (
                    <span className="absent">pending</span>
                  )}
                </td>
                {showRows ? (
                  <td data-label="Rows" className="num">
                    {typeof rows === "number" ? <span className="mono">{formatInt(rows)}</span> : <span className="absent">not counted</span>}
                  </td>
                ) : null}
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="reads-accepts">
        Matches {SBOM_FORMATS.join(" or ")} SBOMs up to 2 MB, for {ECOSYSTEMS.join(", ")}.
      </p>
    </>
  );
}
