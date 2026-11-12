import type { Metadata } from "next";
import { PageHead } from "@/components/console/page-head";
import { EmptyState, Region } from "@/components/console/region";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { readCriteria } from "@/lib/build-data";
import { formatDate } from "@/lib/format";

export const metadata: Metadata = { title: "Criteria", description: "C1 to C9, the criteria for the whole month, signed and hashed before any test CVE is scored." };

/** Read from config/criteria.yaml and evaluation/registration.json when the site is built. */
export default function CriteriaPage() {
  const loaded = readCriteria();
  return (
    <>
      <PageHead title="Criteria">
        The engagement contract for all five phases: what the customer signs, the threshold, and the phase that brings the evidence.
      </PageHead>
      <Region id="criteria" title="C1 to C9" note="Read from config/criteria.yaml when this site was built">
        {loaded.state === "absent" ? (
          <EmptyState
            title="The criteria are not registered yet"
            body="They are written with the customer and hashed into evaluation/registration.json at step six, before any test CVE is scored. This page reads that file when the site is built."
            action={{ label: "See the limits instead", href: "/app/limits" }}
          />
        ) : loaded.state === "unreadable" ? (
          <div className="well state" data-kind="error" role="alert">
            <h3>{loaded.file} does not have the shape this page reads</h3>
            <p>Each criterion needs an id and a sentence; a threshold, a phase and an evidence file are read when present. Fix the file or this reader, then build again.</p>
          </div>
        ) : (
          <>
            <p className="mb-md text-app-sm text-fg-2">
              Registration hash{" "}
              <span className="mono">{loaded.value.hash ?? "not recorded"}</span>
              {loaded.value.registeredAt ? `, registered ${formatDate(loaded.value.registeredAt, "long")}` : ""}. A change after this is a dated entry in DECISIONS.md with both verdicts.
            </p>
            <Table label="C1 to C9">
              <TableHeader>
                <TableRow>
                  <TableHead>Criterion</TableHead>
                  <TableHead>The sentence the customer signs</TableHead>
                  <TableHead>Threshold</TableHead>
                  <TableHead>Evidence in phase</TableHead>
                  <TableHead>Evidence file</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loaded.value.criteria.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="lead">{c.id}</TableCell>
                    <TableCell className="wrap">{c.sentence}</TableCell>
                    <TableCell className="wrap">{c.threshold}</TableCell>
                    <TableCell>{c.phase}</TableCell>
                    <TableCell className="mono">{c.evidence ?? "none yet"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </>
        )}
      </Region>
    </>
  );
}
