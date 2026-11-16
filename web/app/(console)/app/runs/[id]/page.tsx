import type { Metadata } from "next";
import { PageHead } from "@/components/console/page-head";
import { EmptyState } from "@/components/console/region";
import { RunDetail } from "@/components/console/run-detail";

type Props = { params: Promise<{ id: string }> };

const RUN_ID = /^[0-9a-f]{32}$/;

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { id } = await params;
  return RUN_ID.test(id)
    ? { title: `Run ${id.slice(0, 12)}`, description: "One triage run: the graph with its costs, the drafts with every claim checked, and the decision that waits or was made." }
    : { title: "Not a run id" };
}

export default async function RunPage({ params }: Props) {
  const { id } = await params;
  if (!RUN_ID.test(id)) {
    return (
      <>
        <PageHead title="Not a run id" />
        <EmptyState
          title={`"${decodeURIComponent(id).slice(0, 40)}" is not a run id`}
          body="A run id is 32 hexadecimal characters, as POST /v1/triage answers it."
          action={{ label: "Back to the runs", href: "/app/runs" }}
        />
      </>
    );
  }
  return <RunDetail id={id} />;
}
