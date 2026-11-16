import type { Metadata } from "next";
import { InboxView } from "@/components/console/inbox-view";

export const metadata: Metadata = {
  title: "Inbox",
  description: "What waits for a person: each draft by its hash, read only without the approver's token.",
};

export default function InboxPage() {
  return <InboxView />;
}
