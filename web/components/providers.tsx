"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { NuqsAdapter } from "nuqs/adapters/next/app";
import { useState, type ReactNode } from "react";
import { queryDefaults } from "@/lib/api/queries";

export function Providers({ children }: { children: ReactNode }) {
  const [client] = useState(() => new QueryClient(queryDefaults));
  return (
    <NuqsAdapter>
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    </NuqsAdapter>
  );
}
