import type { Metadata } from "next";
import { Suspense } from "react";
import { ProductsView } from "@/components/console/products-view";

export const metadata: Metadata = { title: "Products", description: "The stand-in products of a fictional customer, pinned by commit, and their exposure by NVD status." };

export default function ProductsPage() {
  return (
    <Suspense>
      <ProductsView />
    </Suspense>
  );
}
