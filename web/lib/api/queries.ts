"use client";

import { useInfiniteQuery, useMutation, useQuery, type QueryClient } from "@tanstack/react-query";
import { ApiError, api, type CveQuery } from "./client";

/** Retry a request the API never answered once; never retry a refusal or a missing address. */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (error instanceof ApiError) {
    if (error.kind === "network") return failureCount < 1;
    if (error.kind === "http") return (error.status ?? 0) >= 500 && failureCount < 1;
    return false;
  }
  return failureCount < 1;
}

export const queryDefaults: ConstructorParameters<typeof QueryClient>[0] = {
  defaultOptions: {
    queries: { retry: shouldRetry, staleTime: 60_000, refetchOnWindowFocus: false },
    mutations: { retry: false },
  },
};

export const useHealth = (live = false) =>
  useQuery({ queryKey: ["health"], queryFn: ({ signal }) => api.health(signal), refetchInterval: live ? 60_000 : false });

export const useMeta = () => useQuery({ queryKey: ["meta"], queryFn: ({ signal }) => api.meta(signal) });

export const useCve = (id: string, asOf: string | null) =>
  useQuery({ queryKey: ["cve", id, asOf], queryFn: ({ signal }) => api.cve(id, asOf, signal) });

export const useTimeline = (id: string) =>
  useQuery({ queryKey: ["timeline", id], queryFn: ({ signal }) => api.timeline(id, signal) });

export const useCveList = (query: CveQuery, enabled = true) =>
  useQuery({ queryKey: ["cves", query], queryFn: ({ signal }) => api.cves(query, signal), enabled });

export const useCvePages = (query: CveQuery) =>
  useInfiniteQuery({
    queryKey: ["cves", "pages", query],
    queryFn: ({ pageParam, signal }) => api.cves({ ...query, limit: 100, ...(pageParam ? { cursor: pageParam } : {}) }, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });

export const useBacklog = () => useQuery({ queryKey: ["backlog"], queryFn: ({ signal }) => api.backlog(signal) });

export const useProducts = () => useQuery({ queryKey: ["products"], queryFn: ({ signal }) => api.products(signal) });

export const useExposure = (id: string | null, asOf: string | null) =>
  useQuery({
    queryKey: ["exposure", id, asOf],
    queryFn: ({ signal }) => api.exposure(id ?? "", asOf, signal),
    enabled: id !== null,
  });

export const useMatch = () => useMutation({ mutationFn: (sbom: Record<string, unknown>) => api.match(sbom) });
