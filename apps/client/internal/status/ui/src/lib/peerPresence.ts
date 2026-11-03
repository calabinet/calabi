import { peerAddresses } from "./peerAddresses.ts";

export const presenceQueryOptions = {
  staleTime: 5_000,
  refetchInterval: 5_000,
  refetchOnWindowFocus: "always" as const,
};

// A failed background poll keeps its last successful data and timestamp.
// Trust that snapshot within the freshness window, even if query status is error.
export function isPresenceCurrent(enabled: boolean, query: { data?: unknown; dataUpdatedAt: number }, now = Date.now()): boolean {
  return enabled && query.data !== undefined && query.dataUpdatedAt > 0 && now - query.dataUpdatedAt < 15_000;
}

// While replacing an absent/expired snapshot, omit the badge rather than
// presenting a routine refresh as unavailable presence.
export function displayedPeerPresence(allowed: string[], nodes: { overlay: string; online?: boolean }[] | undefined, enabled: boolean,
  query: { data?: unknown; dataUpdatedAt: number; isFetching: boolean }, now = Date.now()): "online" | "offline" | "unknown" | null {
  const current = isPresenceCurrent(enabled, query, now);
  if (enabled && !current && query.isFetching) return null;
  return peerPresence(allowed, current ? nodes : undefined);
}

// Presence is the coordinator's control-session status, not WG traffic activity.
export function peerPresence(allowed: string[], nodes?: { overlay: string; online?: boolean }[]): "online" | "offline" | "unknown" {
  const address = peerAddresses(allowed).overlay;
  const node = address ? nodes?.find(n => n.overlay === address) : undefined;
  return node?.online === true ? "online" : node?.online === false ? "offline" : "unknown";
}
