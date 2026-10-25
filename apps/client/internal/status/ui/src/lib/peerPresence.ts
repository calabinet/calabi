import { peerAddresses } from "./peerAddresses.ts";

// Presence is the coordinator's control-session status, not WG traffic activity.
export function peerPresence(allowed: string[], nodes?: { overlay: string; online?: boolean }[]): "online" | "offline" | "unknown" {
  const address = peerAddresses(allowed).overlay;
  const node = address ? nodes?.find(n => n.overlay === address) : undefined;
  return node?.online === true ? "online" : node?.online === false ? "offline" : "unknown";
}
