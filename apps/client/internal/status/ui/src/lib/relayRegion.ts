// relayRegion.ts — whose relay a region code names.
//
// The coordinator puts an org's own relays into its map under "self-" + label and
// leaves the platform's under their bare region code, so the code alone says
// which is which (apps/client/internal/mesh/homepick.go isSelfHostedRegion). The
// address does not: "edge01-lax.example.net:3340" and "relay.office.example:3340"
// look like the same kind of thing, and one of them is the org's own box.
//
// Three different relays can be on the 组网 page at once — the edge the tunnels
// use (top right), this device's home relay, and the relay each peer is reached
// through — and they were all rendered as an unlabelled address. This is what
// lets the page say whose each one is.

const SELF_PREFIX = "self-";

export interface RelayOwner {
  /** The org's own relay (true) or the platform's (false). */
  self: boolean;
  /** The region as a person would name it: the code without the "self-" marker. */
  label: string;
}

/**
 * relayOwner reads a relay region code. null for an empty or missing code — an
 * older daemon, a direct path, a relay the netmap named no region for — which
 * callers must render as "not known", never as "platform".
 */
export function relayOwner(region?: string | null): RelayOwner | null {
  const code = (region ?? "").trim();
  if (!code) return null;
  if (code.startsWith(SELF_PREFIX)) {
    return { self: true, label: code.slice(SELF_PREFIX.length) };
  }
  return { self: false, label: code };
}

/** What the page calls a relay's owner. */
export type RelayOwnerKind = "self" | "platform";

/**
 * relayOwnerKind is the label a relay gets, or null when there is none to give:
 * the owner is not known, or this device is signed in to a self-hosted server.
 * There every relay is that server's own and its coordinator hands out bare
 * region codes — the "self-" marker is something only the platform adds — so
 * reading the code would call the administrator's own relay "platform", a
 * party that is not in the picture at all.
 */
export function relayOwnerKind(owner: RelayOwner | null, selfHostedServer: boolean): RelayOwnerKind | null {
  if (!owner || selfHostedServer) return null;
  return owner.self ? "self" : "platform";
}
