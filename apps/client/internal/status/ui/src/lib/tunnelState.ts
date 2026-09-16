// Shared tunnel "effective state" — the SAME collapsing logic the cloud console
// uses (web/console/src/lib/tunnelState.ts). Keeping them in lock-step is the
// whole point: the :7400 daemon console and the web console must never disagree
// on what state a tunnel is in. The daemon's Tunnels page starts from this base
// state and only LAYERS its local signals (its own live edge session + the
// per-tunnel health probe) on top — it never invents a different vocabulary.
//
// THIS IS THE THIRD MIRROR, and on 2026-09-15 it was the one that drifted: the
// console and web/admin gained `upstream_down` + `unverified` and this file did
// not, so a tunnel served by ANOTHER machine read "online" here and "upstream
// unchecked" there. Nothing flagged it — scripts/lint/check-tunnel-state.mjs
// compared only two of the three files. It now compares all three.
//
// Precedence (highest first): admin_disabled → disabled → error → pending →
// offline → mismatch → upstream_down → unverified → active. First match wins, so
// admin intent dominates and a disabled tunnel doesn't flap between
// pending/offline as the daemon comes/goes.

import type { RemoteTunnel } from "../api/types";

export type EffectiveState =
  | "admin_disabled"
  | "disabled"
  | "error"
  | "pending"
  | "offline"
  | "mismatch"
  | "upstream_down"
  | "unverified"
  | "active";

export function effectiveState(t: RemoteTunnel): EffectiveState {
  // An admin disable dominates and is distinct from a user's own disable — the
  // user can't lift it, so the badge/tooltip says so.
  if (t.disabled_by_admin) return "admin_disabled";
  if (t.status === "disabled") return "disabled";
  if (t.status === "error") return "error";
  if (!t.edge_node_id || t.edge_node_id === 0) return "pending";
  // status === "offline" only ever lands here after the edge ran teardown
  // (session_end / client_close) — treat as "client side currently down".
  if (t.status === "offline") return "offline";
  // client_id == 0 means the tunnel isn't pinned to any device, so
  // client_online doesn't apply — treat as active when nothing else is wrong.
  if (t.client_id && !t.client_online) return "offline";
  // client_edge_node_id is the edge the client's daemon is CURRENTLY on. If it
  // differs from edge_node_id (where the domain is pinned), the public URL is
  // unreachable. 0 = no signal (skip rather than flap into mismatch).
  if (
    t.client_id &&
    t.client_online &&
    t.client_edge_node_id &&
    t.client_edge_node_id !== t.edge_node_id
  ) {
    return "mismatch";
  }
  // The edge has the tunnel + the client is online, but the client's last
  // probe couldn't reach the local target (local_addr). Only trust this when
  // the client is present — a stale "unhealthy" from a since-disconnected
  // daemon must not override "offline" (handled above).
  if (t.client_online && t.upstream_state === "unhealthy") {
    return "upstream_down";
  }
  // NOTHING HAS CONFIRMED THE LOCAL UPSTREAM, so do not claim it is fine.
  //
  // For rows THIS daemon serves, Tunnels.tsx layers its own live probe over the
  // top and this never shows — the state below is what a row belonging to
  // another machine collapses to, which is exactly where the drift showed.
  //
  // A new tunnel also passes through here for ~30s before its first probe
  // lands. That is not a flaw in the rule: during those 30 seconds the upstream
  // genuinely is unverified. It is rendered as a NEUTRAL state, never a fault —
  // "we have not checked", not "it is broken".
  if (t.upstream_state !== "healthy") {
    return "unverified";
  }
  return "active";
}
