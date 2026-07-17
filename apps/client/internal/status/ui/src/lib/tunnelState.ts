// Shared tunnel "effective state" — the SAME collapsing logic the cloud console
// uses (web/console/src/lib/tunnelState.ts). Keeping the two in lock-step is the
// whole point: the :7400 daemon console and the web console must never disagree
// on what state a tunnel is in. The daemon's Tunnels page starts from this base
// state and only LAYERS its local signals (its own live edge session + the
// per-tunnel health probe) on top — it never invents a different vocabulary.
//
// Precedence (highest first): admin_disabled → disabled → error → pending →
// offline → mismatch → active. First match wins, so admin intent dominates and a
// disabled tunnel doesn't flap between pending/offline as the daemon comes/goes.

import type { RemoteTunnel } from "../api/types";

export type EffectiveState =
  | "admin_disabled"
  | "disabled"
  | "error"
  | "pending"
  | "offline"
  | "mismatch"
  | "active";

export function effectiveState(t: RemoteTunnel): EffectiveState {
  if (t.disabled_by_admin) return "admin_disabled";
  if (t.status === "disabled") return "disabled";
  if (t.status === "error") return "error";
  if (!t.edge_node_id || t.edge_node_id === 0) return "pending";
  if (t.status === "offline") return "offline";
  // client_id == 0 means the tunnel isn't pinned to any device, so
  // client_online doesn't apply — treat as active when nothing else is wrong.
  if (t.client_id && !t.client_online) return "offline";
  // client_edge_node_id is the edge the owning client's daemon is CURRENTLY on.
  // If it differs from edge_node_id (where the domain is pinned), the public URL
  // is unreachable. 0 = no signal (skip rather than flap into mismatch).
  if (
    t.client_id &&
    t.client_online &&
    t.client_edge_node_id &&
    t.client_edge_node_id !== t.edge_node_id
  ) {
    return "mismatch";
  }
  return "active";
}
