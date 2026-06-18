// Shape mirrors the Go side. Keep in sync with:
//   apps/client/internal/status/status.go (Snapshot, TunnelInfo)
//   apps/bff-console/internal/handlers/tunnels.go (marshalTunnel)
//   apps/bff-console/internal/handlers/billing.go (plans)
//   apps/bff-console/internal/handlers/account.go (account.me)

export type Lifecycle =
  | "starting"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "stopped"
  | "fatal"
  // The reconnect loop exhausted its retry budget and PARKED — it stops
  // dialing until the user acts (manual region switch / re-login). Shown
  // as "服务器不可用，可手动切换地域".
  | "unavailable"
  | "unknown";

export interface Healthz {
  state: Lifecycle;
  connected: boolean;
  since: string;
  started_at: string;
  uptime_seconds: number;
  version: string;
  server_addr: string;
}

export interface TunnelInfo {
  proxy_id: string;
  tunnel_id?: number;
  name: string;
  type: string;
  local_addr: string;
  public_addr: string;
  bytes_in: number;
  bytes_out: number;
  connections: number;
  pending?: boolean;
}

// EdgeSwitchInfo — surfaced by daemon when the sticky edge_node_id from
// the previous boot is no longer in /v1/edges' healthy set and the
// picker had to land on a different edge. Tunnels.tsx renders this as
// a yellow Alert above the table. nil = no switch (typical case).
//
// Under M12 per-edge wildcard DNS, tunnels bound to the previous edge
// are temporarily unreachable until that edge comes back online — the
// user has to either wait or delete + recreate the tunnel on the new
// edge.
export interface EdgeSwitchInfo {
  previous_edge_node_id: number;
  current_edge_node_id: number;
  since: string;
}

export interface Snapshot {
  client_version: string;
  server_addr: string;
  session_id?: string;
  tenant_id?: string;
  client_id?: string;
  // M11.20.3 — edge's HTTPListener.BaseDomain plumbed through AUTH_RESP.
  // Tunnels.tsx uses it to render TCP/UDP public addrs as
  // `<base_domain>:<remote_port>`. Empty if the edge is too old; the SPA
  // falls back to server_addr's host (which in dev rendered the
  // confusing "localhost:<port>" before this field existed).
  base_domain?: string;
  // M11.20.6 — the daemon's underlying TCP/TLS conn RemoteAddr resolved
  // to IP (e.g. "127.0.0.1" in dev, "1.2.3.4" in prod). Tunnels.tsx
  // prefers this for TCP/UDP public addr display — `<server_ip>:<port>`
  // is what the user explicitly asked for (vs domain or "localhost").
  // Empty when not authenticated; SPA falls back through base_domain ->
  // server_addr host -> bare `:<port>`.
  server_ip?: string;
  // Edge's public HTTP / HTTPS listener ports (AUTH_RESP). A self-hosted
  // console renders `http://<domain>:<http_port>` for non-standard ports;
  // 0/absent (platform edge on 80/443) → bare domain.
  http_port?: number;
  https_port?: number;
  // The identity-svc edge_node_id of the edge this daemon picked +
  // dialed this boot. Tunnels.tsx compares each row's edge_node_id
  // against this to render the "当前节点 / 其他节点" Edge column.
  // 0 / undefined when daemon went through a tier that doesn't know
  // the id (CALABI_SERVER env override or compile-time default).
  edge_node_id?: number;
  // The org the daemon's saved token is scoped to (creds.ActiveOrgID).
  // The top-bar Org chip uses THIS as the source of truth — it tracks the
  // token within one snapshot poll, so the displayed Org never diverges
  // from the (token-scoped) tunnel list even if a switch's reload is
  // skipped. 0 / undefined = unknown (pre-login); fall back to /v1/orgs.
  active_org_id?: number;
  // The region the daemon is anchored to (CLI flag / creds.EdgeRegion /
  // last successful region). The top-bar region switcher highlights this
  // even when disconnected / parked, where edge_node_id is unavailable.
  preferred_region?: string;
  connected: boolean;
  lifecycle: Lifecycle;
  started_at: string;
  uptime_seconds: number;
  tunnels: TunnelInfo[];
  edge_switch?: EdgeSwitchInfo;
}

export interface RemoteTunnel {
  id: number;
  org_id: number;
  workspace_id?: number;
  client_id?: number;
  name: string;
  type: "http" | "https" | "tcp" | "udp" | "sni";
  local_addr?: string;
  domain?: string;
  remote_port?: number;
  status: "enabled" | "disabled" | "error" | "offline";
  edge_node_id?: number;
  config_json?: string;
  client_online?: boolean;
  client_last_seen_at?: string;
  created_at?: string;
  updated_at?: string;
}

export interface TunnelList {
  items: RemoteTunnel[];
  // M11.19.1 — daemon filters items down to this machine's device_id,
  // but the Org-wide quota cap is applied against ALL members'
  // tunnels. So we ship two counters from the daemon so the Overview
  // card can render `team_total / plan_max` honestly with a "其中本机
  // N 条" hint, instead of pretending the SPA's filtered count is
  // what the quota is spending.
  //
  // Both are optional so older daemon builds without M11.19.1 don't
  // break the SPA — Overview falls back to items.length in that case.
  my_total?: number;
  team_total?: number;
}

export interface CreateTunnelBody {
  workspace_id?: number;
  client_id?: number;
  name: string;
  type: RemoteTunnel["type"];
  local_addr?: string;
  domain?: string;
  // Phase 2 — user-requested platform subdomain PREFIX (基础版+) for
  // http/https. Edge resolves it to <subdomain>.<region base>. Mutually
  // exclusive with a custom `domain`. Empty = auto-allocated subdomain.
  subdomain?: string;
  remote_port?: number;
  config_json?: string;
}

// Edit a tunnel's mutable core fields. Omitted / undefined = leave unchanged.
// Only name + local_addr are editable; the public endpoint stays put.
export interface UpdateTunnelBody {
  name?: string;
  local_addr?: string;
}

export interface AccountMe {
  user: { id: number; email?: string };
  org: { id: number; name?: string };
  plan: {
    code: string;
    // Gating subset of quota-svc features_json (tcp/udp/sni/custom_domain).
    // Used by TunnelWizard to disable protocol options / custom-domain input
    // the server would 403. Mirrors apps/bff-console account.go which already
    // returns this field.
    features_json?: string;
    monthly_traffic_mb?: number;
    max_tunnels?: number;
    // Concurrent online client cap. -1 = unlimited. Mirrors the
    // matching `max_online_clients` quota dimension in quota-svc.
    // Edge-node refuses new sessions when current online count
    // would exceed this; the daemon displays the cap as info on
    // the overview page.
    max_online_clients?: number;
    read_only: boolean;
  };
}

// M11.7 Org switcher types — mirror bff-console/internal/handlers/orgs.go's
// orgListRowJSON.
export interface OrgListRow {
  id: number;
  name?: string;
  kind?: string;           // "personal" | "team"
  realname_kind?: string;
  plan_id?: number;
  status?: string;
  realname_status?: string;
}

export interface OrgListResponse {
  items: OrgListRow[];
  active_org_id: number;
}

export interface OrgSwitchResponse {
  active_org_id: number;
}

export interface CurrentUsage {
  org_id: number;
  bytes_in: number;
  bytes_out: number;
  bytes_total: number;
  percent_of_limit: number;
  limit_mb: number;
}

// UsageBucket mirrors apps/bff-console/internal/handlers/usage.go::marshalBuckets.
// One row per granularity unit (day / hour / month). Used by Overview's
// "今日流量" card via /v1/usage/daily?n=1.
export interface UsageBucket {
  ts: string;
  bytes_in: number;
  bytes_out: number;
  bytes_total: number;
}

export interface UsageHistory {
  org_id: number;
  granularity: string;
  buckets: UsageBucket[];
}

export interface ClientDevice {
  id: number;
  display_name?: string;
  online: boolean;
  fingerprint?: string;
}

export interface ClientDevicesList {
  items: ClientDevice[];
}

// ---- M7-S5 — probe + inspect ----------------------------------------------

export interface ProbePort {
  port: number;
  listening: boolean;
  latency_ms: number;
  hint?: string;
}

export interface ProbeHealth {
  proxy_id: string;
  healthy: boolean;
  checked_at: string;
  latency_ms: number;
  error?: string;
  consecutive_bad: number;
  consecutive_good: number;
}

export interface ConnectionRow {
  id: number;
  proxy_id: string;
  started_at: string;
  ended_at?: string;
  visitor_ip?: string;
  bytes_in: number;
  bytes_out: number;
  duration_ms?: number;
  error?: string;
}

export interface HTTPCaptureRow {
  id: number;
  proxy_id: string;
  started_at: string;
  method: string;
  path: string;
  host?: string;
  request_headers?: Record<string, string>;
  request_body?: string;
  response_status?: number;
  response_headers?: Record<string, string>;
  response_body?: string;
  duration_ms?: number;
  error?: string;
}

export interface ReplayResponse {
  status: number;
  body: string;
  target: string;
}

// EdgeListItem mirrors bff-console GET /v1/edges item shape. We use
// it in Tunnels.tsx to enrich each row's bare edge_node_id with a
// region + healthy flag + public_addr (for the tooltip). Keep in sync
// with apps/bff-console/internal/handlers/edges.go::listEdgesHandler.
export interface EdgeListItem {
  edge_node_id: number;
  node_label?: string;
  region?: string;
  public_addr?: string;
  healthy?: boolean;
  active_clients?: number;
  last_seen_at?: string;
  // owned = this is one of the caller org's self-hosted (BYOI) edges.
  // Drives the data-egress affinity toggle in the top bar.
  owned?: boolean;
}

// EdgeAffinity is the daemon's data-egress preference for a BYOI org:
// "own" = default to the org's self-hosted edge; "platform" = use the
// platform data plane even when an own edge exists.
export interface EdgeAffinity {
  affinity: "own" | "platform";
  prefer_platform: boolean;
}

export interface EdgeList {
  items: EdgeListItem[];
  // owned_total = how many self-hosted (BYOI) edges the caller org OWNS
  // (active edge certs), independent of whether any are currently live in
  // the directory. The top-bar egress toggle is gated on THIS (entitlement)
  // so it stays visible even when the org's edge is momentarily offline.
  // items[].owned still reflects live ownership (used to detect "node down").
  owned_total?: number;
}
