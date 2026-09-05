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

// ServiceMode — GET /v1/service-mode. Tells the SPA whether this daemon is a
// pinned-identity "agent" (a service installed via `daemon install --api-key`,
// or CALABI_API_KEY in the env) or "interactive" (desktop / a service installed
// without a key). In agent mode the login portal and org switching are refused
// server-side, so the SPA hides those affordances. Whether the agent may MANAGE
// tunnels is a separate axis derived from the pinned key's scopes (see
// AccountMe.scopes / tunnel.write) — a management key gets a writable console, a
// read-only key stays read-only. The endpoint is daemon-only; when absent (older
// daemon) the SPA defaults to interactive.
export interface ServiceMode {
  mode: "agent" | "interactive";
  // `agent` is the canonical flag; `read_only` is a deprecated alias kept for
  // one release so a stale cached bundle still reads the pinned-identity state.
  agent?: boolean;
  read_only?: boolean;
  login_enabled: boolean;
  // WEB console origin (e.g. https://console.calabi.net) — where the login page
  // links for registration. Baked into the daemon at build time and overridable
  // via $CALABI_CONSOLE_WEB, so self-hosted deployments point at their own
  // console. Absent/empty (older daemon, or unset) → hide the link.
  console_web?: string;
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
  // This install's Publish-side identity: the fingerprint the daemon reports
  // (and the mesh sends to the coordinator) plus the clients.id it resolved to.
  // Empty until a device registration has happened — which is a state worth
  // seeing, since it's the reason a mesh device can show no client link.
  fingerprint?: string;
  device_id?: number;
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
  // The edge the OWNING client's daemon is currently connected to. When it
  // differs from edge_node_id (where the domain is pinned) the public URL is
  // unreachable — the shared effectiveState() maps that to "mismatch". 0 = no
  // signal. Mirrors bff-console marshalTunnel's client_edge_node_id.
  client_edge_node_id?: number;
  // True when an ADMIN disabled this tunnel (vs the user's own disable). The
  // user can't lift it; effectiveState() surfaces it as "admin_disabled".
  disabled_by_admin?: boolean;
  client_last_seen_at?: string;
  created_at?: string;
  updated_at?: string;
  // True when the current identity created this tunnel. Drives the takeover
  // affordance — takeover is creator-only (you can't grab a teammate's tunnel).
  created_by_me?: boolean;
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
  // This daemon's own device_id (creds.DeviceID). The list now includes
  // tunnels bound to OTHER clients in the org; the SPA compares each row's
  // client_id against this to tell "runs here" from "runs on another client"
  // (and to offer takeover). 0/absent on a freshly-installed daemon.
  my_device_id?: number;
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
  // Data-plane scopes of the bearer behind this console. Only an API-key
  // principal carries these (e.g. ["tunnel.read","tunnel.write"]); a login
  // session gets null. In agent mode the SPA reads this to decide whether the
  // pinned key may MANAGE tunnels (tunnel.write present) or is read-only.
  scopes?: string[] | null;
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
  // Billing split (bff-console usage.go). platform_bytes_total = platform TUNNEL
  // bytes (billed); self_hosted = BYOI tunnel (not billed);
  // platform_relay_bytes_total = platform mesh-relay bytes (billed). The cap %
  // is over platform tunnel + platform relay. Optional so an older backend that
  // omits them degrades to bytes_total. Relay is org-level → 0 for a member view.
  platform_bytes_total?: number;
  self_hosted_bytes_total?: number;
  platform_relay_bytes_total?: number;
  // Self-hosted relay ("self-…" regions): the org's own relays DO report usage
  // (attributed to the org, tagged self-) but it's display-only, never billed.
  // Org-level — same on every client of the org, so two clients finally agree; 0
  // for a member's own-scoped view (falls back to the local mesh meter there).
  self_hosted_relay_bytes_total?: number;
  // "org" (management/auditor — carries the platform/self + relay splits) vs
  // "own" (a plain member — no splits, self_hosted/relay are always 0). The
  // overview uses it to know the split fields are trustworthy; a member on a
  // self-hosted edge has no split, so their whole tunnel total IS self-hosted.
  scope?: "org" | "own";
}

// UsageBucket mirrors apps/bff-console/internal/handlers/usage.go::marshalBuckets.
// One row per granularity unit (day / hour / month). Used by Overview's
// "今日流量" card via /v1/usage/daily?n=1.
export interface UsageBucket {
  ts: string;
  // PLATFORM (billed) pair — platform tunnel plus platform relay EGRESS.
  bytes_in: number;
  bytes_out: number;
  bytes_total: number;
  // SELF-HOSTED pair, composed the same way (BYOI tunnel + "self-" relay egress).
  // Recorded but never billed, and never summed into the pair above — a node whose
  // egress moved to its own edge reads its traffic HERE. Optional: a daemon may be
  // talking to a bff-console older than the field.
  self_hosted_bytes_in?: number;
  self_hosted_bytes_out?: number;
  self_hosted_bytes_total?: number;
  // The relay egress already INSIDE each pair. Subtract to get tunnel-only; edge
  // and relay are independent axes (own edge + platform relay is a real setup).
  relay_bytes_out?: number;
  self_hosted_relay_bytes_out?: number;
}

export interface UsageHistory {
  org_id: number;
  granularity: string;
  buckets: UsageBucket[];
}

// MeshUsage is THIS machine's Connect (mesh) traffic — GET /v1/usage/mesh.
// Served locally by the daemon in both editions (mesh isn't metered server-side
// per machine), so it's a separate call from the tunnel usage above. Each figure
// is split by transport: relay (via a DERP relay — billed when the relay is a
// platform one) vs direct (a hole-punched peer-to-peer path — never billed). The
// server can't provide this split (it never sees direct traffic), so it's local.
export interface MeshUsageBucket {
  relay: number;
  direct: number;
}
export interface MeshUsageDay {
  date: string; // local "2006-01-02"
  relay: number;
  direct: number;
}
export interface MeshUsage {
  today: MeshUsageBucket;
  month: MeshUsageBucket;
  daily: MeshUsageDay[]; // oldest→newest, gaps filled with 0
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
  // mesh_probed: whether reachability at this machine's overlay address
  // could be tested at all (false = not on the mesh). It keeps "couldn't
  // check" from reading as "not reachable".
  mesh_probed?: boolean;
  // mesh_reachable: the port accepts connections at the overlay address, not
  // just loopback. A 127.0.0.1-only service is listening but no mesh peer can
  // reach it. Meaningless unless mesh_probed.
  mesh_reachable?: boolean;
  // bind_addrs: the addresses this port is actually bound to (0.0.0.0,
  // 127.0.0.1, a specific IP, ...), read from the kernel socket table. Present
  // only in the enumerated scan; the dial fallback can't know it.
  bind_addrs?: string[];
  // source: "enumerated" (real socket table, carries bind_addrs and every port)
  // or "dialed" (curated-list fallback when the platform can't be enumerated).
  source?: string;
}

// ProbeCheck is one on-demand reachability check (POST /v1/probe/check) — the
// same Go probe.Result the background monitor publishes, so proxy_id and the
// consecutive_* counters come back zeroed and mean nothing here.
export type ProbeCheck = Omit<ProbeHealth, "proxy_id" | "consecutive_bad" | "consecutive_good">;

export interface ProbeHealth {
  proxy_id: string;
  healthy: boolean;
  checked_at: string;
  latency_ms: number;
  error?: string;
  // Stable code for WHY it failed (apps/client/internal/probe/reason.go), so
  // the UI can word it in the user's language instead of showing the OS
  // sentence in `error`. Absent when healthy, or when the failure didn't match
  // a known case — then `error` is all we have.
  reason?: string;
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

// DomainItem mirrors bff-console GET /v1/domains item shape (a subset).
// Keep in sync with apps/bff-console/internal/handlers/domains.go::domainToMap.
export interface DomainItem {
  name: string;
  status: string; // "pending" | "verified" | "failed"
  cert_id?: number;
  cert_name?: string;
  // True when some tunnel in the org already uses this domain as its public
  // hostname (bff-console cross-references the org's tunnels). bound_tunnel_name
  // is that tunnel's name. Drives the wizard's "in use" tag + unused-first sort.
  in_use?: boolean;
  bound_tunnel_name?: string;
}

export interface DomainList {
  items: DomainItem[];
}

// MeshPeer / MeshStatus mirror localweb.MeshStatus (GET /v1/mesh) — the Connect
// (WireGuard mesh) state the daemon reports for the local node.
export interface MeshPeer {
  public_key: string;
  allowed_ips: string[];
  last_handshake_sec: number; // unix seconds; 0 = never
  rx_bytes: number;
  tx_bytes: number;
  path?: string; // "direct" once hole punching found a peer-to-peer path, else "relay"
  endpoint?: string; // the direct UDP endpoint carrying it (empty over the relay)
  // Round-trip of that direct path, in microseconds; absent over the relay.
  // "direct" only means the relay is out of the picture — this is what says
  // whether the path is any good. Two machines on one LAN can be "direct" over a
  // public address, hairpinning out through the ISP and back: ~8ms and 0.3 MB/s
  // where the LAN path is ~0.4ms and 500 MB/s.
  rtt_micros?: number;
}

export interface MeshStatus {
  enabled: boolean; // a `mesh:` block is configured on this daemon
  up: boolean; // the datapath is currently live
  paused?: boolean; // stopped locally via meshDown; Start (meshUp) re-enrolls
  coord?: string;
  relay?: string;
  // derp_home is the region this node is homed on ("self-…" = the org's own
  // relay). relay is the address; derp_home is what flags self-hosted vs platform.
  derp_home?: string;
  name?: string;
  overlay?: string; // this node's overlay IP
  // org_id is the org (== meshnet) the RUNNING session enrolled into. It can
  // lag the daemon's active org for the moment between an org switch and the
  // re-enrollment — which is precisely when it needs to be visible.
  org_id?: number;
  peers: MeshPeer[];
}

// MeshServiceDecl is one service THIS machine declares it offers on the mesh
// (GET/POST /v1/mesh/services). A declaration only — an admin confirms it in the
// web console before any access rule matches it. from_config entries come from
// --mesh-service / the config file and can't be removed here.
export interface MeshServiceDecl {
  name: string;
  proto: string;
  port: number;
  // What THIS machine dials to reach the app; "" = 127.0.0.1:<port>. NOT where
  // the app is bound, and not on the path mesh traffic takes — a peer's packet
  // arrives on this machine's mesh address and finds a socket there or doesn't.
  target?: string;
  note?: string;
  from_config?: boolean;
  // Registered by a manager in the WEB console. This machine checks it like any
  // other but cannot edit or remove it.
  from_console?: boolean;
  // This machine's own last self-check. checked=false means it could not test
  // (udp, or nothing observed yet) — not a failure. target_ok && !mesh_ok is the
  // one this page exists for: the app answers where this machine dials it but
  // not on the address peers use, i.e. it is bound to 127.0.0.1.
  checked?: boolean;
  target_ok?: boolean;
  mesh_ok?: boolean;
}

// MeshAdvertise is this node's subnet-router / exit-node role (GET/POST
// /v1/mesh/advertise). forwarding_supported is false off Linux — the node then
// advertises but doesn't actually forward.
export interface MeshAdvertise {
  routes: string[]; // subnet-router CIDRs this node advertises
  advertise_exit_node: boolean; // advertise this node AS an exit node
  exit_node: string; // route THIS node's default traffic through this peer
  forwarding_supported: boolean; // read-only; true only on Linux
  // The CONSUMER side: what this node accepts FROM peers. Off by default — an
  // accepted route lands in THIS machine's routing table and can hijack the
  // return path of connections to services this machine publishes.
  accept_routes?: boolean;
  route_excludes?: string[]; // refused even while accepting the rest
}
