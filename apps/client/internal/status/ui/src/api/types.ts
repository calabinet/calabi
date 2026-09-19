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
  // Why, when status is "error". A CODE, not a sentence (`port_in_use:20000`)
  // — see tunnel-svc's IdleDisableReason for the convention. bff-console omits
  // the field entirely when there is nothing to say, and the daemon proxies
  // /v1/tunnels row-for-row, so it arrives here unchanged.
  status_reason?: string;
  edge_node_id?: number;
  config_json?: string;
  client_online?: boolean;
  // The edge the OWNING client's daemon is currently connected to. When it
  // differs from edge_node_id (where the domain is pinned) the public URL is
  // unreachable — the shared effectiveState() maps that to "mismatch". 0 = no
  // signal. Mirrors bff-console marshalTunnel's client_edge_node_id.
  client_edge_node_id?: number;
  // Upstream (local_addr) health as last reported by the OWNING daemon, and the
  // probe error when it failed. bff-console omits both when nothing has ever
  // reported, and the daemon proxies /v1/tunnels row-for-row — so absent here
  // means "nobody checked", NOT "healthy". effectiveState() maps that to
  // "unverified"; leaving the fields undeclared is what let this console call
  // an unchecked upstream "online" while the web console said otherwise.
  upstream_state?: "healthy" | "unhealthy" | string;
  upstream_error?: string;
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

// The org's tunnel-security baseline, as the create flow needs it: does this
// org refuse a tunnel that nobody is allowed to reach, and if the answer is
// yes, which policy does an unprotected create fall back to.
//
// A SUBSET of what bff-console GET /v1/org/security returns — the counts and
// the idle-disable setting belong to the web console's security page, which is
// where they are acted on. Read-only here: this machine's local console can see
// the rule it is held to, but changing what the whole ORG may create is not a
// decision to take from one desktop.
export interface OrgSecurity {
  require_protection: boolean;
  // The narrower rule: tcp/udp/sni must carry an IP allow list. Its own switch,
  // independent of require_protection — an org can govern raw ports without
  // governing every web tunnel.
  require_bare_port_protection: boolean;
  // Applied by tunnel-svc to a create that carries no protection. "" = none.
  default_ip_policy: string;
}

// A named IP access-control policy belonging to the org. Only `name` ever goes
// on the wire when a tunnel points at one — tunnel-svc expands it into
// addresses at create time, so a console can never ship a stale copy of a
// policy somebody just edited.
export interface IPPolicy {
  name: string;
  description: string;
  allow: string[] | null;
  deny: string[] | null;
  used_by: number;
}

// One member's quota row from GET /v1/orgs/{id}/member-quotas: what they are
// allowed and what they already hold. A plain member gets only their own row.
//
// `effective` is min(member, org) per dimension, -1 = unlimited. `used` is
// ABSENT when the member holds nothing at all — not zero-filled — so read it
// defensively. `exempt` means a manager with no quota set on them by name: the
// org default does not bind them.
export interface MemberQuotaRow {
  user_id: number;
  role: string;
  email?: string;
  exempt: boolean;
  effective?: Record<string, number>;
  used?: Record<string, number>;
}

// An organization's SSO application, stored once in the control plane and
// pointed at by name from a tunnel's config_json.security.oauth.from_policy.
//
// There is no `client_secret` field and there never will be: the server strips
// it from every read (a tunnel's config_json is visible to every member of a
// team org). `secret_set` is how the UI tells "configured, hidden" from "not
// configured" — an empty password box means neither on its own.
export interface OAuthPolicy {
  name: string;
  description: string;
  provider: string;
  client_id: string;
  secret_set: boolean;
  allow_emails: string[] | null;
  allow_domains: string[] | null;
  used_by: number;
}

// Edit a tunnel's mutable core fields. Omitted / undefined = leave unchanged.
// Only name + local_addr are editable; the public endpoint stays put.
export interface UpdateTunnelBody {
  name?: string;
  local_addr?: string;
}

export interface AccountMe {
  user: { id: number; email?: string };
  // The human who MINTED the API key this console runs under. Present ONLY in
  // agent mode, and only when the key records its creator — an older key has
  // nobody to name.
  //
  // Separate from `user` on purpose: an agent is not signed in as that person,
  // it holds a credential they issued. `user` stays {id:0} for an API key,
  // which is the truthful answer to "who authenticated" — nobody did.
  acting_user?: { id: number; email?: string };
  org: { id: number; name?: string };
  // Data-plane scopes of the bearer behind this console. Only an API-key
  // principal carries these (e.g. ["tunnel.read","tunnel.write"]); a login
  // session gets null. In agent mode the SPA reads this to decide whether the
  // pinned key may MANAGE tunnels (tunnel.write present) or is read-only.
  scopes?: string[] | null;
  plan: {
    code: string;
    // Gating subset of quota-svc features_json (tcp/udp/sni/custom_domain,
    // plus ip_policy/basic_auth for the create flow's 访问策略 step). Used to
    // disable protocol options and hide access controls the server would 403.
    // Mirrors apps/bff-console account.go which already returns this field.
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
  // Platform-wide display switches, proxied straight through from
  // bff-console /v1/account/me (statusapi forwards the body verbatim).
  // hide_commerce is the 运营设置 toggle that takes the commerce entry points
  // out of the web console; this UI uses it to stop telling people to
  // 升级套餐 when there is no place to do that.
  ui?: {
    hide_commerce?: boolean;
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
  // MagicDNS label, joined in from the netmap by the daemon. Absent when the
  // netmap has not arrived yet — render the short key then, never a blank.
  name?: string;
  // Services this peer offers. Confirmed ones only — the coordinator drops
  // unapproved declarations before the netmap, so anything here is something an
  // admin authorised and an access rule can match.
  services?: { name: string; proto: string; port: number }[];
  // Platform as the peer's own runtime reported it: "windows" / "linux" /
  // "darwin". Absent from a node that enrolled before it was collected.
  os?: string;
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
  // relay_rtt_micros is the round trip to the RELAY carrying this peer — ONE LEG
  // (this node to that relay), not end-to-end to the peer the way rtt_micros is.
  // A separate field, and rendered with its own label, because a relayed 12ms and
  // a direct 30ms are not comparable and one column of bare numbers invites
  // exactly that comparison.
  relay_rtt_micros?: number;
}

export interface MeshStatus {
  // subnet_aliases is the mapping for THIS node's own subnet routes when it
  // publishes a LAN that collides with consumers' own. Shown because nobody can
  // dial an address they cannot see.
  subnet_aliases?: { alias: string; real: string }[];
  // Routes that asked for a stand-in prefix and did not get one. They still work
  // for consumers that do not collide with them; the ones that DO collide cannot
  // reach them, silently — which is exactly why this is surfaced.
  unaliased_routes?: string[];
  // The org's alias budget and usage, in addresses (a /24 is 256), so the page
  // can say WHY rather than only THAT.
  alias_budget_addrs?: number;
  alias_used_addrs?: number;
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

// MeshOrgNode is one of the ORG's mesh devices as bff-console reports it
// (proxied through the daemon). Only the fields the peer table joins on are
// modelled — the console's own row is much wider.
export interface MeshOrgNode {
  id: number;
  name?: string;
  overlay: string; // the join key: a peer's allowed_ips carries this as a /32
  owner_user_id: number;
  owner_email?: string; // resolved by bff-console; absent for unattributed
  // Needed to tell "the rules do not let you reach it" apart from "nobody can
  // reach it". A parked or not-yet-approved device is in nobody's netmap, so
  // counting it as blocked-by-policy would send someone to argue with an admin
  // about a rule that is not the problem.
  approved?: boolean;
  disabled?: boolean;
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
  // This machine's own refusal of inbound CONNECTIONS, whatever the org's access
  // rules allow. Replies to conversations it started still come back. Optional
  // because an older daemon does not report it.
  block_incoming?: boolean;
  // alias_supported is read-only, and a CAPABILITY rather than a setting: every
  // advertised route is published under a stand-in prefix, so the only question
  // is whether this host can install the rewrite (Linux + iptables NETMAP).
  // Optional because an older daemon does not report it — undefined must not be
  // rendered as "unsupported".
  alias_supported?: boolean;
}

// UpdateInfo — GET /v1/update (the daemon's selfupdate agent).
//
// `available` and `can_apply` are SEPARATE on purpose. A Linux or agent install
// can be out of date (available) while having nothing it can install itself
// (can_apply=false, reason="no-artifact") — that is the "有新版本，请手动更新"
// state, not an error. See docs/runbook/client-update-policy.md §4.1.
export interface UpdateInfo {
  current: string;
  latest?: string;
  available: boolean;
  has_artifact: boolean;
  can_apply: boolean;
  rollback?: boolean;
  // Why can_apply is false: no-artifact | artifact-unsigned | artifact-foreign |
  // unsupported-platform | not-privileged.
  reason?: string;
  checked_at: string;
  // Security release: installs under "security only" and skips the window.
  critical?: boolean;
  // Below the manifest's min_supported: installs whatever the setting says.
  // The one case where "tell me only" is not honoured.
  mandatory?: boolean;
  // The machine's update setting.
  policy: UpdatePolicy;
  // Would a ROUTINE update install itself here (mode auto AND can_apply).
  // Critical releases also install under "security"; read policy.mode for the
  // whole answer.
  auto: boolean;
  // Why an installable update is NOT being installed right now:
  // notify-only | security-only | outside-window | busy. Empty = nothing
  // waiting. Different from `reason`, which is why it CANNOT be installed here.
  hold?: string;
  // When the max-defer backstop expires for a held version — or, for a
  // "rollout" hold, when this machine's turn is expected.
  hold_until?: string;
  // The org's requirement (U5c), when one applies. `policy` stays the machine's
  // own choice; the daemon acts on the stricter of the two.
  org_policy?: OrgUpdatePolicy;
  // The MACHINE's timezone abbreviation. The window is on this clock, not the
  // browser's — the restart happens on the machine.
  timezone?: string;
  // idle | checking | updating | failed
  state: string;
  error?: string;
}

export interface OrgUpdatePolicy {
  org_id: number;
  // "" | security | auto
  min_mode?: string;
  // Upper bound on max_defer_days. Absent = no bound.
  max_defer_days?: number;
}

// UpdatePolicy — the machine's update setting. PUT /v1/update/policy merges,
// so a partial body only changes the fields it names.
export interface UpdatePolicy {
  // auto | security | notify
  mode: string;
  // Hours on the MACHINE's clock, half-open [start, end). Equal = no window.
  window_start_hour: number;
  window_end_hour: number;
  // How long the window and the busy check may hold a routine update back.
  // 0 = they may not hold it at all.
  max_defer_days: number;
}

// ---- a self-hosted server (GET /v1/selfhosted) ------------------------------

// The coordinator this device joined, as the local daemon reports it.
// cert_presented / cert_pinned: it now presents a certificate its saved trust
// refuses — a person compares it with what the server prints.
export interface SelfHostedPart {
  server: string;
  trust?: "system" | "pin" | "ca" | "plaintext";
  pins?: string[];
  cert_presented?: string;
  cert_pinned?: string;
}

// Why this device's tunnels are or are not up. The edge, its certificate and
// the sign-in all come from the coordinator (docs/runbook/self-hosted-server-plan.md).
export type SelfHostedEdgeState =
  | "connected"
  | "connecting"
  | "no_edge"
  | "awaiting_approval"
  | "needs_invite"
  | "disabled"
  | "not_joined";

export interface SelfHostedStatus {
  // "platform": the calabi.net daemon (can_join says whether it may switch).
  // "self_hosted": the local daemon.
  mode: "platform" | "self_hosted";
  can_join?: boolean;
  reason?: string;
  // Local daemon only. managed: the config is the console's own; can_leave:
  // it may also switch back to calabi.net.
  managed?: boolean;
  can_leave?: boolean;
  config_path?: string;
  tunnels?: number;
  mesh?: SelfHostedPart & {
    state: "connected" | "connecting" | "paused" | "off" | "cert_changed" | "needs_invite" | "disabled";
    node_id?: number;
    reauth?: boolean;
  };
  // The edge the coordinator names for this device's tunnels; present once
  // joined. server is missing until the coordinator has named one.
  edge?: { server?: string; connected: boolean; state: SelfHostedEdgeState; error?: string };
}

export interface SelfHostedJoin {
  mesh: { link?: string; server?: string; key?: string; pin?: string; plaintext?: boolean };
  replace?: boolean;
}

export interface SelfHostedTunnel {
  id: number;
  name: string;
  type: string;
  public_addr: string;
  local_addr: string;
  status: string; // online | pending | offline (offline whenever its device is)
  node_id: number;
  node_name: string;
  node_online: boolean;
  traffic_30d: number;
  first_seen: string;
  reported_at?: string;
}

export interface SelfHostedUsage {
  unavailable?: string; // "no_database": the coordinator keeps no traffic
  relay_not_recorded?: boolean;
  month?: { tunnel_bytes: number; relay_bytes: number; from: string; to: string };
  days: { start: string; bytes: number }[];
  devices: { used: number; disabled: number; limit: number };
}
