// client.ts — HTTP wrapper around the daemon's local API surface.
//
// Two flavours of endpoint:
//   - Read endpoints (GET): no auth required (loopback bind).
//   - Write endpoints (POST/PUT/DELETE): require X-Local-Token. We
//     fetch the token on first write and cache it in memory; if the
//     daemon restarts and rotates the token, a write will get 401 and
//     we refetch + retry once.
//
// Errors throw an ApiError so React Query handles them uniformly.

import type {
  AccountMe,
  ClientDevicesList,
  ConnectionRow,
  CreateTunnelBody,
  CurrentUsage,
  EdgeAffinity,
  EdgeList,
  DomainList,
  Healthz,
  HTTPCaptureRow,
  IPPolicy,
  MemberQuotaRow,
  MeshAdvertise,
  MeshOrgNode,
  MeshServiceDecl,
  MeshStatus,
  OAuthPolicy,
  OrgListResponse,
  OrgSecurity,
  OrgSwitchResponse,
  ProbeHealth,
  ProbeCheck,
  ProbePort,
  RemoteTunnel,
  ReplayResponse,
  ServiceMode,
  Snapshot,
  TunnelList,
  UpdateTunnelBody,
  UpdateInfo,
  UpdatePolicy,
  UsageHistory,
  MeshUsage,
  SelfHostedJoin,
  SelfHostedStatus,
  SelfHostedTunnel,
  SelfHostedUsage,
} from "./types";

export class ApiError extends Error {
  status: number;
  body: any;
  constructor(message: string, status: number, body: any) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

let cachedLocalToken: string | null = null;

async function fetchLocalToken(): Promise<string> {
  const r = await fetch("/v1/local-token");
  if (!r.ok) {
    // Keep the body: a locked console answers {"error":"console_locked"}, and
    // main.tsx has to see that to send the page back to the unlock form.
    let body: any = null;
    try {
      body = await r.json();
    } catch {
      body = null;
    }
    throw new ApiError("could not fetch local-token", r.status, body);
  }
  const j = await r.json();
  cachedLocalToken = j.token as string;
  return cachedLocalToken;
}

async function getLocalToken(force = false): Promise<string> {
  if (!force && cachedLocalToken) return cachedLocalToken;
  return fetchLocalToken();
}

// Low-level fetch wrapper for write requests.
async function writeRequest(
  method: "POST" | "PUT" | "DELETE",
  path: string,
  body?: any,
  retried = false,
): Promise<Response> {
  const tok = await getLocalToken();
  const headers: Record<string, string> = {
    "X-Local-Token": tok,
  };
  let payload: BodyInit | undefined;
  if (body !== undefined && body !== null) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const r = await fetch(path, { method, headers, body: payload });
  if (r.status === 401 && !retried) {
    // Token rotated under us. One retry with a fresh token.
    await fetchLocalToken();
    return writeRequest(method, path, body, true);
  }
  return r;
}

async function jsonOrThrow<T>(r: Response): Promise<T> {
  const text = await r.text();
  let parsed: any = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  if (!r.ok) {
    const msg =
      (parsed && parsed.error) ||
      (typeof parsed === "string" ? parsed : `HTTP ${r.status}`);
    throw new ApiError(msg, r.status, parsed);
  }
  return parsed as T;
}

// viewerTZ is this browser's IANA timezone (e.g. "America/New_York",
// "Asia/Shanghai"). The usage endpoints forward it to metering-svc (via
// bff-console) so "今日" and the 近7天 chart bucket on the user's OWN wall clock
// in any country — the server stores UTC and localizes at read time. Empty when
// the browser can't report a zone; the server then falls back to UTC.
function viewerTZ(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  } catch {
    return "";
  }
}

// ---- read endpoints --------------------------------------------------------

export const api = {
  healthz: async (): Promise<Healthz> =>
    jsonOrThrow<Healthz>(await fetch("/healthz")),
  snapshot: async (): Promise<Snapshot> =>
    jsonOrThrow<Snapshot>(await fetch("/tunnels")),
  me: async (): Promise<AccountMe> =>
    jsonOrThrow<AccountMe>(await fetch("/v1/me")),
  // serviceMode tells the SPA whether the daemon is a pinned-identity agent
  // (read-only console) or interactive. Defaults to interactive when the
  // endpoint is missing (older daemon) so the UI degrades gracefully.
  serviceMode: async (): Promise<ServiceMode> => {
    try {
      return await jsonOrThrow<ServiceMode>(await fetch("/v1/service-mode"));
    } catch {
      return { mode: "interactive", agent: false, login_enabled: true };
    }
  },
  usage: async (): Promise<CurrentUsage> =>
    jsonOrThrow<CurrentUsage>(await fetch("/v1/usage/current")),
  // /v1/usage/current?period=today returns an UNCAPPED real-time SUM over
  // [today 00:00, now) in the VIEWER's timezone (tz forwarded below), which is
  // what the Overview's "今日流量" card wants — a live figure that advances every
  // refresh. /v1/usage/daily?tz=…&n=1 now also starts at today (i=0 = today), but
  // it settles per-bucket rather than tracking "now", so the card keeps using
  // this endpoint for the real-time number.
  usageToday: async (): Promise<CurrentUsage> =>
    jsonOrThrow<CurrentUsage>(
      await fetch("/v1/usage/current?period=today&tz=" + encodeURIComponent(viewerTZ())),
    ),
  // /v1/usage/daily — one bucket per day, most-recent first. With the viewer tz
  // forwarded, buckets are the viewer's calendar days and i=0 = TODAY (for n≤7,
  // served exact from the raw window); defaults to 30 buckets server-side.
  usageDaily: async (n = 30): Promise<UsageHistory> =>
    jsonOrThrow<UsageHistory>(
      await fetch("/v1/usage/daily?n=" + n + "&tz=" + encodeURIComponent(viewerTZ())),
    ),

  // This machine's Connect (mesh) traffic — today / month / last-N-days. Served
  // locally by the daemon (both editions), separate from the tunnel usage above.
  meshUsage: async (days = 7): Promise<MeshUsage> =>
    jsonOrThrow<MeshUsage>(await fetch("/v1/usage/mesh?days=" + days)),
  tunnels: async (): Promise<TunnelList> =>
    jsonOrThrow<TunnelList>(await fetch("/v1/tunnels")),
  // ONE tunnel, by id. The create flow's last step watches the row it just made
  // until an edge claims it — by id rather than by searching the list, because
  // a list is filtered (this daemon's device), paged and time-ordered, and none
  // of that has anything to do with whether this particular row exists. A 404
  // here is an answer; an absence from the list is not.
  tunnel: async (id: number): Promise<RemoteTunnel> =>
    jsonOrThrow<RemoteTunnel>(await fetch("/v1/tunnels/" + id)),
  // The org's tunnel-security baseline + its named IP policies. Both are
  // best-effort at every call site: a standalone daemon answers 501 (no org
  // exists to hold a baseline) and a control-plane blip must not stop somebody
  // creating a tunnel. tunnel-svc enforces the rule either way, so the worst
  // case of a failed read is the old behaviour — a refusal after submit.
  orgSecurity: async (): Promise<OrgSecurity> =>
    jsonOrThrow<OrgSecurity>(await fetch("/v1/org/security")),
  orgIPPolicies: async (): Promise<{ items: IPPolicy[] }> =>
    jsonOrThrow<{ items: IPPolicy[] }>(await fetch("/v1/org/ip-policies")),
  // The org's named login policies, offered by the per-tunnel security drawer.
  // Best-effort like the other two: standalone answers 501, and a tunnel that
  // already points at a policy keeps doing so whether or not we can list them.
  orgOAuthPolicies: async (): Promise<{ items: OAuthPolicy[] }> =>
    jsonOrThrow<{ items: OAuthPolicy[] }>(await fetch("/v1/org/oauth-policies")),
  // The caller's own member quota + current usage, so the create flow can grey
  // the button rather than refuse a filled-in form. Best-effort at the call
  // site: standalone answers 501 and an org with no member quotas returns no
  // row for us.
  memberQuotas: async (orgID: number): Promise<{ items: MemberQuotaRow[] }> =>
    jsonOrThrow<{ items: MemberQuotaRow[] }>(
      await fetch("/v1/orgs/" + orgID + "/member-quotas"),
    ),
  clients: async (): Promise<ClientDevicesList> =>
    jsonOrThrow<ClientDevicesList>(await fetch("/v1/clients")),
  // Edge directory — Tunnels page joins this against each row's
  // edge_node_id to render region + healthy state. Server caches at
  // 30s; the SPA polls every 30s so most calls are cache hits.
  edges: async (): Promise<EdgeList> =>
    jsonOrThrow<EdgeList>(await fetch("/v1/edges")),
  // Verified custom domains (BYOI) — the New-tunnel wizard offers these as a
  // dropdown so users pick a ready domain instead of typing an unverified one.
  domains: async (): Promise<DomainList> =>
    jsonOrThrow<DomainList>(await fetch("/v1/domains")),
  logsTail: async (n: number): Promise<{ lines: string[]; count: number }> =>
    jsonOrThrow(await fetch("/logs?tail=" + n)),

  // Connect (WireGuard mesh) status for the local node. enabled:false when no
  // `mesh:` block is configured; a 404 means the daemon build predates /v1/mesh.
  mesh: async (): Promise<MeshStatus> =>
    jsonOrThrow<MeshStatus>(await fetch("/v1/mesh")),

  // ---- write endpoints ----------------------------------------------------

  // Stop the mesh subsystem on this daemon (leave the meshnet). Local-token gated.
  // Reversible with meshUp. The org-wide kill switch is the web console.
  meshDown: async (): Promise<void> => {
    const r = await writeRequest("POST", "/v1/mesh/down");
    if (!r.ok && r.status !== 204) await jsonOrThrow(r);
  },

  // Resume mesh after meshDown (re-enroll immediately). Local-token gated.
  meshUp: async (): Promise<void> => {
    const r = await writeRequest("POST", "/v1/mesh/up");
    if (!r.ok && r.status !== 204) await jsonOrThrow(r);
  },

  // Subnet-router / exit-node role for this node.
  meshAdvertise: async (): Promise<MeshAdvertise> =>
    jsonOrThrow<MeshAdvertise>(await fetch("/v1/mesh/advertise")),

  // Set the role (routes / exit-node). Local-token gated; restarts the mesh
  // session so the change takes effect.
  // accept_routes / route_excludes are OPTIONAL on the wire: omitting a field
  // means "leave it unchanged", so an older page can't silently switch route
  // acceptance off when it saves the fields it knows about. alias_routes is
  // gone — aliasing is applied to every advertised route, so there is no subset
  // to send; the daemon drops the field if an older page still posts one.
  setMeshAdvertise: async (body: {
    routes: string[];
    advertise_exit_node: boolean;
    exit_node: string;
    accept_routes?: boolean;
    route_excludes?: string[];
    block_incoming?: boolean;
  }): Promise<MeshAdvertise> =>
    jsonOrThrow<MeshAdvertise>(await writeRequest("POST", "/v1/mesh/advertise", body)),

  // What this machine declares it offers on the mesh.
  meshServices: async (): Promise<{ items: MeshServiceDecl[] }> =>
    jsonOrThrow<{ items: MeshServiceDecl[] }>(await fetch("/v1/mesh/services")),

  // The ORG's mesh devices, proxied from bff-console — used only to label peers
  // with their owner. Absent on a local daemon and 401 for an api-key agent, so
  // every caller must treat a failure as "no labels" rather than an error worth
  // showing: the peer list is the page, the owner column is a nicety on top.
  meshOrgNodes: async (): Promise<{ items: MeshOrgNode[] }> =>
    jsonOrThrow<{ items: MeshOrgNode[] }>(await fetch("/v1/mesh/nodes")),

  // Replace the console-managed declarations. Local-token gated; restarts the
  // mesh session so the new set is re-declared to the coordinator.
  setMeshServices: async (items: MeshServiceDecl[]): Promise<{ items: MeshServiceDecl[] }> =>
    jsonOrThrow<{ items: MeshServiceDecl[] }>(
      await writeRequest("POST", "/v1/mesh/services", { items }),
    ),

  createTunnel: async (body: CreateTunnelBody): Promise<RemoteTunnel> =>
    jsonOrThrow<RemoteTunnel>(await writeRequest("POST", "/v1/tunnels", body)),

  deleteTunnel: async (id: number): Promise<void> => {
    const r = await writeRequest("DELETE", "/v1/tunnels/" + id);
    if (!r.ok && r.status !== 204) await jsonOrThrow(r);
  },

  // Edit a tunnel's name / local upstream. Only name + local_addr are
  // editable; the public endpoint (type / domain / port) is fixed. The server
  // re-pushes config so the owning daemon re-homes onto the new upstream.
  updateTunnel: async (id: number, body: UpdateTunnelBody): Promise<RemoteTunnel> =>
    jsonOrThrow<RemoteTunnel>(await writeRequest("PUT", "/v1/tunnels/" + id, body)),

  // Take over a tunnel that runs on (is bound to) another client — re-bind it
  // to THIS machine. localAddr is optional: the upstream service usually differs
  // on a different machine, so the modal lets the user set it. The public
  // endpoint is unchanged; the other client stops serving it.
  takeoverTunnel: async (id: number, localAddr?: string): Promise<RemoteTunnel> =>
    jsonOrThrow<RemoteTunnel>(
      await writeRequest("POST", "/v1/tunnels/" + id + "/takeover", {
        local_addr: localAddr ?? "",
      }),
    ),

  // Set a tunnel's IP access-control policy by replacing its config_json
  // (the SPA builds the full blob; empty clears the policy). Server validates
  // CIDRs + gates on the plan's ip_policy feature; the edge enforces it.
  setTunnelSecurity: async (id: number, configJSON: string): Promise<RemoteTunnel> =>
    jsonOrThrow<RemoteTunnel>(
      await writeRequest("POST", "/v1/tunnels/" + id + "/security", {
        config_json: configJSON,
      }),
    ),

  // Dismiss the M12 edge-switch banner. Fire-and-forget — the SPA
  // already invalidates the snapshot query so the next poll will see
  // edge_switch=null and stop rendering the banner.
  dismissEdgeSwitch: async (): Promise<void> => {
    const r = await writeRequest("POST", "/v1/edge-switch/dismiss");
    if (!r.ok && r.status !== 204) await jsonOrThrow(r);
  },

  exportConfig: async (): Promise<string> => {
    // Export is a GET with the local-token header (not a write per se,
    // but we gate it because the response is the full tunnel list +
    // could include sensitive workspace ids).
    const tok = await getLocalToken();
    const r = await fetch("/v1/config/export", {
      headers: { "X-Local-Token": tok },
    });
    if (r.status === 401) {
      await fetchLocalToken();
      return api.exportConfig();
    }
    if (!r.ok) throw new ApiError("export failed", r.status, null);
    return r.text();
  },

  importConfig: async (
    doc: any,
    dryRun: boolean,
  ): Promise<{ dry_run: boolean; total: number; items: any[] }> =>
    jsonOrThrow(
      await writeRequest(
        "POST",
        "/v1/config/import" + (dryRun ? "?dry_run=1" : ""),
        doc,
      ),
    ),

  // ---- M7-S5 probe + inspect ----------------------------------------------

  probePorts: async (): Promise<{ items: ProbePort[] }> =>
    jsonOrThrow(await fetch("/v1/probe/ports")),

  probeHealth: async (): Promise<{ items: ProbeHealth[]; enabled: boolean }> =>
    jsonOrThrow(await fetch("/v1/probe/health")),

  // One-shot check behind the new-tunnel wizard's 「检测」 button. The daemon
  // validates the address before dialling, so a public host comes back as
  // healthy:false with a reason rather than being probed.
  probeCheck: async (type: string, localAddr: string): Promise<ProbeCheck> =>
    jsonOrThrow(
      await writeRequest("POST", "/v1/probe/check", { type, local_addr: localAddr }),
    ),

  inspectConnections: async (proxyID: string): Promise<{ items: ConnectionRow[] }> =>
    jsonOrThrow(await fetch("/v1/inspect/connections?proxy_id=" + encodeURIComponent(proxyID))),

  inspectCaptures: async (proxyID: string): Promise<{ items: HTTPCaptureRow[] }> =>
    jsonOrThrow(await fetch("/v1/inspect/captures?proxy_id=" + encodeURIComponent(proxyID))),

  replay: async (proxyID: string, captureID: number): Promise<ReplayResponse> =>
    jsonOrThrow(
      await writeRequest("POST", "/v1/inspect/replay", {
        proxy_id: proxyID,
        capture_id: captureID,
      }),
    ),

  // ---- M7.1 in-window auth ------------------------------------------------

  // login does NOT require the local-token (chicken-and-egg). We POST
  // directly to /v1/auth/login; the daemon proxies to bff-console and
  // persists the returned tokens to creds.
  login: async (body: { email: string; password: string; totp_code?: string }) => {
    const r = await fetch("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        identifier: body.email,
        password: body.password,
        totp_code: body.totp_code,
      }),
    });
    return jsonOrThrow<{
      access_token: string;
      refresh_token: string;
      access_expires_in_sec: number;
      user_id: number;
      email: string;
    }>(r);
  },

  logout: async (): Promise<{ status: string }> =>
    jsonOrThrow(await writeRequest("POST", "/v1/auth/logout", {})),

  // ---- a self-hosted server (docs/runbook/self-hosted-sign-in-plan.md §6.2) ----
  // Both daemons answer: the calabi.net one says whether it can switch
  // (mode "platform"), the local one what it is connected to. A 404 is a daemon
  // from before this, which cannot switch at all.
  selfHosted: async (): Promise<SelfHostedStatus> =>
    jsonOrThrow<SelfHostedStatus>(await fetch("/v1/selfhosted")),
  // Connect to a coordinator, an edge, or both. The daemon then starts again in
  // the other mode ({switching: true}); failures carry {code, part, pin?}.
  joinSelfHosted: async (body: SelfHostedJoin): Promise<{ switching: boolean }> =>
    jsonOrThrow(await writeRequest("POST", "/v1/selfhosted/join", body)),
  // The person compared the certificate a server presents now with what the
  // server prints; the pin must be the one presented at this moment.
  trustSelfHosted: async (pin: string): Promise<unknown> =>
    jsonOrThrow(await writeRequest("POST", "/v1/selfhosted/trust", { part: "mesh", pin })),
  leaveSelfHosted: async (): Promise<{ switching: boolean }> =>
    jsonOrThrow(await writeRequest("POST", "/v1/selfhosted/leave", {})),
  // Every tunnel the meshnet's daemons reported, and its traffic, in the
  // viewer's time zone — from the coordinator, connected or not.
  selfHostedTunnels: async (): Promise<{ items: SelfHostedTunnel[] }> =>
    jsonOrThrow(await fetch("/v1/selfhosted/tunnels")),
  selfHostedUsage: async (days = 7): Promise<SelfHostedUsage> =>
    jsonOrThrow<SelfHostedUsage>(
      await fetch("/v1/selfhosted/usage?days=" + days + "&tz=" + encodeURIComponent(viewerTZ())),
    ),

  // ---- M11.7 multi-Org ----------------------------------------------------

  // listOrgs returns every Org the logged-in user belongs to plus the
  // currently-active one. Daemon proxies straight to bff-console
  // /v1/orgs — same shape, no extra enrichment.
  listOrgs: async (): Promise<OrgListResponse> =>
    jsonOrThrow<OrgListResponse>(await fetch("/v1/orgs")),

  // switchOrg mints a fresh JWT pair anchored to target_org_id on the
  // server, persists the new tokens to creds via the daemon, then kicks
  // the running edge session so the next dial re-binds. SPA's responsibility
  // after the promise resolves: invalidate queries + window.location.reload()
  // so every page re-renders against the new Org cleanly.
  //
  // Note: tokens are NOT echoed to the SPA — the daemon proxies all
  // bff-console calls with the stored bearer, so the SPA never needs to
  // see it. Mirrors web/console's pattern except web/console must hold
  // the bearer in localStorage (no daemon middleman).
  switchOrg: async (targetOrgID: number): Promise<OrgSwitchResponse> =>
    jsonOrThrow<OrgSwitchResponse>(
      await writeRequest("POST", "/v1/orgs/switch", {
        target_org_id: targetOrgID,
      }),
    ),

  // ---- manual region switch -----------------------------------------------

  // switchRegion persists the chosen edge region to creds (daemon side),
  // drops the sticky edge, and kicks the edge session to re-anchor to that
  // region. Cross-region auto-switch is otherwise disabled, so this is the
  // user's escape hatch when their region is down (lifecycle "unavailable")
  // or they simply want to move regions. After it resolves the SPA reloads
  // so every page re-queries against the new region's edge.
  switchRegion: async (region: string): Promise<{ region: string }> =>
    jsonOrThrow<{ region: string }>(
      await writeRequest("POST", "/v1/edge-region", { region }),
    ),

  // getEdgeAffinity reads the daemon's data-egress preference (own | platform).
  getEdgeAffinity: async (): Promise<EdgeAffinity> =>
    jsonOrThrow<EdgeAffinity>(await fetch("/v1/edge-affinity")),

  // setEdgeAffinity flips between the org's own BYOI edge and the platform
  // data plane. The daemon clears its edge anchor + re-anchors the session,
  // so the SPA reloads afterwards (same shape as switchRegion).
  setEdgeAffinity: async (affinity: "own" | "platform"): Promise<EdgeAffinity> =>
    jsonOrThrow<EdgeAffinity>(
      await writeRequest("POST", "/v1/edge-affinity", { affinity }),
    ),

  // ---- self-update ---------------------------------------------------------

  // updateInfo returns null when this daemon has no update agent: a dev build,
  // updates disabled, or any client older than the endpoint (all 404). Callers
  // render nothing rather than an error — "we don't know" is not a failure.
  updateInfo: async (): Promise<UpdateInfo | null> => {
    const r = await fetch("/v1/update");
    if (r.status === 404) return null;
    return jsonOrThrow<UpdateInfo>(r);
  },

  // updateCheck re-checks now. A failed check answers 502 WITH the snapshot, so
  // the card can keep showing the last known version next to the error.
  updateCheck: async (): Promise<UpdateInfo> => {
    const r = await writeRequest("POST", "/v1/update/check");
    if (r.status === 502) return (await r.json()) as UpdateInfo;
    return jsonOrThrow<UpdateInfo>(r);
  },

  // setUpdatePolicy changes the machine's update setting. The body MERGES: send
  // only what changed. Returns the fresh snapshot, already re-decided against
  // the new policy.
  setUpdatePolicy: async (body: Partial<UpdatePolicy>): Promise<UpdateInfo> =>
    jsonOrThrow<UpdateInfo>(await writeRequest("PUT", "/v1/update/policy", body)),

  // updateApply installs it. 409 = this machine cannot (see reason); the body is
  // still the snapshot. The daemon restarts itself on success, so the request
  // may simply never come back — the caller must not treat that as a failure.
  updateApply: async (): Promise<UpdateInfo> =>
    jsonOrThrow<UpdateInfo>(await writeRequest("POST", "/v1/update/apply")),

  // ---- remote access: the console's unlock secret --------------------------

  // consoleState: is this page being viewed from another machine, and has it
  // been unlocked? The daemon's guard answers it ahead of every other /v1 route,
  // so it works while locked. A daemon older than 1.9.0 has no such route (404);
  // callers treat any error as "not locked".
  consoleState: async (): Promise<ConsoleState> =>
    jsonOrThrow<ConsoleState>(await fetch("/v1/console/state")),

  // consoleUnlock trades the unlock secret for a session cookie the page never
  // sees (HttpOnly). No local token: a locked visitor cannot have one yet.
  consoleUnlock: async (secret: string): Promise<{ ok: boolean }> =>
    jsonOrThrow<{ ok: boolean }>(
      await fetch("/v1/console/unlock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ secret }),
      }),
    ),
};

// /v1/console/state — see the daemon's internal/status/console_unlock.go.
export interface ConsoleState {
  // true = show the unlock form instead of the console.
  locked: boolean;
  // Viewed from another machine (or through a reverse proxy).
  remote: boolean;
  // false = the daemon has no secret configured, so there is nothing to enter.
  unlock_available: boolean;
}

// isConsoleLocked: the daemon's answer to a visitor from another machine whose
// unlock is missing or has lapsed. Not an account problem — see AuthGate.
export function isConsoleLocked(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401 && e.body?.error === "console_locked";
}
