// Package statusapi owns the /v1/* HTTP surface the calabi daemon
// exposes on 127.0.0.1:7400 for the browser UI to drive.
//
// Why a separate package, not just more handlers in internal/status?
//
//   - status (read-only) stays dependency-free; this package pulls in
//     net/http reverse-proxying, creds, JWT refresh — heavier surface
//     we don't want bleeding into every test that touches the status
//     page.
//   - Cycle avoidance: internal/status defines the State type; api
//     would otherwise need a State to render `/v1/me`, status would
//     need api to register routes, classic import cycle.
//
// What's in here:
//
//   - A thin reverse-proxy to bff-console for tunnel CRUD + usage. We
//     inject the bearer token from creds.Config.AccessToken (or APIKey
//     if no access token). On 401 we attempt one refresh via
//     /v1/auth/refresh and retry, then give up to surface to the UI.
//   - GET /v1/local-token returns the freshly-minted token so the SPA
//     can stamp it on subsequent write requests as X-Local-Token.
//   - Local-token middleware wraps all WRITE endpoints (POST/PUT/DELETE).
//     Read endpoints stay open (loopback bind = trust boundary).
//   - Config import/export — wrappers that round-trip the tunnel list
//     through bff-console as a self-contained JSON document.
//
// Naming note: package name is `statusapi` (one word, no dash) so the
// import path stays Go-conventional. Internally we call it "the write
// API" in comments to keep it distinct from the read-side status page.
package statusapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/inspect"
	"github.com/calabi/calabi/apps/client/internal/probe"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Config wires the api server with its external endpoints. Zero value
// is unusable — callers must set BFFConsoleURL.
type Config struct {
	// BFFConsoleURL is the base URL the daemon proxies tunnel CRUD to.
	// Trailing slash optional. Default in dev: http://127.0.0.1:8081.
	BFFConsoleURL string
	// ConsoleWebURL is the WEB console origin (where a human registers and
	// manages their account in a browser) — surfaced to the SPA via
	// /v1/service-mode so the login page can link to sign-up. Distinct from
	// BFFConsoleURL: in production the API host and the web console are
	// different origins, so one can't be derived from the other. Empty = the
	// SPA hides the link instead of offering a dead one.
	ConsoleWebURL string
	// HTTPClient overrides the http.Client used for outbound bff-console
	// calls. Default has 15s timeout. Tests stub this with a httptest
	// server-pointing client.
	HTTPClient *http.Client

	// optional probe + inspector hooks. Nil = the corresponding
	// /v1/probe and /v1/captures endpoints return 503 "feature disabled".
	HealthMonitor *probe.Monitor
	Inspector     InspectorSource

	// Mesh is the platform daemon's Connect (WireGuard mesh) status source,
	// backing GET /v1/mesh + POST /v1/mesh/down on the :7400 console. Wired by
	// main to the mesh enrollment controller (daemon_mesh_platform.go). Nil = no
	// mesh subsystem → the endpoints 404 (the SPA renders "unavailable on this
	// daemon"), which is the pre-MESH platform-daemon behaviour.
	Mesh MeshStatusSource
	// LocalAddrFor returns the local_addr for a given proxy_id (used
	// by the replay endpoint to know where to POST). Nil disables replay.
	LocalAddrFor func(proxyID string) string

	// OnLoginSucceeded fires asynchronously after a successful SPA
	// login (creds persisted). Wired by main to call
	// clientreg.Ensure so the desktop machine appears in /v1/clients
	// immediately — without this the wizard's defaultClientId is
	// empty until the daemon's 15-second reconnect tick happens to
	// re-register on handshake. Nil = no-op (CLI / dev mode).
	OnLoginSucceeded func()

	// OnOrgSwitched fires after a successful /v1/orgs/switch where
	// new tokens were persisted to creds. main wires this to cancel
	// the in-flight edge session so the next dial re-binds to the
	// freshly-active Org — without this the running session keeps
	// quotas + tunnel claims tied to the previous Org until it
	// naturally disconnects. Nil = no-op.
	OnOrgSwitched func()

	// OnLogout fires after a successful SPA logout where the bearer
	// has been cleared from creds. main wires this to wipe the local
	// tunnel snapshot AND tear down the in-flight edge session — the
	// session is still holding an in-memory bearer that's now revoked
	// on identity-svc, so the user's intent ("log me out") needs the
	// data-plane closure too. Without this, presence + tunnel claims
	// stay live until the existing TCP connection naturally times
	// out (could be minutes). Nil = no-op.
	OnLogout func()

	// OnEdgeSwitchDismiss fires when the SPA's edge-switch banner is
	// dismissed by the user (POST /v1/edge-switch/dismiss). main wires
	// this to status.State.ClearEdgeSwitch so the banner doesn't pop
	// back on the next poll. Nil = no-op (the endpoint still returns
	// 204 so the SPA doesn't show a spurious error).
	OnEdgeSwitchDismiss func()

	// OnRegionSwitched fires after the SPA picks a new edge region
	// (POST /v1/edge-region) and the handler persisted it into creds.
	// main wires this to wipe the local tunnel snapshot + clear any stale
	// edge-switch banner + tear down the in-flight edge session, so the
	// next dial re-anchors to the chosen region. Same teardown shape as
	// OnOrgSwitched — the daemon is one live data-plane session, so a
	// region change is logout+login on the data plane. Nil = no-op.
	OnRegionSwitched func()

	// AgentMode pins the local console to ONE identity: the daemon's
	// long-lived API key (a service installed via `daemon install
	// --api-key …`, or CALABI_API_KEY in the env). In this mode :7400 is a
	// READ-ONLY window onto that pinned identity — the interactive login
	// portal and every creds/cloud-mutating write are refused (403), so a
	// browser on the loopback box can't sign in as a DIFFERENT user and
	// silently re-bind the running service to themselves (the identity-
	// hijack the user reported on 2026-06-25). False = interactive mode
	// (desktop / a service installed without a key): the login portal is
	// live and the logged-in human IS the identity. Derived once at daemon
	// boot from the resolved credential kind — stable for the process.
	AgentMode bool
}

// InspectorSource is what statusapi needs from the daemon's inspector.
// Kept as an interface so the api package doesn't import cmd/.
type InspectorSource interface {
	SnapshotConnections(proxyID string) []inspect.Connection
	SnapshotCaptures(proxyID string) []inspect.HTTPCapture
	GetCapture(proxyID string, captureID uint64) *inspect.HTTPCapture
}

// Server holds the proxy + handler state. One per daemon process.
type Server struct {
	logger     *slog.Logger
	cfg        Config
	httpClient *http.Client

	// refreshMu serializes concurrent refresh attempts so we don't fire
	// 10 refresh-token grants when the page loads 10 widgets at once.
	refreshMu sync.Mutex
	// lastRefreshAt rate-limits refresh attempts (defense in depth
	// against a stuck refresh loop). 30s cooldown.
	lastRefreshAt time.Time

	// cache memoizes GET responses for the high-poll endpoints.
	// cache.go for the TTL table and invalidation rules.
	cache *responseCache
}

// New builds a Server with sensible defaults.
func New(logger *slog.Logger, cfg Config) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &Server{
		logger:     logger.With("component", "client.statusapi"),
		cfg:        cfg,
		httpClient: hc,
		cache:      newResponseCache(),
	}
}

// Register attaches every /v1/* route to mux. Called from status.Server.Run.
//
// Routing convention:
//   - Reads (GET): open. Loopback bind = trust enough.
//   - Writes (POST/PUT/DELETE): wrapped with requireLocalToken.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/local-token", s.handleLocalToken)

	// Lets the SPA discover whether this daemon is a pinned-identity agent
	// (read-only console, no login) or interactive (login portal live).
	// Open read — the SPA fetches it before /v1/me to decide what to render.
	mux.HandleFunc("GET /v1/service-mode", s.handleServiceMode)

	// in-window auth. Login MUST NOT require the local-token
	// (chicken-and-egg: the SPA can't fetch /v1/local-token before
	// the user identifies themselves — that endpoint is open, but
	// the user needs to know to send the token on later writes).
	// Logout requires it because by then the SPA has fetched it.
	// agentBlock additionally refuses both in agent mode: a pinned-key
	// service has no interactive session to start or end. (Login keeps no
	// local-token; logout composes with requireLocalToken as before.)
	mux.HandleFunc("POST /v1/auth/login", s.agentBlock(s.handleAuthLogin))
	mux.HandleFunc("POST /v1/auth/logout", s.agentBlock(s.requireLocalToken(s.handleAuthLogout)))

	// Account / org context for the UI's header.
	mux.HandleFunc("GET /v1/me", s.proxyGET("/v1/account/me"))
	// Org switcher surface: list memberships + switch active Org.
	// switch is a guarded write (local-token required) since it rotates
	// the bearer in creds; the GET stays open (loopback bind).
	mux.HandleFunc("GET /v1/orgs", s.proxyGET("/v1/orgs"))
	mux.HandleFunc("POST /v1/orgs/switch", s.agentBlock(s.requireLocalToken(s.handleOrgSwitch)))
	mux.HandleFunc("GET /v1/usage/current", s.proxyGET("/v1/usage/current"))
	mux.HandleFunc("GET /v1/usage/history", s.proxyGET("/v1/usage/history"))
	mux.HandleFunc("GET /v1/usage/daily", s.proxyGET("/v1/usage/daily"))

	// Tunnel CRUD — read open, writes guarded.
	// list goes through a custom proxy that post-filters by
	// this daemon's device_id. Without that filter, a daemon running
	// in a team Org sees every member's tunnels, but it can only
	// actually claim its own — the rest just sit "offline" with no
	// way for the local user to fix them. Filter at the daemon layer
	// (not in bff-console) so the user-side web console keeps showing
	// the full team list and only this single-machine SPA gets the
	// narrower view.
	mux.HandleFunc("GET /v1/tunnels", s.handleListMyTunnels)
	mux.HandleFunc("GET /v1/tunnels/{id}", s.proxyGETPath("/v1/tunnels/", "id"))
	// Tunnel management is NOT identity-blocked in agent mode: a pinned
	// API-key agent may create/edit/delete its OWN org's tunnels from :7400,
	// exactly like a logged-in console — that's the point of a "management"
	// key. The real gate is bff-console, which refuses these writes unless the
	// key carries the tunnel.write scope (read-only keys → 403 upstream, which
	// the SPA pre-empts by hiding the controls). This is distinct from the
	// identity-rebinding endpoints (login/logout/org-switch), which stay
	// agent-blocked because a pinned agent has no interactive session to swap.
	mux.HandleFunc("POST /v1/tunnels", s.requireLocalToken(s.handleCreateTunnel))
	mux.HandleFunc("DELETE /v1/tunnels/{id}", s.requireLocalToken(s.proxyDeletePath("/v1/tunnels/", "id")))
	mux.HandleFunc("PUT /v1/tunnels/{id}", s.requireLocalToken(s.proxyBodyPath("PUT", "/v1/tunnels/", "id")))
	// IP access-control policy edit — proxyBodyPath can't append a suffix, so
	// a tiny dedicated handler forwards to /v1/tunnels/{id}/security.
	mux.HandleFunc("POST /v1/tunnels/{id}/security", s.requireLocalToken(s.handleTunnelSecurity))
	// Takeover: re-bind a tunnel created on / running on another client to THIS
	// machine. Tunnel management (not identity), so allowed for a management key
	// too — bff-console enforces the tunnel.write scope upstream.
	mux.HandleFunc("POST /v1/tunnels/{id}/takeover", s.requireLocalToken(s.handleTunnelTakeover))

	// Devices — useful for the tunnel wizard so the UI can pick the
	// "this machine" client_id rather than make the user paste it.
	mux.HandleFunc("GET /v1/clients", s.proxyGET("/v1/clients"))

	// Edges directory — the SPA's tunnel-list 「Edge」 column uses this
	// to enrich each row with region + healthy state (we ship the bare
	// edge_node_id on the tunnel; the directory gives it a human label).
	// Cached at 30s (see ttlFor below); the underlying identity-svc
	// query is already cheap but caching saves a round-trip per SPA
	// open + per polling tick.
	mux.HandleFunc("GET /v1/edges", s.proxyGET("/v1/edges"))

	// Verified custom domains — the New-tunnel wizard offers these as a
	// dropdown (only verified ones are usable), tagged with cert status.
	mux.HandleFunc("GET /v1/domains", s.proxyGET("/v1/domains"))

	// Plans + subscription mirroring so the UI knows the quota.
	mux.HandleFunc("GET /v1/plans", s.proxyGET("/v1/plans"))
	mux.HandleFunc("GET /v1/subscriptions/me", s.proxyGET("/v1/subscriptions/me"))

	// Config import/export — operates on top of /v1/tunnels.
	mux.HandleFunc("GET /v1/config/export", s.requireLocalToken(s.handleConfigExport))
	// Bulk tunnel import is tunnel management, not identity — same posture as
	// the per-tunnel writes above (bff-console enforces tunnel.write per row).
	mux.HandleFunc("POST /v1/config/import", s.requireLocalToken(s.handleConfigImport))

	// probe + inspector. All open (read-only diagnostics).
	mux.HandleFunc("GET /v1/probe/ports", s.handleProbePorts)
	mux.HandleFunc("GET /v1/probe/health", s.handleProbeHealth)
	// One-shot reachability check for the new-tunnel wizard. POST because it
	// dials; open like the other probes because probe.CheckOnce refuses any
	// target a tunnel would refuse to forward to.
	mux.HandleFunc("POST /v1/probe/check", s.handleProbeCheck)
	mux.HandleFunc("GET /v1/inspect/connections", s.handleInspectConnections)
	mux.HandleFunc("GET /v1/inspect/captures", s.handleInspectCaptures)
	mux.HandleFunc("POST /v1/inspect/replay", s.requireLocalToken(s.handleInspectReplay))

	//sticky: dismiss the edge-switch banner. The current edge_switch
	// payload sits in status.State; the SPA shows a yellow Alert when
	// snapshot.edge_switch is non-null. Clicking close calls this
	// endpoint, daemon clears the payload, the next snapshot poll has
	// edge_switch=null and the banner stays gone until another switch
	// fires (a different daemon process or a true mid-run flip).
	mux.HandleFunc("POST /v1/edge-switch/dismiss", s.requireLocalToken(s.handleEdgeSwitchDismiss))

	// Manual region switch. The SPA's top-bar region dropdown POSTs
	// {"region":"cn-x"} here; we persist it as the daemon's preferred
	// region (creds.EdgeRegion), drop the sticky edge so the picker
	// fresh-selects inside the new region, and fire OnRegionSwitched to
	// rebind the edge session. This is the user-driven escape hatch now
	// that cross-region auto-switch is disabled — see edgepicker's
	// RestrictToRegion + the reconnect loop's park-after-N behaviour.
	// NOT agent-blocked: region is data-plane ROUTING, not identity. A pinned
	// agent operator may steer which region/edge the agent connects to from the
	// local console (it doesn't change WHO the agent is). See agentBlock.
	mux.HandleFunc("POST /v1/edge-region", s.requireLocalToken(s.handleEdgeRegionSwitch))

	// BYOI soft-affinity toggle. A BYOI org's daemon defaults to its OWN
	// self-hosted edge; the user may opt onto the platform data plane (they
	// paid for the plan). GET reads the current preference; POST flips it,
	// clears the edge/region anchor, and kicks the session to re-pick. The
	// SPA only surfaces the toggle when the org actually owns an edge
	// (any GET /v1/edges item with owned=true).
	mux.HandleFunc("GET /v1/edge-affinity", s.handleEdgeAffinityGet)
	// NOT agent-blocked (same rationale as edge-region): egress affinity is
	// data-plane routing (own vs platform edge), not identity.
	mux.HandleFunc("POST /v1/edge-affinity", s.requireLocalToken(s.handleEdgeAffinitySwitch))

	// Connect (WireGuard mesh) — the node's live status for the SPA's Connect
	// page. Read open (loopback bind). `down` is a guarded LOCAL pause (until
	// daemon restart); it is NOT agent-blocked because mesh participation is
	// data-plane, not identity — same posture as edge-region/affinity. The
	// org-wide kill switch is the web console's node-disable (MESH.8b).
	mux.HandleFunc("GET /v1/mesh", s.handleMesh)
	mux.HandleFunc("POST /v1/mesh/down", s.requireLocalToken(s.handleMeshDown))
	mux.HandleFunc("POST /v1/mesh/up", s.requireLocalToken(s.handleMeshUp))
	// Subnet-router / exit-node role. Read open; the write is local-token gated
	// but NOT agent-blocked (data-plane routing config, like edge-region).
	mux.HandleFunc("GET /v1/mesh/advertise", s.handleMeshAdvertiseGet)
	mux.HandleFunc("POST /v1/mesh/advertise", s.requireLocalToken(s.handleMeshAdvertiseSet))
	// Locally declared services. Read open (loopback bind); the write is
	// local-token gated but NOT agent-blocked — declaring what this machine
	// offers is data-plane config, like edge-region/advertise. It is only a
	// CLAIM either way: an admin confirms it in the web console before any
	// ACL rule matches, so a local operator cannot grant themselves access.
	mux.HandleFunc("GET /v1/mesh/services", s.handleMeshServicesGet)
	mux.HandleFunc("POST /v1/mesh/services", s.requireLocalToken(s.handleMeshServicesSet))
}

// handleEdgeAffinityGet reports the daemon's current edge affinity:
// {"affinity":"own"|"platform","prefer_platform":bool}.
func (s *Server) handleEdgeAffinityGet(w http.ResponseWriter, _ *http.Request) {
	prefer := false
	if cfg, _ := creds.Load(); cfg != nil {
		prefer = cfg.PreferPlatformEdge
	}
	aff := "own"
	if prefer {
		aff = "platform"
	}
	writeJSON(w, http.StatusOK, map[string]any{"affinity": aff, "prefer_platform": prefer})
}

// handleEdgeAffinitySwitch persists the chosen affinity and, when it changes,
// clears the edge/region anchor (LastEdgeNodeID/LastEdgeRegion) so the next
// pick re-evaluates, then kicks the edge session (OnRegionSwitched — same
// data-plane re-anchor teardown a region switch uses). Body: {"affinity":
// "own"|"platform"}.
func (s *Server) handleEdgeAffinitySwitch(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req struct {
		Affinity string `json:"affinity"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	aff := strings.ToLower(strings.TrimSpace(req.Affinity))
	if aff != "own" && aff != "platform" {
		writeError(w, http.StatusBadRequest, "affinity must be 'own' or 'platform'")
		return
	}
	preferPlatform := aff == "platform"

	cfg, _ := creds.Load()
	if cfg == nil {
		cfg = &creds.Config{}
	}
	if cfg.PreferPlatformEdge == preferPlatform {
		// No-op switch — already on this affinity. Still kick the session so a
		// parked daemon retries (mirrors the region-switch no-op behaviour).
		if s.cfg.OnRegionSwitched != nil {
			s.cfg.OnRegionSwitched()
		}
		writeJSON(w, http.StatusOK, map[string]string{"affinity": aff})
		return
	}
	cfg.PreferPlatformEdge = preferPlatform
	// Affinity change → clear the anchor so the picker re-evaluates from
	// scratch (a stale region lock would otherwise pin the old edge). We must
	// clear EdgeRegion too, not just the sticky LastEdgeRegion: effectiveRegion
	// (daemon.go) prefers EdgeRegion, so a region the user manually picked for
	// the OLD class (e.g. a self-hosted-only region like "my-vps-hk") would keep
	// RestrictToRegion on and — since that region has no edge of the NEW class —
	// the picker's narrowByOwnership would fall back to the wrong-class edge in
	// it, leaving the daemon on the self-hosted edge after switching to platform.
	// Clearing it re-anchors to any region of the new class.
	cfg.LastEdgeNodeID = 0
	cfg.LastEdgeRegion = ""
	cfg.EdgeRegion = ""
	if err := creds.Save(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "persist affinity: "+err.Error())
		return
	}
	s.logger.Info("SPA edge affinity switch", "affinity", aff)
	if s.cfg.OnRegionSwitched != nil {
		s.cfg.OnRegionSwitched()
	}
	writeJSON(w, http.StatusOK, map[string]string{"affinity": aff})
}

// handleEdgeRegionSwitch persists the user-selected region into creds and
// kicks the edge session so the daemon re-anchors to it. Body:
// {"region":"cn-hangzhou"}. We clear LastEdgeNodeID so the picker does a
// fresh load-balanced pick inside the new region instead of trying to
// stick to an edge that lives in the OLD region (which the region-locked
// query would filter out anyway).
func (s *Server) handleEdgeRegionSwitch(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req struct {
		Region string `json:"region"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	req.Region = strings.TrimSpace(req.Region)
	if req.Region == "" {
		writeError(w, http.StatusBadRequest, "region required")
		return
	}
	cfg, _ := creds.Load()
	if cfg == nil {
		cfg = &creds.Config{}
	}
	if cfg.EdgeRegion == req.Region {
		// No-op switch — the daemon is already anchored here. Still kick
		// the session: the user likely clicked this to force a retry out
		// of a parked (LifecycleUnavailable) state in the same region.
		if s.cfg.OnRegionSwitched != nil {
			s.cfg.OnRegionSwitched()
		}
		writeJSON(w, http.StatusOK, map[string]string{"region": req.Region})
		return
	}
	cfg.EdgeRegion = req.Region
	// Drop sticky — the old edge is in the previous region; a fresh
	// load-balanced pick inside the new region is what we want.
	cfg.LastEdgeNodeID = 0
	if err := creds.Save(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "persist region: "+err.Error())
		return
	}
	s.logger.Info("SPA region switch", "region", req.Region)
	if s.cfg.OnRegionSwitched != nil {
		s.cfg.OnRegionSwitched()
	}
	writeJSON(w, http.StatusOK, map[string]string{"region": req.Region})
}

// handleEdgeSwitchDismiss invokes the configured callback (set by main
// to status.State.ClearEdgeSwitch) and returns 204. Nil callback is
// silently OK so older daemon binaries still answer 204 — the SPA
// treats this as fire-and-forget either way.
func (s *Server) handleEdgeSwitchDismiss(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.OnEdgeSwitchDismiss != nil {
		s.cfg.OnEdgeSwitchDismiss()
	}
	w.WriteHeader(http.StatusNoContent)
}

// agentBlock refuses a request with 403 when the daemon runs in agent
// mode (a pinned API-key identity). Wrap ONLY the IDENTITY endpoints with it —
// login, logout, org-switch: the whole point of agent mode is that a local
// operator can't sign in as a DIFFERENT user (or switch the org) and silently
// re-bind the running service to themselves (the identity-hijack).
//
// Data-plane ROUTING (edge-region / edge-affinity) is deliberately NOT wrapped:
// it only steers which edge/region the pinned identity connects to — it doesn't
// change WHO the agent is — so an agent operator may adjust it from :7400.
//
// Tunnel management (create/edit/delete/security/import) is deliberately NOT
// wrapped — a management key may run those from :7400 just like a logged-in
// console; bff-console enforces the tunnel.write scope upstream.
//
// In interactive mode it's a transparent pass-through. Compose OUTSIDE
// requireLocalToken so login (which carries no local-token by design) is still
// blocked in agent mode.
func (s *Server) agentBlock(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AgentMode {
			writeError(w, http.StatusForbidden,
				"this client runs as a pinned API-key agent; sign-in, sign-out and org switching are managed from the web console")
			return
		}
		next(w, r)
	}
}

// handleServiceMode tells the SPA whether this daemon is a pinned-identity
// agent (login portal disabled) or interactive (login live). The SPA fetches
// it before /v1/me to decide what chrome to render. Whether an AGENT may
// manage tunnels locally is a separate axis the SPA derives from the pinned
// key's scopes (account/me → tunnel.write), since bff-console — not the daemon
// — is the authority on that.
func (s *Server) handleServiceMode(w http.ResponseWriter, _ *http.Request) {
	mode := "interactive"
	if s.cfg.AgentMode {
		mode = "agent"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":  mode,
		"agent": s.cfg.AgentMode,
		// read_only retained for one release as an alias of agent so a stale
		// cached SPA bundle doesn't mis-render; new SPA reads "agent".
		"read_only":     s.cfg.AgentMode,
		"login_enabled": !s.cfg.AgentMode,
		// Where the login page sends people to register. Baked at build time
		// (main.defaultConsoleWeb), overridable via $CALABI_CONSOLE_WEB so a
		// self-hosted deployment points at its own console. Empty → the SPA
		// omits the link rather than linking somewhere dead.
		"console_web": s.cfg.ConsoleWebURL,
	})
}

// requireLocalToken is the middleware applied to write endpoints. The
// SPA stamps X-Local-Token on every fetch() once it fetches the value
// from /v1/local-token. Constant-time compare + always-disk read so
// daemon restarts invalidate stale tokens.
func (s *Server) requireLocalToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Local-Token")
		if got == "" {
			// Fall-back: some browsers strip custom headers from
			// EventSource; allow query-param for SSE-shaped writes
			// (we don't have any today, but the wiring is cheap).
			got = r.URL.Query().Get("local_token")
		}
		if !creds.CompareLocalToken(got) {
			writeError(w, http.StatusUnauthorized, "local-token mismatch (fetch /v1/local-token)")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleLocalToken(w http.ResponseWriter, r *http.Request) {
	tok, err := creds.LoadLocalToken()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "local-token not yet minted")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

// handleAuthLogin proxies /v1/auth/login to bff-console, persists the
// returned tokens into the local creds file, and returns the same
// body to the SPA. lets the user log in inside the desktop
// window instead of opening a terminal for `calabi login`.
//
// Why write through to creds: the daemon's reconnect loop reads
// creds on every retry, so persisting here means the next 15s tick of
// the reconnect loop will pick up the new credentials and successfully
// connect to the edge — no daemon restart required.
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.BFFConsoleURL == "" {
		writeError(w, http.StatusServiceUnavailable, "bff-console URL not configured")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	// Validate the body shape so we don't proxy garbage upstream.
	var req struct {
		Identifier string `json:"identifier"`
		Email      string `json:"email"`
		Password   string `json:"password"`
		TotpCode   string `json:"totp_code"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	// SPA may send "email" for clarity; bff-console expects "identifier"
	// (also accepts phone there). Normalize.
	if req.Identifier == "" {
		req.Identifier = req.Email
	}
	if req.Identifier == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "identifier + password required")
		return
	}
	upstreamBody, _ := json.Marshal(map[string]any{
		"identifier": req.Identifier,
		"password":   req.Password,
		"totp_code":  req.TotpCode,
		// Every login through the desktop daemon is a CLIENT login: pin the
		// token to the user's personal Org so the client always opens in
		// 个人空间, never inheriting a team the user last switched to on the
		// web. The user can still switch to a team in-app afterwards.
		"prefer_personal_org": true,
	})
	u, _ := s.buildURL("/v1/auth/login", "")
	upReq, _ := http.NewRequestWithContext(r.Context(), "POST", u, bytes.NewReader(upstreamBody))
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(upReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		// Forward the upstream error verbatim so the SPA can show
		// "密码错误" vs "TOTP required" etc.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}
	var loginResp struct {
		AccessToken        string `json:"access_token"`
		RefreshToken       string `json:"refresh_token"`
		AccessExpiresInSec int64  `json:"access_expires_in_sec"`
		UserID             int64  `json:"user_id"`
		Email              string `json:"email"`
		ActiveOrgID        int64  `json:"active_org_id"`
	}
	if err := json.Unmarshal(respBody, &loginResp); err != nil {
		writeError(w, http.StatusBadGateway, "decode upstream: "+err.Error())
		return
	}
	if loginResp.AccessToken == "" {
		writeError(w, http.StatusBadGateway, "upstream returned no access_token")
		return
	}
	// Persist to creds. Load-modify-save so we don't blow away fingerprint/api_key/etc.
	cfg, _ := creds.Load()
	if cfg == nil {
		cfg = &creds.Config{}
	}
	cfg.AccessToken = loginResp.AccessToken
	cfg.RefreshToken = loginResp.RefreshToken
	cfg.User.ID = loginResp.UserID
	cfg.User.Email = loginResp.Email
	// Pin the Org chip to the org the token is actually scoped to. Without
	// this, ActiveOrgID stays at its prior/zero value and the top-bar shows
	// "个人空间" while the token serves a different (e.g. team) org's
	// tunnels — the divergence users kept hitting. The OnLoginSucceeded
	// hook re-reads creds and pushes this into the snapshot.
	cfg.ActiveOrgID = loginResp.ActiveOrgID
	if err := creds.Save(cfg); err != nil {
		// Surface but don't fail the login — the SPA can use the token
		// in-memory; restart will lose it but that's not the end of the world.
		s.logger.Warn("save creds after SPA login", "err", err)
	}
	// Wipe the read cache — the bearer just changed so any previously
	// cached entries are stamped against the wrong user.
	s.cache.invalidateAll()
	s.logger.Info("SPA login succeeded", "user_id", loginResp.UserID, "email", loginResp.Email)
	// Fire device auto-registration so the wizard's client picker has a
	// usable defaultClientId immediately — see Config.OnLoginSucceeded
	// for why. Goroutine: dialing identity-svc takes ~5s in the cold
	// path, and we don't want to block returning the access_token to
	// the SPA on it.
	if s.cfg.OnLoginSucceeded != nil {
		go s.cfg.OnLoginSucceeded()
	}
	// Echo the upstream body to the SPA.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBody)
}

// handleAuthLogout calls bff-console /v1/auth/logout (which revokes
// the JWT session on identity-svc) and clears the access/refresh
// tokens from the local creds. Leaves fingerprint + device_id intact
// so the user can log back in without re-pairing the device.
//
// also clear APIKey + fire OnLogout. APIKey is a fallback
// credential resolveToken() will pick up if present — leaving it set
// would let the daemon immediately reconnect with the API key after
// the user clicked "退出登录", which is the opposite of the user's
// intent. OnLogout tears down the in-flight edge session so tunnels
// and presence go offline server-side immediately (same root cause
// as's Org-switch fix — the control loop blocks on a raw TCP
// read that doesn't honour ctx; only closing the mux unblocks it).
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	// Fire-and-forget upstream — if the call fails (offline, identity-
	// svc down), still clear local creds. Better to log the user out
	// locally than refuse because we couldn't reach the server.
	if s.cfg.BFFConsoleURL != "" {
		if tok := resolveBearer(s.cfg.AgentMode); tok != "" {
			u, _ := s.buildURL("/v1/auth/logout", "")
			req, _ := http.NewRequestWithContext(r.Context(), "POST", u, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			if resp, err := s.httpClient.Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}
	cfg, _ := creds.Load()
	if cfg != nil {
		cfg.AccessToken = ""
		cfg.RefreshToken = ""
		cfg.APIKey = ""
		cfg.ActiveOrgID = 0
		// Keep cfg.Fingerprint + cfg.DeviceID + cfg.User.Email so the
		// next register cycle reuses the same device row + the login
		// form pre-fills the email. DeviceID gets refreshed on the
		// next RegisterClient after re-login anyway.
		_ = creds.Save(cfg)
	}
	// Drop cached responses tied to the old token.
	s.cache.invalidateAll()
	// SYNC tear-down: wipe local tunnel state + kill the edge session.
	// Same shape as OnOrgSwitched — both are non-blocking calls
	// (ClearAllTunnels is a map reset, sessionRestartTrigger is a
	// once-guarded mux close + channel send). Calling sync means the
	// SPA's subsequent /login navigation can't race the session
	// teardown.
	if s.cfg.OnLogout != nil {
		s.cfg.OnLogout()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// handleOrgSwitch proxies POST /v1/orgs/switch to bff-console, persists the
// fresh access_token / refresh_token / active_org_id into creds, blows away
// the read cache (any cached entry is now stamped against the wrong Org),
// and fires OnOrgSwitched so the daemon's reconnect loop tears down the
// in-flight edge session — the next dial picks up the new bearer + Org
// scope. (multi-Org in the desktop SPA).
//
// We don't echo the access_token / refresh_token to the SPA — the daemon
// holds them on disk and the SPA only ever sees them via the existing
// proxied bearer in `proxy()` above. Keeps the desktop SPA's same trust
// model as the CLI: only the daemon process holds the long-lived keys.
func (s *Server) handleOrgSwitch(w http.ResponseWriter, r *http.Request) {
	if s.cfg.BFFConsoleURL == "" {
		writeError(w, http.StatusServiceUnavailable, "bff-console URL not configured")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req struct {
		TargetOrgID int64 `json:"target_org_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	if req.TargetOrgID <= 0 {
		writeError(w, http.StatusBadRequest, "target_org_id required")
		return
	}
	upstreamBody, _ := json.Marshal(map[string]int64{"target_org_id": req.TargetOrgID})
	u, _ := s.buildURL("/v1/orgs/switch", "")
	upReq, _ := http.NewRequestWithContext(r.Context(), "POST", u, bytes.NewReader(upstreamBody))
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Accept", "application/json")
	if tok := resolveBearer(s.cfg.AgentMode); tok != "" {
		upReq.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := s.httpClient.Do(upReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		// Forward bff-console's verdict verbatim — 403 (not a member),
		// 503 (identity down), etc. SPA shows the message in the toast.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}
	var switchResp struct {
		AccessToken        string `json:"access_token"`
		RefreshToken       string `json:"refresh_token"`
		AccessExpiresInSec int64  `json:"access_expires_in_sec"`
		ActiveOrgID        int64  `json:"active_org_id"`
	}
	if err := json.Unmarshal(respBody, &switchResp); err != nil {
		writeError(w, http.StatusBadGateway, "decode upstream: "+err.Error())
		return
	}
	if switchResp.AccessToken == "" {
		writeError(w, http.StatusBadGateway, "upstream returned no access_token")
		return
	}
	cfg, _ := creds.Load()
	if cfg == nil {
		cfg = &creds.Config{}
	}
	cfg.AccessToken = switchResp.AccessToken
	cfg.RefreshToken = switchResp.RefreshToken
	if switchResp.ActiveOrgID != 0 {
		cfg.ActiveOrgID = switchResp.ActiveOrgID
	}
	if err := creds.Save(cfg); err != nil {
		// Save failed — in-memory the SPA still gets the new tokens
		// once we wipe the cache + re-proxy, but a daemon restart
		// would lose them. Warn loudly + carry on.
		s.logger.Warn("save creds after org switch", "err", err)
	}
	s.cache.invalidateAll()
	// Fire OnOrgSwitched SYNCHRONOUSLY. It's a thin wire-up: wipe the
	// local tunnel state + cancel the in-flight session + nudge the
	// reconnect loop. None of those block on I/O. Calling it in a
	// goroutine (as we did initially) raced against the SPA's
	// window.location.reload — the SPA could snapshot /tunnels while
	// the previous Org's claims were still cached locally, leaving
	// every row in the new Org's /v1/tunnels showing as 离线 (because
	// snap.tunnels held tunnel_ids that don't match). Sync here gives
	// the SPA a clean post-condition before it re-paints.
	if s.cfg.OnOrgSwitched != nil {
		s.cfg.OnOrgSwitched()
	}
	// SPA only needs to know the switch succeeded + the new active_org_id
	// so its header re-renders. We deliberately strip access_token /
	// refresh_token from the response — the SPA uses cookie-less proxy
	// auth and never touches the bearer directly.
	writeJSON(w, http.StatusOK, map[string]any{
		"active_org_id": switchResp.ActiveOrgID,
	})
}

// handleListMyTunnels proxies /v1/tunnels and returns the full list bff-console
// already scoped to this identity (a member's own created tunnels; an org / API
// key's whole-org set) — so the :7400 console shows EVERY tunnel the user
// created in this org, whether made from the console or via an API key, and
// whether it runs on this machine or another. We additionally compute my_total
// (how many run on THIS device) so the overview can show a "N on this machine"
// pill; the per-row effective-state badge makes off-machine rows read as
// offline/pending rather than as a fault.
//
// myDevice resolves from creds.DeviceID, which the daemon writes after every
// successful clientreg.Ensure. DeviceID 0 (very fresh install) → my_total just
// counts unbound rows; the full list still shows.
func (s *Server) handleListMyTunnels(w http.ResponseWriter, r *http.Request) {
	myDevice := int64(0)
	if c, err := creds.Load(); err == nil && c != nil {
		myDevice = c.DeviceID
	}
	if myDevice == 0 {
		// Pre-register window — degrade to raw proxy so we don't hide
		// legitimate rows during the first 5–10s after login.
		s.proxy(w, r, "GET", "/v1/tunnels", nil)
		return
	}
	// Synthesize a captured-response writer so we can mutate the body
	// before flushing to the SPA. We don't want to bypass s.proxy's
	// auth-refresh-retry + cache plumbing — capturing keeps both.
	buf := &bytes.Buffer{}
	cw := &captureWriter{ResponseWriter: w, body: buf, status: http.StatusOK, hdr: http.Header{}}
	s.proxy(cw, r, "GET", "/v1/tunnels", nil)
	// Non-200 → pass through whatever upstream said, unmutated. The
	// captureWriter's WriteHeader already pushed the status to the
	// real writer; the body is in buf and we just flush it.
	if cw.status != http.StatusOK {
		// Copy upstream headers to the real writer (statusapi.proxy()
		// also did this — but our captureWriter intercepted them).
		for k, v := range cw.hdr {
			w.Header()[k] = v
		}
		w.WriteHeader(cw.status)
		_, _ = w.Write(buf.Bytes())
		return
	}
	// Try to parse; on any decode error, fall through to the raw body
	// so we never trap the user in a "page broken" state because of a
	// schema drift.
	var parsed struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		for k, v := range cw.hdr {
			w.Header()[k] = v
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
		return
	}
	// The local :7400 console is a PER-CLIENT view: it shows only the tunnels
	// that belong to THIS identity — the ones I created plus the ones running on
	// THIS machine. A manager/owner does NOT get the org-wide list here (that
	// would dump every teammate's tunnel onto every member's local console); the
	// full org view lives in the web console. We filter on the row's
	// `created_by_me` flag (bff-console stamps it per identity) unioned with
	// "bound to my device_id", so a tunnel I created but run on another of my
	// machines still shows (and is takeover-able), while a teammate's tunnel that
	// doesn't run here is hidden.
	mine := make([]map[string]any, 0, len(parsed.Items))
	myTotal := 0
	for _, it := range parsed.Items {
		// JSON numbers decode as float64; tolerate both.
		var cid int64
		switch v := it["client_id"].(type) {
		case float64:
			cid = int64(v)
		case int64:
			cid = v
		case json.Number:
			n, _ := v.Int64()
			cid = n
		}
		boundHere := myDevice > 0 && cid == myDevice
		createdByMe, _ := it["created_by_me"].(bool)
		if !createdByMe && !boundHere {
			continue // teammate's tunnel that doesn't run here — hidden from the local console
		}
		if boundHere {
			myTotal++
		}
		mine = append(mine, it)
	}
	// alongside the filtered items, surface counts so the SPA can
	// render an honest 「活跃隧道 team_total/plan_max + 其中本机 my_total」.
	// team_total stays the org/RBAC total bff-console returned (pre-narrow) so the
	// plan-cap banner reflects org-wide usage, not just my own rows. my_total =
	// how many of MY rows run on THIS machine, for the overview's "N on this
	// machine" pill.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"items":        mine,
		"my_total":     myTotal,
		"team_total":   len(parsed.Items),
		"my_device_id": myDevice,
	})
}

// captureWriter buffers the response body so handleListMyTunnels can
// rewrite the body without losing s.proxy()'s header / status work.
type captureWriter struct {
	http.ResponseWriter
	body   *bytes.Buffer
	status int
	hdr    http.Header
}

func (c *captureWriter) Header() http.Header         { return c.hdr }
func (c *captureWriter) WriteHeader(code int)        { c.status = code }
func (c *captureWriter) Write(b []byte) (int, error) { return c.body.Write(b) }

// proxyGET returns a handler that forwards GET <path>?<query> to bff-console.
// Path is the constant suffix; the request's query string is preserved.
func (s *Server) proxyGET(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.proxy(w, r, "GET", path, nil)
	}
}

// proxyGETPath substitutes the {param} path-value into the bff-console
// path. E.g. proxyGETPath("/v1/tunnels/", "id") on GET /v1/tunnels/42
// forwards to bff-console /v1/tunnels/42.
func (s *Server) proxyGETPath(prefix, param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.PathValue(param)
		if v == "" {
			writeError(w, http.StatusBadRequest, "missing "+param)
			return
		}
		s.proxy(w, r, "GET", prefix+v, nil)
	}
}

// proxyBody forwards the request body unchanged.
func (s *Server) proxyBody(method, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB safety
		s.proxy(w, r, method, path, body)
	}
}

func (s *Server) proxyBodyPath(method, prefix, param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.PathValue(param)
		if v == "" {
			writeError(w, http.StatusBadRequest, "missing "+param)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s.proxy(w, r, method, prefix+v, body)
	}
}

func (s *Server) proxyDeletePath(prefix, param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.PathValue(param)
		if v == "" {
			writeError(w, http.StatusBadRequest, "missing "+param)
			return
		}
		s.proxy(w, r, "DELETE", prefix+v, nil)
	}
}

// handleCreateTunnel forwards POST /v1/tunnels, but first binds the new tunnel
// to THIS daemon's device when the caller didn't pick one. The :7400 console
// manages a single machine, so "this device" is always the right target. The
// SPA wizard normally pre-fills client_id from /v1/clients, but an AGENT's
// device is an org Agent (user_id=0) that doesn't appear in that user-scoped
// list, so the wizard sends no client_id and bff-console 400s
// ("client_id is required"). The daemon authoritatively knows its own device
// (creds.DeviceID, written after clientreg.Ensure/EnsureAgent), so we inject it
// here — covering both interactive and agent installs.
func (s *Server) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	body = s.injectOwnDeviceID(body)
	s.proxy(w, r, "POST", "/v1/tunnels", body)
}

// injectOwnDeviceID sets client_id to this daemon's device when the body omits
// it (or sends 0). Returns the body unchanged on any parse error or when the
// daemon hasn't registered yet (DeviceID==0) — better to let bff-console answer
// than to mangle the request.
func (s *Server) injectOwnDeviceID(body []byte) []byte {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return body
	}
	// Already chosen a non-zero client_id → respect it.
	switch v := m["client_id"].(type) {
	case float64:
		if v != 0 {
			return body
		}
	case json.Number:
		if n, _ := v.Int64(); n != 0 {
			return body
		}
	}
	myDevice := int64(0)
	if c, err := creds.Load(); err == nil && c != nil {
		myDevice = c.DeviceID
	}
	if myDevice == 0 {
		return body
	}
	m["client_id"] = myDevice
	if out, err := json.Marshal(m); err == nil {
		return out
	}
	return body
}

// handleTunnelTakeover reassigns a tunnel to THIS machine: it forwards a
// PUT /v1/tunnels/{id} carrying client_id = this daemon's device_id (and an
// optional new local_addr from the body, since the upstream service almost
// always differs on a different machine). bff-console / tunnel-svc release the
// old client's edge route and let this daemon claim it. The public endpoint is
// unchanged. Body: {"local_addr":"127.0.0.1:8080"} (local_addr optional).
func (s *Server) handleTunnelTakeover(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	myDevice := int64(0)
	if c, err := creds.Load(); err == nil && c != nil {
		myDevice = c.DeviceID
	}
	if myDevice == 0 {
		writeError(w, http.StatusConflict,
			"this client isn't registered yet — wait for it to connect, then try again")
		return
	}
	var in struct {
		LocalAddr string `json:"local_addr"`
	}
	if raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)); len(raw) > 0 {
		_ = json.Unmarshal(raw, &in)
	}
	out := map[string]any{"client_id": myDevice}
	if la := strings.TrimSpace(in.LocalAddr); la != "" {
		out["local_addr"] = la
	}
	body, _ := json.Marshal(out)
	s.proxy(w, r, "PUT", "/v1/tunnels/"+id, body)
}

// handleTunnelSecurity forwards a per-tunnel IP-policy edit to bff-console
// POST /v1/tunnels/{id}/security. A dedicated handler (vs proxyBodyPath)
// because the upstream path has a /security suffix after the id.
func (s *Server) handleTunnelSecurity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	s.proxy(w, r, "POST", "/v1/tunnels/"+id+"/security", body)
}

// proxy is the workhorse: build the upstream URL, attach the bearer
// token from creds, forward, retry once on 401 after refresh.
//
// We don't use httputil.ReverseProxy because the auth-refresh-retry
// flow needs to inspect the response status before deciding to retry,
// and the token comes from creds (not an incoming header). A hand-rolled
// proxy is simpler than wrapping ReverseProxy's Transport/ModifyResponse.
func (s *Server) proxy(w http.ResponseWriter, r *http.Request, method, path string, body []byte) {
	if s.cfg.BFFConsoleURL == "" {
		writeError(w, http.StatusServiceUnavailable, "bff-console URL not configured")
		return
	}
	upstream, err := s.buildURL(path, r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	// Read-side cache lookup. We only consult cache for GET — other
	// verbs always hit upstream so the SPA's mutation reflects in
	// state immediately.
	bearer := resolveBearer(s.cfg.AgentMode)
	cacheable := method == http.MethodGet && ttlFor(path) > 0
	if cacheable {
		key := cacheKey(path+"?"+r.URL.RawQuery, bearer)
		if e, ok := s.cache.get(key); ok {
			// Serve from cache. Mark the response so an operator
			// looking at debug logs / curl can tell it was a hit.
			w.Header().Set("X-Statusapi-Cache", "HIT")
			for k, v := range e.headers {
				if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Transfer-Encoding") {
					continue
				}
				w.Header()[k] = v
			}
			w.WriteHeader(e.statusCode)
			_, _ = w.Write(e.body)
			return
		}
	}

	// First attempt with whatever token we have on disk.
	resp, err := s.doUpstream(r.Context(), method, upstream, body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream error: "+err.Error())
		return
	}
	// Retry once on 401 — but only if the refresh actually changes the
	// token (otherwise we'd loop). doRefresh returns true iff it wrote
	// a new access_token.
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if s.doRefresh(r.Context()) {
			// Token rotated — anything we cached against the old token
			// is now wrong-user data. Drop it.
			s.cache.invalidateAll()
			bearer = resolveBearer(s.cfg.AgentMode)
			resp, err = s.doUpstream(r.Context(), method, upstream, body)
			if err != nil {
				writeError(w, http.StatusBadGateway, "upstream retry error: "+err.Error())
				return
			}
		} else {
			// Surface the 401 — the UI knows to redirect to login.
			s.copyResponse(w, &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(strings.NewReader(`{"error":"login required","code":"unauthorized"}`)),
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			})
			return
		}
	}
	// Successful writes invalidate the read cache families that they
	// could have changed. We do this BEFORE copying to the client so a
	// fast SPA refetch right after the write goes upstream rather than
	// reading the stale cache snapshot.
	if method != http.MethodGet && resp.StatusCode >= 200 && resp.StatusCode < 400 {
		switch {
		case strings.HasPrefix(path, "/v1/tunnels"):
			s.cache.invalidatePrefix("/v1/tunnels")
		case strings.HasPrefix(path, "/v1/clients"):
			s.cache.invalidatePrefix("/v1/clients")
		}
	}
	// Cacheable GET: capture body + headers + status so the next call
	// in the TTL window can short-circuit.
	if cacheable && resp.StatusCode == http.StatusOK {
		buf, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4MB safety
		resp.Body.Close()
		if rerr == nil {
			key := cacheKey(path+"?"+r.URL.RawQuery, bearer)
			s.cache.put(key, cachedResponse{
				body:       buf,
				headers:    cloneHeader(resp.Header),
				statusCode: resp.StatusCode,
				expiresAt:  time.Now().Add(ttlFor(path)),
			})
			w.Header().Set("X-Statusapi-Cache", "MISS")
			for k, v := range resp.Header {
				if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Transfer-Encoding") {
					continue
				}
				w.Header()[k] = v
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(buf)
			return
		}
		// Read failure — fall through to the streaming copy path and
		// skip caching for this hit. Resp body was already drained so
		// we synthesise a one-shot reader from what we did read.
		resp.Body = io.NopCloser(bytes.NewReader(buf))
	}
	s.copyResponse(w, resp)
}

// cloneHeader copies an http.Header for cache storage. The original
// belongs to the upstream response and can be reused by the http
// client; without a copy a concurrent reader could see torn state.
func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

func (s *Server) buildURL(path, rawQuery string) (string, error) {
	base := strings.TrimRight(s.cfg.BFFConsoleURL, "/")
	u, err := url.Parse(base + path)
	if err != nil {
		return "", fmt.Errorf("parse upstream: %w", err)
	}
	if rawQuery != "" {
		u.RawQuery = rawQuery
	}
	return u.String(), nil
}

func (s *Server) doUpstream(ctx context.Context, method, u string, body []byte) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	if tok := resolveBearer(s.cfg.AgentMode); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "calabi-daemon/0.1")
	return s.httpClient.Do(req)
}

// doRefresh attempts a single refresh-token exchange. Returns true if
// the on-disk access_token changed; false otherwise (invalid refresh,
// network blip, recent cooldown).
func (s *Server) doRefresh(ctx context.Context) bool {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if time.Since(s.lastRefreshAt) < 30*time.Second {
		return false // cool down — avoid hammering identity-svc
	}
	s.lastRefreshAt = time.Now()

	cfg, err := creds.Load()
	if err != nil || cfg == nil || cfg.RefreshToken == "" {
		return false
	}
	prev := cfg.AccessToken
	body, _ := json.Marshal(map[string]string{"refresh_token": cfg.RefreshToken})
	u, err := s.buildURL("/v1/auth/refresh", "")
	if err != nil {
		return false
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Warn("refresh failed", "err", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.logger.Warn("refresh non-OK", "status", resp.StatusCode)
		return false
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false
	}
	if out.AccessToken == "" || out.AccessToken == prev {
		return false
	}
	cfg.AccessToken = out.AccessToken
	if out.RefreshToken != "" {
		cfg.RefreshToken = out.RefreshToken
	}
	if err := creds.Save(cfg); err != nil {
		s.logger.Warn("save refreshed creds", "err", err)
	}
	return true
}

func (s *Server) copyResponse(w http.ResponseWriter, resp *http.Response) {
	defer resp.Body.Close()
	for k, v := range resp.Header {
		// Skip hop-by-hop; net/http handles Content-Length itself.
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// resolveBearer picks the credential statusapi uses to reach bff-console on the
// user's behalf — notably the /v1/me probe AuthGate uses to decide logged-in vs
// not. An interactive login (access_token) takes PRECEDENCE over a saved
// api_key: the local console reflects the signed-in human, so a stale api_key
// left in the creds file must not 401 the /me probe and bounce the user back to
// the login screen right after they signed in — which is exactly what happened
// while the daemon handshake (resolveToken, which already prefers the login)
// connected fine. Falls back to api_key for the pure-key / standalone case,
// where there's no interactive session.
//
// The env fallback is load-bearing for AGENT mode: a service installed via
// `daemon install --api-key …` carries the key in CALABI_API_KEY (service env),
// NOT in the creds file — so without this the /me probe had no bearer, returned
// 401, and :7400 rendered a blank LOGIN screen. That empty login is exactly the
// door a different user walked through to re-bind the service to themselves.
// Reading the env here makes the agent console authenticate as its pinned key
// and show that identity read-only. Mirrors resolveCredential's env tiers in
// apps/client/cmd/calabi/http.go (login-first for interactive use).
func resolveBearer(agentMode bool) string {
	c, _ := creds.Load()
	// Agent mode pins the console to the API KEY — the SAME identity the data
	// plane uses. A login token that happens to sit in creds (from a prior
	// `calabi login` on this box) must NOT win here: otherwise /v1/me reports the
	// login user (e.g. an owner with org.role.owner scopes, no tunnel.write) and
	// the SPA's canManage mis-reads the agent as read-only even for a management
	// key. The data-plane handshake already pins to the key (resolveCredential);
	// this keeps the console identity consistent with it.
	if agentMode {
		if c != nil && c.APIKey != "" {
			return c.APIKey
		}
		if v := os.Getenv("CALABI_API_KEY"); v != "" {
			return v
		}
		// No key reachable (shouldn't happen in agent mode) — fall through.
	}
	if c != nil {
		if c.AccessToken != "" {
			return c.AccessToken
		}
		if c.APIKey != "" {
			return c.APIKey
		}
	}
	if v := os.Getenv("CALABI_API_KEY"); v != "" {
		return v
	}
	if v := os.Getenv("CALABI_TOKEN"); v != "" {
		return v
	}
	return ""
}

// ---------------------------------------------------------------------------
// Config import/export
// ---------------------------------------------------------------------------

// configExport is the self-contained JSON document. Versioned so a
// future schema break can refuse the wrong shape rather than silently
// import garbage.
type configExport struct {
	SchemaVersion int               `json:"schema_version"`
	ExportedAt    string            `json:"exported_at"`
	ClientVersion string            `json:"client_version,omitempty"`
	Tunnels       []json.RawMessage `json:"tunnels"`
}

const configSchemaVersion = 1

func (s *Server) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	listURL, _ := s.buildURL("/v1/tunnels", "")
	resp, err := s.doUpstream(r.Context(), "GET", listURL, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "list tunnels: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeError(w, resp.StatusCode, "upstream list failed")
		return
	}
	var listed struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		writeError(w, http.StatusBadGateway, "decode list: "+err.Error())
		return
	}
	out := configExport{
		SchemaVersion: configSchemaVersion,
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		Tunnels:       listed.Items,
	}
	w.Header().Set("Content-Disposition", `attachment; filename="calabi-config.json"`)
	writeJSON(w, http.StatusOK, out)
}

// handleConfigImport accepts the same shape configExport produces.
//
// ?dry_run=1 returns a per-tunnel "would_create" diff without doing
// any writes. Without it, each tunnel is POSTed to bff-console; per-row
// errors collect into a partial-success response so the UI can show
// which items landed and which didn't.
func (s *Server) handleConfigImport(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var doc configExport
	if err := json.Unmarshal(body, &doc); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	if doc.SchemaVersion != configSchemaVersion {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported schema_version %d (want %d)",
			doc.SchemaVersion, configSchemaVersion))
		return
	}
	dryRun := r.URL.Query().Get("dry_run") == "1"

	// Dedup: re-importing a backup must not duplicate tunnels. Build the set of
	// existing tunnels (name+type+local_addr) so an incoming match is skipped
	// rather than re-created; also dedup repeats within this doc. Mirrors the
	// standalone localweb import so both editions behave the same. A list
	// failure degrades to "no existing" (we'd rather attempt the import than
	// silently skip everything).
	existing := map[string]struct{}{}
	if listURL, e := s.buildURL("/v1/tunnels", ""); e == nil {
		if resp, e := s.doUpstream(r.Context(), "GET", listURL, nil); e == nil {
			if resp.StatusCode == http.StatusOK {
				var listed struct {
					Items []map[string]any `json:"items"`
				}
				_ = json.NewDecoder(resp.Body).Decode(&listed)
				for _, t := range listed.Items {
					existing[importKey(asString(t["name"]), asString(t["type"]), asString(t["local_addr"]))] = struct{}{}
				}
			}
			resp.Body.Close()
		}
	}

	type item struct {
		Name    string `json:"name"`
		Created bool   `json:"created"`
		Skipped bool   `json:"skipped,omitempty"`
		Error   string `json:"error,omitempty"`
	}
	out := struct {
		DryRun  bool   `json:"dry_run"`
		Total   int    `json:"total"`
		Created int    `json:"created"`
		Skipped int    `json:"skipped"`
		Items   []item `json:"items"`
	}{DryRun: dryRun, Total: len(doc.Tunnels), Items: make([]item, 0, len(doc.Tunnels))}

	createURL, _ := s.buildURL("/v1/tunnels", "")
	for _, raw := range doc.Tunnels {
		// Re-shape: strip server-side fields (id, status, edge_node_id,
		// created_at, ...) that POST /v1/tunnels rejects or ignores.
		var src map[string]any
		if err := json.Unmarshal(raw, &src); err != nil {
			out.Items = append(out.Items, item{Error: "parse: " + err.Error()})
			continue
		}
		name, _ := src["name"].(string)
		key := importKey(name, asString(src["type"]), asString(src["local_addr"]))
		if _, dup := existing[key]; dup {
			out.Items = append(out.Items, item{Name: name, Skipped: true})
			out.Skipped++
			continue
		}
		existing[key] = struct{}{}
		clean := map[string]any{
			"name":         src["name"],
			"type":         src["type"],
			"local_addr":   src["local_addr"],
			"domain":       src["domain"],
			"remote_port":  src["remote_port"],
			"workspace_id": src["workspace_id"],
			"client_id":    src["client_id"],
			"config_json":  src["config_json"],
		}
		if dryRun {
			out.Items = append(out.Items, item{Name: name, Created: true})
			out.Created++
			continue
		}
		buf, _ := json.Marshal(clean)
		resp, err := s.doUpstream(r.Context(), "POST", createURL, buf)
		if err != nil {
			out.Items = append(out.Items, item{Name: name, Error: err.Error()})
			continue
		}
		if resp.StatusCode >= 300 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			out.Items = append(out.Items, item{Name: name,
				Error: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))})
			continue
		}
		resp.Body.Close()
		out.Items = append(out.Items, item{Name: name, Created: true})
		out.Created++
	}
	writeJSON(w, http.StatusOK, out)
}

// importKey is the dedup identity for a tunnel on config import: name + type +
// local_addr, lowercased. Mirrors localweb.importKey so both editions dedup the
// same way.
func importKey(name, typ, local string) string {
	return strings.ToLower(strings.TrimSpace(name)) + "|" +
		strings.ToLower(strings.TrimSpace(typ)) + "|" +
		strings.ToLower(strings.TrimSpace(local))
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// ---------------------------------------------------------------------------
// probe + inspector handlers
// ---------------------------------------------------------------------------

// handleProbePorts surfaces the local listening-port scan. The probe
// sweep takes ~250ms; we cap with a 1s context so a misbehaving
// loopback firewall doesn't stall the UI.
func (s *Server) handleProbePorts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
	defer cancel()
	// Pass this machine's overlay address so each listening port is also tested
	// for MESH reachability. A port bound to 127.0.0.1 is listening but no mesh
	// peer can reach it, and the Tools page offers to declare these as mesh
	// services — declaring a loopback-only port would authorize traffic to an
	// endpoint that always refuses.
	rows := probe.Scan(ctx, s.meshOverlay())
	writeJSON(w, http.StatusOK, map[string]any{"items": rows})
}

// meshOverlay is this machine's mesh address, or "" when it isn't on the mesh
// (no source configured, mesh down, or paused) — in which case reachability
// simply isn't probed rather than being reported as false.
func (s *Server) meshOverlay() string {
	if s.cfg.Mesh == nil {
		return ""
	}
	st := s.cfg.Mesh.MeshStatus()
	if !st.Up {
		return ""
	}
	return st.Overlay
}

// handleMeshServicesGet lists what this machine declares it offers.
func (s *Server) handleMeshServicesGet(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Mesh == nil {
		writeError(w, http.StatusNotFound, "mesh not available on this daemon")
		return
	}
	items := s.cfg.Mesh.MeshServices()
	if items == nil {
		items = []MeshServiceDecl{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleMeshServicesSet replaces the console-managed declarations. Body:
// {"items":[{name,proto,port,note}]}. Entries that came from the config file are
// ignored if echoed back — the file owns them.
func (s *Server) handleMeshServicesSet(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mesh == nil {
		writeError(w, http.StatusNotFound, "mesh not available on this daemon")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var in struct {
		Items []MeshServiceDecl `json:"items"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	// Validate here so a typo surfaces at the click, not as an entry the
	// coordinator silently drops at enroll time.
	out := make([]MeshServiceDecl, 0, len(in.Items))
	seen := map[string]bool{}
	for _, d := range in.Items {
		// Neither source is this list's to own: the config file re-declares its
		// entries every restart, and a console-registered one would become a
		// SECOND row claiming that name with only one of them authorized. The
		// flags have to be checked HERE too — the list is echoed back through
		// this handler, so stripping them below would hide them from the layer
		// that acts on them.
		if d.FromConfig || d.FromConsole {
			continue
		}
		name := meshproto.NormalizeLabel(d.Name)
		proto := strings.ToLower(strings.TrimSpace(d.Proto))
		if proto == "" {
			proto = "tcp"
		}
		// The SAME rule the coordinator applies. Without it a name it cannot use
		// — one containing a space is the easy way in — is accepted here, stored,
		// declared, and then SKIPPED at enrollment, because a registration drops
		// unusable entries rather than failing. The service then exists on this
		// machine and never appears in the web console, with nothing anywhere
		// saying why.
		if err := meshproto.ValidateLabel(name); err != nil {
			writeError(w, http.StatusBadRequest, "service name: "+
				strings.TrimPrefix(err.Error(), "invalid label: "))
			return
		}
		if proto != "tcp" && proto != "udp" {
			writeError(w, http.StatusBadRequest, "service "+name+": proto must be tcp or udp")
			return
		}
		if d.Port <= 0 || d.Port > 65535 {
			writeError(w, http.StatusBadRequest, "service "+name+": port out of range")
			return
		}
		if seen[name] {
			writeError(w, http.StatusBadRequest, "service "+name+" declared twice on this machine")
			return
		}
		if err := meshproto.ValidateHostPort(d.Target); err != nil {
			writeError(w, http.StatusBadRequest, "service "+name+": "+
				strings.TrimPrefix(err.Error(), "invalid label: "))
			return
		}
		seen[name] = true
		// Target has to survive the round trip: the SPA echoes the whole list
		// back on every edit, so dropping it here silently cleared the target of
		// every other service each time one was added or removed.
		out = append(out, MeshServiceDecl{
			Name: name, Proto: proto, Port: d.Port,
			Target: strings.TrimSpace(d.Target), Note: strings.TrimSpace(d.Note),
		})
	}
	if err := s.cfg.Mesh.SetMeshServices(out); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": s.cfg.Mesh.MeshServices()})
}

// handleProbeHealth returns the rolling health snapshot maintained by
// the health monitor. If HealthMonitor is nil the user opted out (or
// the daemon hasn't started the loop yet) and we return an empty list.
func (s *Server) handleProbeHealth(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.HealthMonitor == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}, "enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":   s.cfg.HealthMonitor.Snapshot(),
		"enabled": true,
	})
}

// handleProbeCheck probes ONE address on demand: the new-tunnel wizard asks
// "is 127.0.0.1:8080 actually serving http?" before the user creates a tunnel
// that would otherwise 502 with no explanation.
//
// POST because it makes the daemon dial something; a GET with the address in
// the query string would also land in browser history and access logs.
//
// probe.CheckOnce validates the address before dialling — this endpoint must
// never become a port scanner for whoever can reach :7400.
//
// A failed check is a 200 with healthy:false, not an HTTP error: "your service
// isn't up yet" is a normal answer to this question, and the SPA renders it as
// a hint rather than a failure.
func (s *Server) handleProbeCheck(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req struct {
		Type      string `json:"type"`
		LocalAddr string `json:"local_addr"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	if strings.TrimSpace(req.LocalAddr) == "" {
		writeError(w, http.StatusBadRequest, "local_addr required")
		return
	}
	// Cap at 4s: 2s dial + 2s TLS/HTTP, matching probeOne's own budget, so a
	// black-holed address can't hold the wizard's spinner open indefinitely.
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, probe.CheckOnce(ctx, probe.TunnelTarget{
		Type:      req.Type,
		LocalAddr: req.LocalAddr,
	}))
}

// handleInspectConnections returns the per-tunnel connection ring.
// proxy_id is required (queries are scoped by tunnel so the UI's
// "view requests" drawer doesn't paginate the whole machine).
func (s *Server) handleInspectConnections(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Inspector == nil {
		writeError(w, http.StatusServiceUnavailable, "inspector disabled")
		return
	}
	pid := r.URL.Query().Get("proxy_id")
	if pid == "" {
		writeError(w, http.StatusBadRequest, "proxy_id required")
		return
	}
	// Normalize nil → [] so the SPA sees "items":[] instead of
	// "items":null. A null.items crashes JS.length /.map() and
	// blanks the InspectorDrawer for tunnels that haven't seen any
	// traffic yet — same shape bug as on /tunnels.
	items := s.cfg.Inspector.SnapshotConnections(pid)
	if items == nil {
		items = []inspect.Connection{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleInspectCaptures returns the per-tunnel HTTP capture ring.
func (s *Server) handleInspectCaptures(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Inspector == nil {
		writeError(w, http.StatusServiceUnavailable, "inspector disabled")
		return
	}
	pid := r.URL.Query().Get("proxy_id")
	if pid == "" {
		writeError(w, http.StatusBadRequest, "proxy_id required")
		return
	}
	// Same null→[] normalization as connections above.
	items := s.cfg.Inspector.SnapshotCaptures(pid)
	if items == nil {
		items = []inspect.HTTPCapture{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleInspectReplay re-sends a captured request to the tunnel's
// local_addr. Body shape: {"proxy_id":"px-1","capture_id":42}.
func (s *Server) handleInspectReplay(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Inspector == nil || s.cfg.LocalAddrFor == nil {
		writeError(w, http.StatusServiceUnavailable, "replay disabled")
		return
	}
	var body struct {
		ProxyID   string `json:"proxy_id"`
		CaptureID uint64 `json:"capture_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.ProxyID == "" || body.CaptureID == 0 {
		writeError(w, http.StatusBadRequest, "proxy_id and capture_id required")
		return
	}
	cap := s.cfg.Inspector.GetCapture(body.ProxyID, body.CaptureID)
	if cap == nil {
		writeError(w, http.StatusNotFound, "capture not found")
		return
	}
	target := s.cfg.LocalAddrFor(body.ProxyID)
	if target == "" {
		writeError(w, http.StatusBadRequest, "no local_addr for proxy_id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	status, respBody, err := inspect.Replay(ctx, target, *cap)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": status,
		"body":   string(respBody),
		"target": target,
	})
}

// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Used by the replay handler to convert the body's int field safely.
// Kept here so the strconv import isn't orphaned if we delete a future
// caller. (Linters whine about unused stdlib imports otherwise.)
var _ = strconv.Atoi

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// errUnauthorized is the sentinel we re-tag 401s with internally —
// kept around in case future code wants to errors.Is() on it (the
// initial implementation handles the status code directly).
var errUnauthorized = errors.New("upstream returned 401")

var _ = errUnauthorized // suppress unused warning until needed
