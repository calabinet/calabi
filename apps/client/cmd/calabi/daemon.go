// `calabi daemon` — keep the client "online" AND auto-activate tunnels
// pushed from the console.
//
// Without daemon mode, a console-created tunnel
// just lit up as "pending" on the /status page — the user still had to
// run `calabi http <port>` for the local side to take effect. Daemon
// mode closes that gap:
//
//  1. Connect + heartbeat (the original "be present" behavior — keeps
//     identity-svc's presence table flipped to online so the console
//     can show the green dot).
//  2. On CONFIG_PUSH.UpsertProxies, send NEW_PROXY with claim_tunnel_id
//     so the edge "claims" the pending tunnel-svc row instead of
//     duplicating it. Install the proxy_id → local_addr mapping in a
//     dynamic registry so subsequent NEW_CONN frames can dial through.
//  3. On CONFIG_PUSH.CloseProxyIDs, send CLOSE_PROXY + drop the local
//     mapping so the edge's router stops handing traffic to us.
//
// The daemon does NOT start any HTTP/TCP listener of its own. The
// `local_addr` carried by the tunnel is a DIAL target — whatever app
// is running there (your dev server, db, etc.) must already be up.
// the Q/A reply on 2026-05-27 for the explainer we gave the user.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/platform/clientreg"
	"github.com/calabi/calabi/apps/client/internal/platform/edgepicker"
	"github.com/calabi/calabi/apps/client/internal/platform/statusapi"
	"github.com/calabi/calabi/apps/client/internal/probe"
	cruntime "github.com/calabi/calabi/apps/client/internal/runtime"
	"github.com/calabi/calabi/apps/client/internal/session"
	"github.com/calabi/calabi/apps/client/internal/status"
	"github.com/calabi/calabi/apps/client/internal/transport"
)

// daemonRegistry is the per-process dynamic ProxyRegistry the daemon
// command installs into the session. Holds the proxy_id → local-side
// tunnel mapping plus a reverse index by tunnel_id so console-side
// deletes can look up which proxy_id to close.
//
// All fields guarded by mu. Reads happen on the NEW_CONN hot path so
// keep it cheap (no allocations under the lock).
type daemonRegistry struct {
	mu        sync.RWMutex
	byProxyID map[string]session.Tunnel
	tunnelMap map[int64]string // tunnel_id → proxy_id
}

func newDaemonRegistry() *daemonRegistry {
	return &daemonRegistry{
		byProxyID: make(map[string]session.Tunnel),
		tunnelMap: make(map[int64]string),
	}
}

// UpsertProxy records the local-side mapping after a successful auto-claim.
// We don't get the tunnel_id back from the edge response, so callers that
// care about the tunnel_id reverse index must call NoteTunnel separately
// — except in practice handleConfigPush has both up.TunnelID and the
// assigned proxy_id when it calls Upsert, so we'd lose nothing by adding
// a 3-arg variant. Kept 2-arg to satisfy the session.ProxyRegistry
// interface; daemon installs the reverse-index entry via the wrapper.
func (r *daemonRegistry) UpsertProxy(proxyID string, t session.Tunnel) {
	r.mu.Lock()
	r.byProxyID[proxyID] = t
	r.mu.Unlock()
}

// RemoveProxy drops both directions of the mapping.
func (r *daemonRegistry) RemoveProxy(proxyID string) {
	r.mu.Lock()
	delete(r.byProxyID, proxyID)
	for tid, pid := range r.tunnelMap {
		if pid == proxyID {
			delete(r.tunnelMap, tid)
			break
		}
	}
	r.mu.Unlock()
}

// ProxyIDByTunnelID looks up the proxy_id this daemon claimed for the
// given tunnel-svc row id. Used by the CONFIG_PUSH delete path.
func (r *daemonRegistry) ProxyIDByTunnelID(tunnelID int64) (string, bool) {
	r.mu.RLock()
	pid, ok := r.tunnelMap[tunnelID]
	r.mu.RUnlock()
	return pid, ok
}

// TunnelIDByProxyID is the reverse of ProxyIDByTunnelID: maps a probe
// Result's proxy_id back to the cloud tunnel_id so the upstream-health
// reporter can POST it to bff-console. 0/false when the proxy isn't a
// claimed cloud tunnel (e.g. standalone/local-only).
func (r *daemonRegistry) TunnelIDByProxyID(proxyID string) (int64, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for tid, pid := range r.tunnelMap {
		if pid == proxyID {
			return tid, true
		}
	}
	return 0, false
}

// noteTunnelID is the daemon-internal helper that stores the reverse
// index. session.ProxyRegistry doesn't surface tunnel_id on UpsertProxy
// (the session only has the Tunnel struct, which doesn't carry the
// row id), so daemon mode populates this from handleConfigPush via the
// 3-arg wrapper installed below.
func (r *daemonRegistry) noteTunnelID(tunnelID int64, proxyID string) {
	if tunnelID == 0 {
		return
	}
	r.mu.Lock()
	r.tunnelMap[tunnelID] = proxyID
	r.mu.Unlock()
}

// RegisteredTunnel returns the Tunnel currently registered for a tunnel_id
// (via the tunnel_id → proxy_id → Tunnel chain). Satisfies
// session.RegisteredTunnelLookup so auto-claim can detect a console edit that
// changed local_addr and re-home the proxy instead of skipping it.
func (r *daemonRegistry) RegisteredTunnel(tunnelID int64) (session.Tunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pid, ok := r.tunnelMap[tunnelID]
	if !ok {
		return session.Tunnel{}, false
	}
	t, ok := r.byProxyID[pid]
	return t, ok
}

// resolver is the NEW_CONN dispatch lookup the session passes into Run.
func (r *daemonRegistry) resolver(proxyID string) (session.Tunnel, bool) {
	r.mu.RLock()
	t, ok := r.byProxyID[proxyID]
	r.mu.RUnlock()
	return t, ok
}

// trackingRegistry wraps daemonRegistry so the per-upsert auto-claim
// path can write through to BOTH indexes in one call. Plumbed through
// the session by way of session.AttachProxyResolver.
//
// The session core doesn't know about tunnel_ids — it just calls
// UpsertProxy(proxyID, tunnel). We use a closure-captured TunnelID via
// the surrounding `up.TunnelID` available in handleConfigPush, but
// since handleConfigPush is in the session package, the cleanest split
// is: session calls UpsertProxy, then daemon-side autoClaim hooks into
// session.AutoClaimHook to register the (tunnel_id, proxy_id) pair.
// That hook doesn't exist yet — sketched as a follow-up if the
// session.Tunnel struct grows to carry TunnelID natively.
//
// For now: daemon's autoClaim hook lives inside session.autoClaimOne,
// which has access to up.TunnelID. We expose noteTunnelID via the
// ProxyRegistry interface by adding an extra interface assertion in
// session.autoClaimOne: if registry implements TunnelIDIndexer, call it.
// See session.TunnelIDIndexer (added in this PR alongside the registry).
type trackingRegistry struct {
	*daemonRegistry
}

func (t *trackingRegistry) NoteTunnelID(tunnelID int64, proxyID string) {
	t.daemonRegistry.noteTunnelID(tunnelID, proxyID)
}

func runDaemon(args []string) int {
	// In a container the runtime is the supervisor — there is no OS service
	// manager to install into (that's the `open /etc/init.d/calabi: no such
	// file or directory` error). Translate `daemon install/start/restart` into
	// a foreground daemon (carrying --api-key into CALABI_API_KEY) and short-
	// circuit stop/uninstall/status. Outside a container this is a no-op.
	if next, handled, code := containerizeDaemonArgs(args); handled {
		return code
	} else {
		args = next
	}

	// `calabi daemon install|uninstall|start|stop|status` get
	// routed through the kardianos/service wrapper before flag parsing
	// so they don't get confused with the bare `calabi daemon` boot path.
	if len(args) > 0 {
		switch args[0] {
		case "install", "uninstall", "start", "stop", "status", "restart":
			return runDaemonService(args)
		}
	}

	// When the Windows SCM launched us, drive the daemon through the service
	// control dispatcher so SCM gets its connection within the start timeout
	// (otherwise: error 1053 / "等待…服务的连接超时"). No-op on other OSes and on
	// interactive runs; the real boot below then runs inside serviceProgram.Start.
	if handled, code := maybeRunUnderServiceManager(); handled {
		return code
	}

	// hand off to the local supervisor daemon when `--local` is passed or
	// the client is in standalone mode — it runs a self-hosted multi-tunnel
	// runner from a YAML config instead of the platform-sync daemon below.
	// See daemon_local.go +
	if daemonIsLocal(args) {
		return runLocalDaemon(args)
	}

	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	name := fs.String("name", "daemon", "client name shown in dashboard")
	// preferred edge region. Empty = no preference (use CALABI_SERVER /
	// default). Persisted to creds when --persist-edge-region is also set,
	// so the next run picks up the same region without the flag.
	edgeRegion := fs.String("edge-region", envOr("CALABI_EDGE_REGION", ""),
		"preferred edge region for ListEdges-based selection (empty = use CALABI_SERVER)")
	persistRegion := fs.Bool("persist-edge-region", false,
		"persist --edge-region into creds so subsequent runs use it by default")
	// BYOI soft-affinity: 'own' = prefer your self-hosted edge (default for a
	// BYOI org), 'platform' = run on the platform data plane even when you have
	// your own edge. Empty = keep the current persisted setting. Changing it
	// clears the edge/region anchor so the next pick re-evaluates.
	edgeAffinity := fs.String("edge-affinity", envOr("CALABI_EDGE_AFFINITY", ""),
		"edge affinity: own | platform (empty = keep current). BYOI orgs default to 'own'.")
	// Connect (mesh) subnet-router / exit-node role for this node. Mirror `calabi
	// mesh up`'s flags so an auto-enrolled platform daemon can advertise routes or
	// act as / use an exit node too. Forwarding is Linux-only.
	meshAdvertiseRoutes := fs.String("advertise-routes", envOr("CALABI_MESH_ADVERTISE_ROUTES", ""),
		"mesh: comma-separated CIDRs to advertise as a subnet router (e.g. 192.168.1.0/24)")
	meshServices := fs.String("mesh-service", envOr("CALABI_MESH_SERVICES", ""),
		"declare services this machine offers on the mesh, e.g. \"db:tcp:5432,web:443\" (proto defaults to tcp). A DECLARATION: each entry lands in the console as pending until an admin confirms it")
	meshAdvertiseExit := fs.Bool("advertise-exit-node", envBool("CALABI_MESH_ADVERTISE_EXIT_NODE", false),
		"mesh: advertise this node as an exit node (offer to forward peers' default route)")
	meshExitNode := fs.String("exit-node", envOr("CALABI_MESH_EXIT_NODE", ""),
		"mesh: route THIS node's default traffic through the named exit-node peer (name or overlay IP)")
	if err := fs.Parse(reorderArgs(args, []string{"name", "edge-region", "persist-edge-region", "edge-affinity",
		"advertise-routes", "advertise-exit-node", "exit-node", "mesh-service"})); err != nil {
		return 2
	}

	// log to file + stderr so service-manager-launched runs
	// (no terminal) still have a paper trail.
	logger := setupDaemonLogger()
	defer func() {
		if hub := loggingGetHub(); hub != nil {
			_ = hub.Close()
		}
	}()

	// persist --edge-region into creds before lock so the next
	// daemon run (cold restart) picks it up without the flag. Doing
	// this before lock acquisition is safe — Save is atomic (tmp +
	// rename) so a concurrent reader sees either the old or the new
	// value, never a half-written file.
	if *persistRegion && *edgeRegion != "" {
		if c, lerr := creds.Load(); lerr == nil && c != nil {
			if c.EdgeRegion != *edgeRegion {
				c.EdgeRegion = *edgeRegion
				if serr := creds.Save(c); serr != nil {
					setupDaemonLogger().Warn("persist edge-region failed",
						"region", *edgeRegion, "err", serr)
				}
			}
		}
	}

	// BYOI affinity toggle. Persist the chosen class and, when it CHANGES,
	// clear the edge/region anchor so the next edgepicker run re-evaluates
	// from scratch (a stale region lock would otherwise pin the old edge,
	// e.g. an own→platform switch would stay stuck on the BYOI region that
	// has no platform edge). Done before the single-instance lock; Save is
	// atomic (tmp + rename).
	if aff := strings.ToLower(strings.TrimSpace(*edgeAffinity)); aff == "own" || aff == "platform" {
		preferPlatform := aff == "platform"
		if c, lerr := creds.Load(); lerr == nil && c != nil {
			if c.PreferPlatformEdge != preferPlatform {
				c.PreferPlatformEdge = preferPlatform
				c.LastEdgeNodeID = 0
				c.LastEdgeRegion = ""
				if serr := creds.Save(c); serr != nil {
					setupDaemonLogger().Warn("persist edge-affinity failed",
						"affinity", aff, "err", serr)
				}
			}
		}
	}

	// single-instance lock. Refuse to start if another daemon
	// is alive — the second one would compete for the same device id
	// and tunnel claims, which silently corrupts presence state.
	lock, err := cruntime.AcquireDaemonLock()
	if err != nil {
		if errors.Is(err, cruntime.ErrAlreadyRunning) {
			fmt.Fprintln(os.Stderr, "calabi daemon:", err)
			fmt.Fprintln(os.Stderr, "  stop the other instance first, or use `calabi daemon stop`.")
			return 3
		}
		fmt.Fprintln(os.Stderr, "calabi daemon: lock:", err)
		return 1
	}
	defer lock.Release()

	// mint a fresh local-token so the browser UI can call the
	// write endpoints without inheriting a token from a prior
	// daemon run. The UI fetches it via /v1/local-token at boot.
	if _, err := creds.MintLocalToken(); err != nil {
		// Non-fatal: the daemon still runs (the user can use the CLI
		// for writes), just the UI write API will refuse requests.
		logger.Warn("local-token mint failed (UI writes will be disabled)", "err", err)
	}

	logger.Info("daemon starting",
		"server", envOr("CALABI_SERVER", defaultServer),
		"pidfile", lock.Path())

	// Long-lived state that survives across reconnect attempts.
	// (We re-instantiate session.Client + transport.Mux on every retry,
	// but the status/inspector/health view persists so the SPA never
	// sees its data disappear during a blip.)
	state := status.New(version, envOr("CALABI_SERVER", defaultServer))
	insp := newDaemonInspector()
	healthMon := probe.New(logger)
	healthMon.SetSource(newStateSource(state))
	registry := &trackingRegistry{daemonRegistry: newDaemonRegistry()}

	// forward-declare so the closures below can capture the
	// trigger by name. Real assignment happens once the reconnect
	// loop has its sessCancel handle to flip. Before assignment it
	// is a no-op — login that races daemon boot just rides the next
	// natural session retry tick instead of restarting immediately.
	sessionRestartTrigger := func() {}

	// +: write-API + probe/inspector endpoints on :7400.
	// Mounted ONCE up-front so the SPA can serve login/diagnostics
	// even when the edge connection is failing — critical for the
	// in-window login flow (user must be able to log in BEFORE
	// the daemon has a working session).
	// daemon's background paths (edgepicker + clientreg) now go
	// through bff-console REST, not identity-svc gRPC. Single env →
	// single public endpoint.
	bffConsoleURL := envOr("CALABI_BFF_CONSOLE", defaultBFFConsole)
	// Agent mode = the daemon's data-plane credential is a long-lived API key
	// (a service installed via `daemon install --api-key …`, or CALABI_API_KEY
	// in the env). In that case :7400 is a READ-ONLY window onto the pinned
	// identity: statusapi refuses the interactive login portal + every
	// creds/cloud-mutating write, so a browser on the loopback box can't sign
	// in as a different user and silently re-bind the running service to
	// themselves. Interactive mode (desktop / a service installed without a
	// key) keeps the login portal live. Derived once here — stable for the
	// process — from the same credential resolver the handshake uses.
	agentMode := daemonUsesAPIKey()
	logger.Info("local console mode",
		"mode", map[bool]string{true: "agent (read-only, pinned API key)", false: "interactive"}[agentMode])
	// Where the SPA's login page points people to register. NOT derivable from
	// bffConsoleURL — in prod that's the API host (api.calabi.net) while the web
	// console is console.calabi.net. Named consoleWebURL because `consoleURL`
	// below already means this daemon's LOCAL status page (:7400).
	consoleWebURL := envOr("CALABI_CONSOLE_WEB", defaultConsoleWeb)
	// Connect (WireGuard mesh) auto-enrollment. The controller asks bff-console
	// whether this node is enrolled and, when so, brings it onto its org's meshnet
	// in the background — the node's coord auth key is the daemon's own credential
	// (resolveToken), which coord resolves to the org == meshnet. Wired into the
	// :7400 console as the /v1/mesh status source; started once we have a signal
	// context (below). Dark until the platform sets the coord/relay addresses, so
	// existing daemons are unaffected until an operator turns Connect on.
	// Seed the node's subnet-router / exit-node role from creds (persisted by the
	// :7400 console toggle so it survives restarts). If the daemon was started with
	// an explicit --advertise-* flag or CALABI_MESH_* env, that wins and is written
	// back to creds — so ops can force it at install and it still sticks.
	meshAdv := meshAdvertise{}
	if c, err := creds.Load(); err == nil && c != nil {
		meshAdv = meshAdvertise{Routes: c.MeshAdvertiseRoutes, ExitNode: c.MeshAdvertiseExitNode, ExitPeer: c.MeshExitNode}
	}
	if *meshAdvertiseRoutes != "" || *meshAdvertiseExit || *meshExitNode != "" {
		meshAdv = meshAdvertise{Routes: splitCSV(*meshAdvertiseRoutes), ExitNode: *meshAdvertiseExit, ExitPeer: *meshExitNode}
		if c, err := creds.Load(); err == nil && c != nil {
			c.MeshAdvertiseRoutes, c.MeshAdvertiseExitNode, c.MeshExitNode = meshAdv.Routes, meshAdv.ExitNode, meshAdv.ExitPeer
			if serr := creds.Save(c); serr != nil {
				logger.Warn("persist mesh advertise flags failed", "err", serr)
			}
		}
	}
	// The mesh name is a MagicDNS label peers RESOLVE, so it must differ per
	// machine — which the --name default ("daemon") does not. Only an EXPLICIT
	// --name carries over; otherwise mesh takes the hostname (or a random label
	// when there isn't a usable one). See meshNodeNameFor.
	meshName := ""
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "name" {
			meshName = *name
		}
	})
	meshCtl := newPlatformMeshController(logger, bffConsoleURL, func() string {
		if tok, kind := resolveCredential(); kind != credDefault {
			return tok
		}
		return ""
	}, meshNodeNameFor(meshName), meshAdv, parseServiceSpecs(logger, *meshServices))
	apiServer := statusapi.New(logger, statusapi.Config{
		BFFConsoleURL: bffConsoleURL,
		ConsoleWebURL: consoleWebURL,
		AgentMode:     agentMode,
		HealthMonitor: healthMon,
		Inspector:     insp,
		Mesh:          meshCtl,
		LocalAddrFor: func(proxyID string) string {
			for _, t := range state.SnapshotNow().Tunnels {
				if t.ProxyID == proxyID {
					return t.LocalAddr
				}
			}
			return ""
		},
		// Auto-register this device with identity-svc the moment the
		// SPA finishes login, so the wizard's client picker can default
		// to "this machine" on first open instead of "(no clients yet)".
		// Re-reading creds inside the closure picks up the tokens the
		// login handler just persisted.
		OnLoginSucceeded: func() {
			cfg, err := creds.Load()
			if err != nil || cfg == nil {
				logger.Warn("post-login: load creds failed", "err", err)
				return
			}
			if err := clientreg.Ensure(cfg, bffConsoleURL, version); err != nil {
				logger.Warn("post-login: device auto-register failed", "err", err)
			} else {
				logger.Info("post-login: device auto-registered", "device_id", cfg.DeviceID)
			}
			// Surface the just-logged-in org to the SPA top bar immediately.
			state.SetActiveOrgID(cfg.ActiveOrgID)
			// a different user is logging in. Their tunnels
			// are by definition NOT what the previous session had
			// claimed; wipe the local view so the SPA doesn't merge
			// the new /v1/tunnels list against stale tunnel_ids and
			// render every row as 离线.
			state.ClearAllTunnels()
			// kick the running edge session so it re-dials
			// with the new bearer. Without this, the daemon stays
			// bound to the PREVIOUS user's token until the current
			// session naturally dies — meaning a "login as B" leaves
			// device row B sitting permanently offline while edge
			// presence keeps user A's row live.
			sessionRestartTrigger()
			// Connect runs on its own controller, not on the edge session, so the
			// kick above does not reach it. Its meshnet is the org behind the
			// credential — which just changed — so re-enroll too.
			meshCtl.Rebind("login")
		},
		// Same kick when the SPA flips to a different Org. The new
		// access_token carries a different org_id claim, but the
		// in-flight edge session keeps using the old one — quota
		// checks and tunnel claims would race against the wrong org
		// until the next natural disconnect. Force a restart so the
		// next handshake re-binds.
		//
		// Note on the architectural side: edge's catch-up filter
		// (tunnelstore.ListByClient(orgID, clientID)) is currently
		// Org-scoped, so the previous Org's tunnels lose their claim
		// when this session rebinds. That's a known limitation —
		// `calabi daemon` is one device with one live data-plane
		// session at a time. Switching Orgs is effectively logout +
		// login on the data plane. Wiping the local view here keeps
		// the SPA honest about that fact.
		OnOrgSwitched: func() {
			logger.Info("org switched; restarting edge session")
			// Reflect the new active org in the snapshot RIGHT AWAY so the
			// SPA top-bar chip flips within one poll — independent of whether
			// the SPA's window.location.reload() fires. The switch handler
			// has already persisted the new creds.ActiveOrgID before calling
			// us, so re-reading creds here yields the new value.
			//
			// Also clear the sticky edge anchor (LastEdgeNodeID/Region): the old
			// org's edge — especially a self-hosted one like "my-vps-hk" — does
			// NOT exist in the new org, so a stale anchor makes the picker
			// reconnect forever to a node that's gone (the "重连中" that never
			// resolves) and keeps it selected in the region switcher. Clearing it
			// forces a fresh pick for the new org, mirroring the affinity/region
			// switch handlers.
			if c, err := creds.Load(); err == nil && c != nil {
				state.SetActiveOrgID(c.ActiveOrgID)
				if c.LastEdgeNodeID != 0 || c.LastEdgeRegion != "" {
					c.LastEdgeNodeID = 0
					c.LastEdgeRegion = ""
					if serr := creds.Save(c); serr != nil {
						logger.Warn("org switch: clear edge anchor failed", "err", serr)
					}
				}
			}
			state.ClearAllTunnels()
			sessionRestartTrigger()
			// meshnet == org, so an org switch moves this node to a DIFFERENT
			// mesh. The mesh controller polls enrollment independently of the edge
			// session, and (before org_id) the answer looked identical across orgs
			// — so the node stayed on the old org's meshnet and then jumped at the
			// next reconnect, whenever that happened to be.
			meshCtl.Rebind("org switch")
		},
		// SPA logout: same teardown shape as Org switch. The handler
		// has already wiped the bearer + APIKey from creds, so the
		// reconnect loop's next dial will fail handshake with auth
		// error → daemon parks at LifecycleFatal until the user logs
		// back in. Killing the in-flight session here is what makes
		// tunnels + presence go offline server-side immediately
		// (edge fires OnProxyClosed → ReportStatus(offline) +
		// presence row reaped); without this they'd linger until
		// the OS-level TCP keep-alive timeout.
		OnLogout: func() {
			logger.Info("logout; tearing down edge session")
			state.SetActiveOrgID(0)
			state.ClearAllTunnels()
			sessionRestartTrigger()
			// Leave the meshnet too: without this the mesh session keeps running
			// on a credential that no longer exists until its stream happens to
			// drop. The follow-up enrollment fetch fails (no bearer), which is
			// what keeps mesh down until the next login.
			meshCtl.Rebind("logout")
		},
		// SPA dismissed the edge-switch banner — clear the state
		// payload so the next /tunnels poll has edge_switch=null and
		// the banner stays gone until the picker fires another switch.
		OnEdgeSwitchDismiss: func() {
			state.ClearEdgeSwitch()
		},
		// SPA picked a new edge region. The handler already persisted it
		// to creds.EdgeRegion + cleared the sticky edge; we mirror the
		// Org-switch teardown here: wipe the local tunnel view (the old
		// region's tunnels won't carry over — different base_domain),
		// clear any stale edge-switch banner, and kick the session so the
		// next dial re-anchors to the chosen region. This ALSO un-parks
		// the reconnect loop if it had given up (LifecycleUnavailable):
		// sessionRestartTrigger nudges reloadCh, which the park select
		// waits on.
		OnRegionSwitched: func() {
			logger.Info("region switched; restarting edge session")
			state.ClearAllTunnels()
			state.ClearEdgeSwitch()
			sessionRestartTrigger()
			// An egress-affinity flip is delivered through this same hook; nudge
			// the mesh so the relay home follows the edge at once (the co-switch)
			// instead of waiting for the next 30s reconcile. No-op unless the
			// home preference actually changed; goroutine so this HTTP handler
			// doesn't block on the enrollment fetch.
			go meshCtl.Nudge()
		},
	})
	// Connect (mesh) traffic meter: per-machine daily byte buckets behind the
	// overview's 组网流量 (today / month) and the 7-day chart's second series.
	// Local in BOTH editions — mesh isn't metered server-side per machine — so
	// it's registered on the status mux here rather than proxied like tunnel usage.
	meshMeter := newMeshUsageMeter(filepath.Join(filepath.Dir(lock.Path()), "mesh-usage.json"))
	attachAPI := func(mux *http.ServeMux) {
		apiServer.Register(mux)
		mux.HandleFunc("/v1/usage/mesh", meshMeter.handleMeshUsage)
	}
	consoleURL := startStatusPageWithAPI(logger, state, attachAPI)
	if consoleURL == "" {
		consoleURL = "http://" + envOr("CALABI_STATUS_ADDR", defaultStatusAddr)
	}

	ctx, cancel := withSignalContext()
	defer cancel()

	// start the health monitor loop in the background.
	go healthMon.Run(ctx)
	// Connect (mesh) enrollment: poll the control plane + reconcile the node's
	// meshnet session. Bound to ctx, torn down on shutdown. No-op until the
	// platform configures a coordinator (enrollment reports enabled:false).
	go meshCtl.Run(ctx)
	// Desktop self-update (F4): the machine-wide system service polls a signed
	// manifest and applies a newer signed installer. No-op for a dev/user daemon
	// or when disabled.
	maybeStartSelfUpdate(ctx, logger, version)
	// Sample mesh peer byte counters into the daily meter (5s, mirrors the
	// standalone tunnel meter). Empty when mesh is down — a no-op sample.
	go meshMeter.run(ctx, func() []meshPeerBytes {
		st := meshCtl.MeshStatus()
		out := make([]meshPeerBytes, 0, len(st.Peers))
		for _, p := range st.Peers {
			out = append(out, meshPeerBytes{Key: p.PublicKey, Bytes: p.RxBytes + p.TxBytes, Path: p.Path})
		}
		return out
	}, 5*time.Second)
	// Forward per-tunnel upstream (local_addr) health to bff-console so the
	// cloud console can show "异常 / upstream unreachable" instead of a
	// misleading "online". Best-effort; no-ops until creds + claimed tunnels
	// exist. Only meaningful when the client is wired to the managed control
	// plane (mode=platform).
	go runUpstreamHealthReporter(ctx, logger, healthMon, registry.daemonRegistry, bffConsoleURL)

	// + session-restart plumbing. The reconnect loop
	// registers a per-session kill function via setSessionKill; SPA
	// login / org-switch handlers call sessionRestartTrigger() to
	// terminate the in-flight session AND skip the post-error back-off
	// so the next dial happens immediately.
	//
	// IMPORTANT: context cancel alone is NOT enough. The
	// session's control loop blocks on `proto.ReadFrame(transport)`,
	// a raw TCP read that doesn't honour ctx. Without forcibly
	// closing the mux from outside, the cancel just sits there until
	// the edge happens to close the connection — which could take
	// the full TCP keep-alive timeout (minutes). The user's "切换组
	// 织后没重新上线" log was the symptom: OnOrgSwitched fired but
	// the old session kept blocking inside ReadFrame, so the
	// reconnect loop never started a new session and the new Org's
	// catch-up CONFIG_PUSH never arrived.
	//
	// kill bundles (ctx cancel + mux.Close). It's once-only so a
	// duplicate trigger doesn't double-close the transport.
	var sessMu sync.Mutex
	var sessKill func()
	reloadCh := make(chan struct{}, 1)
	setSessionKill := func(f func()) {
		sessMu.Lock()
		sessKill = f
		sessMu.Unlock()
	}
	sessionRestartTrigger = func() {
		sessMu.Lock()
		k := sessKill
		sessMu.Unlock()
		if k != nil {
			k()
		}
		select {
		case reloadCh <- struct{}{}:
		default:
		}
	}

	// SIGHUP hot-reload. On Unix only; Windows is a no-op (use
	// `calabi daemon restart` instead). Reload regenerates local-token
	// and signals the session to rotate creds on next reconnect.
	stopReload := installSIGHUP(logger, func() {
		logger.Info("reload: creds + local-token refreshed; session will pick up on next reconnect")
		sessionRestartTrigger()
	})
	defer stopReload()

	fmt.Println()
	fmt.Println("  calabi daemon supervisor up — Ctrl-C to stop.")
	fmt.Println("  console: " + consoleURL)
	fmt.Println()
	// Also log it (services have no console — this lands in the service log so
	// an operator can find the real port there).
	logger.Info("console ready", "url", consoleURL)

	// reconnect loop. The previous behaviour was "exit 1 on
	// handshake failure" — fine for a foreground CLI run by a power
	// user who immediately knows what to fix, fatal for the desktop
	// flow where the daemon launches BEFORE the user has typed any
	// credentials (the SPA login form needs the :7400 server to stay
	// up so it can collect them).
	//
	// New behaviour: forever-retry. Each iteration re-reads the creds
	// file (so a SPA login mid-loop is picked up) and re-dials.
	// LifecycleFatal during the back-off lets the SPA tell the user
	// "auth error — please log in" rather than just spinning forever.
	const retryDelay = 15 * time.Second
	// maxReconnectFails: after this many CONSECUTIVE failures to even
	// establish a session (dial / handshake / region-unavailable), the
	// loop PARKS — it stops retrying and waits for a user action (manual
	// region switch / login / org switch all nudge reloadCh). This is the
	// "重连10次后提示并停止重连" behaviour. A successful handshake resets
	// the counter, so a long-lived session that later drops doesn't count
	// toward the cap.
	const maxReconnectFails = 10
	reconnectFails := 0
	for ctx.Err() == nil {
		// Interactive daemon with no real credential yet — a service installed
		// WITHOUT --api-key, or the desktop app before its first sign-in. Don't
		// dial the edge with the demo token (credDefault): it can only fail
		// auth, so a foreground run would log a rejection every 15s and a
		// service would churn its reconnect log. Park in a "needs login" state
		// and wait for the SPA login hook (OnLoginSucceeded → sessionRestart-
		// Trigger nudges reloadCh) — the dormant-until-login shape an
		// interactive install should have. Agent mode never lands here (its
		// credential is the API key), and a logged-in interactive daemon
		// resolves to credLogin, so this only gates the pre-login window.
		if _, kind := resolveCredential(); kind == credDefault {
			state.SetLifecycle(status.LifecycleFatal)
			logger.Info("no credential yet; waiting for sign-in (open the local console to log in)")
			select {
			case <-ctx.Done():
			case <-reloadCh:
				reconnectFails = 0
				logger.Info("credential provided; starting session")
			}
			continue
		}
		state.SetLifecycle(status.LifecycleConnecting)
		// runOneSession derives its own session ctx + builds a
		// kill func that closes the mux. We hand it setSessionKill so
		// the trigger can reach across goroutines to terminate the
		// session — closing the mux is what unblocks the ReadFrame
		// loop (see the long comment above setSessionKill).
		connected, err := runOneSession(ctx, logger, state, insp, registry, *name, *edgeRegion, setSessionKill)
		setSessionKill(nil)
		if ctx.Err() != nil {
			break
		}
		// Distinguish auth errors (fatal until creds change) from
		// network blips (recoverable on retry).
		if isAuthError(err) {
			// An API-key daemon (a service installed with --api-key, or
			// CALABI_API_KEY in the env) authenticates with a long-lived
			// key, NOT an interactive login session. The remedy for a
			// rejected key is to reinstall with a valid one — logging in
			// through the SPA does nothing, and the device_deleted /
			// clear-creds dance below is login-session-specific. So branch
			// the handling on the credential mode.
			usingAPIKey := daemonUsesAPIKey()

			// Special-case device_deleted (the user revoked this
			// install from the web console). Without this branch
			// the reconnect loop would happily re-dial with the
			// same access_token — identity-svc's auth still
			// accepts it because tokens are user-scoped, not
			// device-scoped — and a fresh device row would silently
			// materialise on the server side. User report 2026-05-31:
			//   "本地客户端似乎在没有重新登录的情况下，又注册上来了"
			// The contract we want: device-deleted is terminal; force
			// the user back through /login on the SPA. Clearing the
			// bearer fields here is the lightest-touch way to do
			// that — the SPA's /me poll then returns 401 within one
			// AuthGate refetch interval (60s) and routes the user
			// to /login. Email + fingerprint stay so the form
			// pre-fills and the next register doesn't fragment the
			// device list. (Login-session mode only — an API key has
			// no session to clear and no SPA login to fall back to.)
			if isDeviceDeletedError(err) && !usingAPIKey {
				if c, lerr := creds.Load(); lerr == nil && c != nil {
					c.ClearAuth()
					if serr := creds.Save(c); serr != nil {
						logger.Warn("clear creds after device_deleted failed; in-memory wipe still applies",
							"err", serr)
					} else {
						logger.Info("device_deleted: cleared local credentials; SPA will be redirected to login on next /me poll")
					}
				}
			}
			state.SetLifecycle(status.LifecycleFatal)
			// Auth is a separate terminal category — it parks on
			// LifecycleFatal until creds change, so it shouldn't burn the
			// reconnect cap. Reset so a later network outage gets its full
			// allowance.
			reconnectFails = 0
			if usingAPIKey {
				logger.Warn("auth failed: the API key was rejected (invalid or revoked) — "+
					"reinstall the service with a valid key, e.g. `calabi daemon install --api-key tk_…` "+
					"(or fix CALABI_API_KEY), then start it again. Create keys in the console (Account → API keys). "+
					"Signing in through the dashboard will NOT fix a key-based service.", "err", err)
			} else {
				logger.Warn("auth failed; SPA can /v1/auth/login to refresh creds, then daemon will pick up", "err", err)
			}
		} else if connected {
			// We had a live session that dropped — a fresh blip, not "can't
			// reach the server". Reset the counter and reconnect normally.
			reconnectFails = 0
			state.SetLifecycle(status.LifecycleReconnecting)
			logger.Info("session ended; reconnecting", "err", err)
		} else {
			// Couldn't even establish a session (dial / handshake /
			// region-unavailable). Count it; park once we hit the cap so
			// we stop hammering a server that isn't coming back — the user
			// can switch region manually to un-park.
			reconnectFails++
			if reconnectFails >= maxReconnectFails {
				state.SetLifecycle(status.LifecycleUnavailable)
				logger.Warn("reconnect attempts exhausted; parking until manual region switch / re-login",
					"fails", reconnectFails, "err", err)
				// PARK: wait ONLY on ctx or an explicit restart trigger
				// (manual region switch / login / org switch all nudge
				// reloadCh). No time.After — we deliberately stop retrying.
				select {
				case <-ctx.Done():
				case <-reloadCh:
					reconnectFails = 0
					logger.Info("manual action received; resuming reconnect")
				}
				continue
			}
			state.SetLifecycle(status.LifecycleReconnecting)
			logger.Info("connect failed; retrying", "fails", reconnectFails, "err", err)
		}
		select {
		case <-ctx.Done():
		case <-reloadCh:
			reconnectFails = 0
			logger.Info("session restart requested; skipping back-off")
		case <-time.After(retryDelay):
		}
	}
	state.SetLifecycle(status.LifecycleStopped)
	return 0
}

// runOneSession does a single dial → handshake → Run cycle. Returns
// the error that terminated the session (nil on graceful shutdown via
// ctx).
//
// Pulled out so the reconnect loop in runDaemon stays readable. Each
// call re-reads creds via resolveToken() so a credentials change
// (SPA login) takes effect on the next iteration without restarting
// the daemon process.
//
// publishKill is the hook: once the transport is up, runOneSession
// publishes a kill function the reconnect loop can call from another
// goroutine to forcibly terminate this session. The kill cancels the
// session ctx AND closes the mux — closing the mux is what actually
// matters because the control loop blocks on a context-unaware
// proto.ReadFrame; cancelling ctx alone would leave it stuck until
// the edge naturally closes the connection (could be minutes). Once-
// guarded with sync.Once so duplicate triggers don't panic on a
// double-close.
// Returns (connected, err): connected is true once the handshake
// succeeds (so the reconnect loop can tell a dropped-but-established
// session — a blip to retry freely — from a never-connected attempt that
// counts toward the park-after-N cap).
func runOneSession(
	ctx context.Context,
	logger *slog.Logger,
	state *status.State,
	insp *daemonInspector,
	registry *trackingRegistry,
	name string,
	cliEdgeRegion string,
	publishKill func(func()),
) (bool, error) {
	// edge selection.
	//   1. CALABI_SERVER env wins (legacy single-edge override path)
	//   2. --edge-region flag / CALABI_EDGE_REGION env (cliEdgeRegion)
	//   3. creds.Config.EdgeRegion (sticky from --persist-edge-region)
	// Tier 2/3 trigger an identity-svc.ListEdges(region) lookup; tier 1
	// or all-misses fall back to defaultServer.
	//
	//sticky: also feed creds.LastEdgeNodeID to edgepicker so it
	// prefers the same edge across daemon boots. DNS is per-edge wildcard
	// — landing on a different edge silently breaks the user's
	// tunnel URLs, so we only fall off the sticky edge when it's dropped
	// from /v1/edges' healthy set.
	effectiveRegion := cliEdgeRegion
	var stickyEdgeID int64
	var stickyEdgeRegion string
	var preferPlatformEdge bool
	if c, lerr := creds.Load(); lerr == nil && c != nil {
		preferPlatformEdge = c.PreferPlatformEdge
		// Agent mode: a region switch from the local :7400 console persists to
		// creds.EdgeRegion and is the operator's LATEST explicit choice, so it
		// wins over the install-baked CALABI_EDGE_REGION env (which arrives here
		// as cliEdgeRegion — the service never passes the --edge-region flag, so
		// there's no explicit-flag precedence to honour). Interactive/foreground
		// keeps flag/env-first precedence below.
		if c.EdgeRegion != "" && daemonUsesAPIKey() {
			effectiveRegion = c.EdgeRegion
		}
		if effectiveRegion == "" {
			effectiveRegion = c.EdgeRegion
		}
		// Anchor: with no explicit preference, fall back to the region we
		// last successfully connected in. This is what makes cross-region
		// auto-switch "off" by default — once a region is established, the
		// picker locks to it (RestrictToRegion below) instead of hopping to
		// another region when this one is briefly unhealthy. A brand-new
		// install (no LastEdgeRegion yet) stays unlocked so the very first
		// connect can anchor to whatever region is available.
		if effectiveRegion == "" {
			effectiveRegion = c.LastEdgeRegion
		}
		stickyEdgeID = c.LastEdgeNodeID
		stickyEdgeRegion = c.LastEdgeRegion
	}
	// edgepicker talks bff-console REST. Authenticate /v1/edges with the
	// SAME credential the handshake uses (resolveCredential), so edge discovery
	// and the session never authenticate as DIFFERENT identities. The old code
	// preferred creds.AccessToken even in a service — so a :7400 login (writing
	// creds.AccessToken) flipped discovery to that user while the handshake
	// stayed on the env API key, a split-brain identity. resolveCredential pins
	// to the API key in agent/service mode (inServiceManager skips the login
	// token) and to the login session in interactive mode — matching the
	// handshake exactly. credDefault (the demo token) is treated as "no
	// usable credential": leave it empty so edgepicker falls back to its
	// DefaultAddr instead of authenticating /v1/edges with a junk token.
	var accessToken string
	if tok, kind := resolveCredential(); kind != credDefault {
		accessToken = tok
	}
	// Keep the SPA top-bar Org chip authoritative on every (re)connect,
	// including daemon startup — covers the case where the daemon booted into
	// an already-switched org without going through the SPA hooks.
	if c, lerr := creds.Load(); lerr == nil && c != nil {
		state.SetActiveOrgID(c.ActiveOrgID)
	}
	pick := edgepicker.Pick(ctx, logger, edgepicker.Input{
		ExplicitAddr: envOr("CALABI_SERVER", ""),
		Region:       effectiveRegion,
		// Lock to the anchored region — disable cross-region auto-switch.
		// Same-region failover still works (the region query load-balances
		// across the region's healthy edges). When the region has no
		// healthy edge, Pick returns RegionUnavailable instead of hopping
		// regions; the user switches region by hand from the top bar.
		RestrictToRegion: effectiveRegion != "",
		BFFConsoleURL:    envOr("CALABI_BFF_CONSOLE", defaultBFFConsole),
		AccessToken:      accessToken,
		DefaultAddr:      defaultServer,
		StickyEdgeNodeID: stickyEdgeID,
		// BYOI soft-affinity: default to the org's own edge; when the user
		// opted onto the platform data plane, narrow to platform edges.
		PreferPlatformEdge: preferPlatformEdge,
		// 401-recovery hook: on a cold boot the stored access_token may
		// be expired. edgepicker runs before any SPA/statusapi traffic,
		// so refresh it inline + retry rather than burning a reconnect
		// cycle dialing the localhost fallback. No-op when creds only
		// hold an API key (no refresh_token to exchange).
		RefreshBearer: refreshBearer,
	})
	logger.Info("edge selected",
		"addr", pick.Addr, "region", pick.Region, "reason", pick.Reason,
		"edge_node_id", pick.EdgeNodeID, "switched", pick.Switched,
		"region_unavailable", pick.RegionUnavailable)
	// Anchor region for the SPA's top-bar region switcher — show it even
	// while disconnected / parked. Prefer the picked region (authoritative
	// once connected); fall back to the effective/locked region otherwise.
	pr := pick.Region
	if pr == "" {
		pr = effectiveRegion
	}
	state.SetPreferredRegion(pr)

	// Region locked + no healthy edge in it: do NOT dial (cross-region
	// auto-switch is disabled). Return connected=false so the reconnect
	// loop counts this toward the park-after-N cap and eventually surfaces
	// "服务器不可用，可手动切换地域". The user un-parks by picking another
	// region from the top bar.
	if pick.RegionUnavailable {
		return false, fmt.Errorf("no healthy edge in region %q; cross-region auto-switch disabled — switch region manually", pick.Region)
	}
	// Surface to /v1/status so the SPA can show "connected via edgeN
	// (region cn-hangzhou)" in the header.
	state.SetServer(pick.Addr)
	// Surface the edge_node_id too — the SPA's tunnel list compares
	// each row's edge_node_id against this to render the 「当前节点 /
	// 其他节点」column. 0 is fine: tier 1/4 fallback paths can't tell
	// us which edge this actually is.
	state.SetEdgeNodeID(pick.EdgeNodeID)

	// sticky bookkeeping. We do this BEFORE the handshake so a
	// transient handshake failure doesn't undo the alert — if the new
	// edge also fails, the user still sees "we tried to switch but
	// can't even reach the new one" via the reconnect loop's lifecycle
	// transitions.
	// classify the switch. An INTRA-region switch (the new edge is in
	// the same region as the previous one) is transparent — regional DNS
	// keeps the tunnel URL stable and the edge mesh forwards / re-homes the
	// tunnel, so no user action is needed and we suppress the banner. Only a
	// CROSS-region switch (base_domain actually changes ⇒ URL changes) raises
	// it. When we can't tell the previous region (boot, empty), we
	// fall back to the behaviour and show the banner on any switch.
	crossRegion := pick.Switched &&
		stickyEdgeRegion != "" && pick.Region != "" &&
		pick.Region != stickyEdgeRegion
	intraRegion := pick.Switched && !crossRegion && stickyEdgeRegion != "" && pick.Region != ""
	switch {
	case pick.Switched && (crossRegion || stickyEdgeRegion == "" || pick.Region == ""):
		state.SetEdgeSwitched(pick.PreviousEdgeNodeID, pick.EdgeNodeID)
		logger.Warn("cross-region edge switch — tunnel URLs changed; previous-region tunnels are unreachable until re-created",
			"previous_edge_node_id", pick.PreviousEdgeNodeID,
			"current_edge_node_id", pick.EdgeNodeID,
			"previous_region", stickyEdgeRegion, "current_region", pick.Region)
	case intraRegion:
		// Transparent intra-region HA failover. No banner; the tunnel URL is
		// unchanged and the mesh + re-claim keep it serving. Clear any stale
		// banner from an earlier cross-region switch in this process.
		state.ClearEdgeSwitch()
		logger.Info("intra-region edge switch (transparent HA) — tunnel URLs unchanged",
			"previous_edge_node_id", pick.PreviousEdgeNodeID,
			"current_edge_node_id", pick.EdgeNodeID, "region", pick.Region)
	case pick.EdgeNodeID != 0 && pick.EdgeNodeID == stickyEdgeID:
		// We landed back on the sticky edge — clear any stale banner.
		state.ClearEdgeSwitch()
	}
	// Persist the chosen edge_node_id for the next boot. Skip when 0
	// (tier 1/4 fallback paths can't tell us which edge this actually
	// is, so we leave the previous value in place rather than wiping it).
	if pick.EdgeNodeID != 0 && (pick.EdgeNodeID != stickyEdgeID || (pick.Region != "" && pick.Region != stickyEdgeRegion)) {
		if c, lerr := creds.Load(); lerr == nil && c != nil {
			c.LastEdgeNodeID = pick.EdgeNodeID
			// remember the region so the next reconnect can classify an
			// edge switch as intra- vs cross-region.
			if pick.Region != "" {
				c.LastEdgeRegion = pick.Region
			}
			if serr := creds.Save(c); serr != nil {
				logger.Warn("persist last_edge_node_id failed",
					"edge_node_id", pick.EdgeNodeID, "err", serr)
			}
		}
	}
	mux, err := transport.Dial(transport.DialOptions{
		Addr:       pick.Addr,
		Insecure:   envBool("CALABI_INSECURE", defaultInsecure),
		CACertFile: envOr("CALABI_EDGE_CA_FILE", ""),
	})
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}
	defer mux.Close()

	// Build the kill func and publish it. sync.Once guarantees the mux
	// is closed at most once even if multiple sessionRestartTrigger calls
	// race (e.g., a SPA org-switch landing while a SIGHUP is also firing).
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	var once sync.Once
	kill := func() {
		once.Do(func() {
			scancel()
			_ = mux.Close()
		})
	}
	if publishKill != nil {
		publishKill(kill)
	}

	cli := session.New(logger, mux, resolveToken(), name)
	cli.SetDeviceID(resolveDeviceID())
	// Publish this install's Publish-side identity to the overview. On a fresh
	// install both are still empty here — the registration below is what mints
	// them — which is exactly the state worth being able to SEE.
	state.SetLocalIdentity(resolveFingerprint(logger), resolveDeviceID())
	cli.AttachTracker(state)
	cli.AttachInspector(insp)
	cli.AttachProxyResolver(registry)
	cli.EnableAutoClaim()

	if err := cli.Handshake(sctx); err != nil {
		return false, fmt.Errorf("handshake: %w", err)
	}
	state.SetLifecycle(status.LifecycleConnected)
	logger.Info("session up; auto-claim ON")

	// Belt-and-braces auto-register: covers the CLI `calabi login` path
	// (which doesn't go through statusapi's handler, so OnLoginSucceeded
	// never fires) AND the daemon-just-restarted-with-stale-deviceID
	// case where identity-svc no longer recognises us. Cheap, idempotent
	// — RegisterClient keyed on (user_id, fingerprint).
	go func() {
		cfg, err := creds.Load()
		if err != nil || cfg == nil {
			return
		}
		bff := envOr("CALABI_BFF_CONSOLE", defaultBFFConsole)
		// Agent mode (the daemon's credential is an API key): register an
		// ORG-OWNED agent device so the headless machine is visible + manageable
		// in the web console, and so its device_id scopes the local console's
		// tunnel list. bff-console infers the org from the API key. A user-login
		// daemon takes the normal per-user RegisterClient path below.
		if tok, kind := resolveCredential(); kind == credAPIKey {
			prevDevID := cfg.DeviceID
			if err := clientreg.EnsureAgent(cfg, bff, version, tok); err != nil {
				logger.Warn("post-handshake: agent auto-register failed", "err", err)
			} else {
				logger.Info("post-handshake: agent registered", "device_id", cfg.DeviceID)
				state.SetLocalIdentity(cfg.Fingerprint, cfg.DeviceID)
				// First boot: the agent's device_id is assigned only NOW, but the
				// AUTH frame for THIS session already went out with the old id
				// (0 on a fresh install) — so edge presence is keyed on the wrong
				// id and the web console shows the agent offline until a natural
				// reconnect. When the id actually changed, restart the session
				// once so the next handshake re-sends AUTH with the real device_id
				// and presence lights up immediately. EnsureAgent is idempotent —
				// after this the id matches and we never restart again.
				if cfg.DeviceID != 0 && cfg.DeviceID != prevDevID {
					logger.Info("agent device_id assigned; restarting session to refresh presence",
						"device_id", cfg.DeviceID)
					kill()
				}
			}
			return
		}
		if cfg.User.ID == 0 {
			return
		}
		prevDevID := cfg.DeviceID
		err = clientreg.Ensure(cfg, bff, version)
		if err != nil {
			logger.Warn("post-handshake: device auto-register failed", "err", err)
			return
		}
		// Registration is what mints these on a fresh install, so refresh the
		// overview before deciding whether the id CHANGED.
		state.SetLocalIdentity(cfg.Fingerprint, cfg.DeviceID)
		if cfg.DeviceID != 0 && cfg.DeviceID != prevDevID {
			// Same rationale as the agent path above. A login device is keyed per
			// org now (one device row per org it serves under), so switching org
			// resolves a DIFFERENT device_id. But the AUTH frame for THIS session
			// already went out with the previous org's id — edge presence is bound
			// to the wrong device row, so the web console shows this client offline
			// under the current org and (stale) online under the previous one.
			// Restart the session so the next handshake re-sends AUTH with the
			// org-correct device_id and presence binds to the right row. Ensure is
			// idempotent — once the id matches we never restart again.
			logger.Info("device_id changed; restarting session to refresh presence",
				"device_id", cfg.DeviceID)
			kill()
		}
	}()

	// connected=true: we got past the handshake. Whatever error Run
	// returns now is a dropped-but-established session (a blip), which the
	// reconnect loop retries without counting toward the park cap.
	return true, cli.Run(sctx, registry.resolver)
}

// isAuthError tells the reconnect loop whether to label the back-off
// as "fatal" (won't recover without operator intervention — wrong
// creds, account suspended, plan over-cap) or just "reconnecting"
// (transient network blip, retry as usual). Distinction matters for
// the SPA's status badge + alert wording.
//
// We string-match because the upstream error is a wrapped proto code
// from the server's handshake reject path. leaves this fragile —
// a structured-error refactor of the protocol is in the backlog.
//
// 2026-05-28 added: calabi.err.quota.online_clients (online-client
// cap reached). Treated as fatal so the SPA stops the reconnect storm
// — user needs to upgrade their plan or quit another device before
// retrying.
// daemonUsesAPIKey reports whether the daemon's CURRENT credential is a
// long-lived API key rather than an interactive login session. It asks
// resolveCredential (the same path the handshake uses) so the auth-failure
// message always matches the credential actually sent: a service installed via
// `daemon install --api-key tk_…` lands on credAPIKey; a desktop/foreground
// daemon that just signed in lands on credLogin even if a stale CALABI_API_KEY
// lingers in the environment. The remedy differs by mode — a rejected key is
// fixed by reinstalling with a valid key, not by signing in through the SPA.
func daemonUsesAPIKey() bool {
	_, kind := resolveCredential()
	return kind == credAPIKey
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, needle := range []string{
		"token not recognized",
		"calabi.err.auth",
		"unauthenticated",
		"code=2002",
		"calabi.err.quota", // online_clients + future quota dims
		"code=4002",
		"code=4001",
	} {
		if containsSubstr(msg, needle) {
			return true
		}
	}
	return false
}

// isDeviceDeletedError is true when the session terminated because the
// web console (or admin) deleted this device. The edge ships the
// reason as the FrameError's message ("device_deleted" —
// apps/identity-svc/internal/server/clients.go::DeleteClient publish
// + apps/calabi-edge/cmd/calabi-edge/evict.go::runEvictConsumer).
//
// Kept as substring match (not a typed code) because the reason rides
// in the human-readable Message field of the error frame and we'd
// rather not depend on the wire format more than necessary. The
// CodeQuotaExceeded(4002) reuse is intentional — the edge piggybacks
// device-delete on the existing online-cap evict channel; checking
// the substring is what disambiguates "cap exceeded" from "your row
// was wiped".
func isDeviceDeletedError(err error) bool {
	return err != nil && containsSubstr(err.Error(), "device_deleted")
}

// containsSubstr is strings.Contains with the import wrangle pushed
// inside. Avoids growing the import block of daemon.go for one call.
func containsSubstr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// loggingGetHub is a tiny indirection so daemon.go doesn't import the
// logging package directly just to flush on shutdown. Kept here because
// the only caller is the deferred close above.
func loggingGetHub() interface{ Close() error } {
	if h := loggingHub(); h != nil {
		return h
	}
	return nil
}
