// daemon_local.go — `calabi daemon --local --config tunnels.yaml`.
//
// The LOCAL supervisor daemon: one process that establishes N tunnels from a
// local YAML config against your own edge, applies each tunnel's security
// policy locally (bcrypt'd, sent in NEW_PROXY), and auto-reconnects on drop.
// Unlike the platform-sync daemon it does NOT report presence, register the
// device, sync with bff-console, or claim CONFIG_PUSH-ed tunnels — it is the
// self-hoster's ngrok.yml-style runner.
//
// Routing: runDaemon hands off here when `--local` is passed or the client is
// in standalone mode.
// The local config's security blocks only take effect against an edge running
// `mode: standalone` (the community edge always does) — a managed/BYOI edge
// ignores client-supplied policy by design.
package main

import (
	"context"
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
	"github.com/calabi/calabi/apps/client/internal/localweb"
	"github.com/calabi/calabi/apps/client/internal/probe"
	cruntime "github.com/calabi/calabi/apps/client/internal/runtime"
	"github.com/calabi/calabi/apps/client/internal/session"
	"github.com/calabi/calabi/apps/client/internal/status"
	"github.com/calabi/calabi/apps/client/internal/transport"
	proto "github.com/calabi/calabi/pkg/protocol"
	"gopkg.in/yaml.v3"
)

// daemonIsLocal decides whether `calabi daemon …` should run the LOCAL
// supervisor daemon instead of the platform-sync one: true when `--local` is
// present OR the client is in standalone mode (`calabi mode standalone` /
// CALABI_MODE=standalone). Shared by both editions' runDaemon. Service
// subcommands (install/start/…) are routed before this is consulted.
func daemonIsLocal(args []string) bool {
	for _, a := range args {
		if a == "--local" || a == "-local" {
			return true
		}
	}
	return clientIsStandalone()
}

// localConfig is the on-disk YAML schema for the local supervisor daemon —
// the self-hosted analogue of ngrok.yml.
type localConfig struct {
	// Server is the edge control endpoint (host:port). Falls back to
	// CALABI_SERVER, then defaultServer.
	//
	// All top-level optionals carry omitempty: the console can rewrite this file
	// (persist()), and without omitempty yaml.Marshal would inject every empty
	// field — so a config with just `token:` would gain a spurious `token_env: ""`
	// (plus `insecure: false`, `ca_file: ""`) on the first save. omitempty keeps
	// the round-trip faithful: only fields you actually set are written back.
	Server string `yaml:"server,omitempty"`
	// Token is the bearer sent to the edge — the only auth field a user needs.
	// Either a literal secret, or `${ENV_VAR}` to read it from the environment
	// (e.g. `token: ${CALABI_TOKEN}`) so the secret stays out of the file. Empty
	// falls back to the resolveToken() chain (CALABI_TOKEN / creds / defaultToken).
	Token string `yaml:"token,omitempty"`
	// TokenEnv is the deprecated predecessor of `token: ${ENV_VAR}` — it named an
	// env var to read the token from. Still parsed so older configs keep working
	// (the YAML decoder rejects unknown keys), but no longer documented. Prefer
	// the `token: ${ENV_VAR}` form.
	TokenEnv string `yaml:"token_env,omitempty"`
	// Insecure skips TLS verification of the edge control cert (dev / a
	// self-signed standalone edge). OR'd with CALABI_INSECURE.
	Insecure bool `yaml:"insecure,omitempty"`
	// CAFile is a PEM CA bundle used to verify the edge control cert.
	// Falls back to CALABI_EDGE_CA_FILE.
	CAFile string `yaml:"ca_file,omitempty"`
	// Tunnels has no omitempty: an empty list persists as `tunnels: []`, which is
	// a valid "connect, create tunnels in the console" config worth keeping explicit.
	Tunnels []localTunnelConfig `yaml:"tunnels"`
	// Mesh is the optional Connect (WireGuard mesh) block. Absent/disabled = the
	// daemon supervises tunnels only. See daemon_local_mesh.go.
	Mesh meshConfig `yaml:"mesh,omitempty"`
}

// localTunnelConfig is one tunnel in the local config.
type localTunnelConfig struct {
	Name       string               `yaml:"name"`
	Type       string               `yaml:"type"`                // http | tcp | udp | sni
	Local      string               `yaml:"local"`               // host:port (bare port → 127.0.0.1:port)
	Domain     string               `yaml:"domain"`              // http / sni (full host; wins over subdomain)
	Subdomain  string               `yaml:"subdomain,omitempty"` // http/https prefix → <subdomain>.<edge base_domain>
	RemotePort uint32               `yaml:"remote_port"`         // tcp / udp
	Security   *localSecurityConfig `yaml:"security,omitempty"`
	// SecurityConfigJSON is a raw {"security":{…}} blob (bcrypt'd). The local
	// console writes this form when it edits a tunnel's policy (round-trip-safe:
	// the structured `security` block can't be reconstructed once passwords are
	// hashed). Takes precedence over `security` when both are present.
	SecurityConfigJSON string `yaml:"security_config_json,omitempty"`
}

// localSecurityConfig mirrors the `calabi http --ip-allow/--basic-auth/…`
// flags so the YAML and the CLI build an identical config_json `security`
// block (passwords bcrypt'd locally at load).
type localSecurityConfig struct {
	IPAllow []string `yaml:"ip_allow"`
	IPDeny  []string `yaml:"ip_deny"`
	Rate    int      `yaml:"rate"`
	// HTTP-only (ignored — and rejected — on tcp/udp/sni):
	BasicAuth         []string `yaml:"basic_auth"` // "user:pass"
	SetHeader         []string `yaml:"set_header"` // "Name: Value"
	DelHeader         []string `yaml:"del_header"`
	OAuthProvider     string   `yaml:"oauth_provider"`
	OAuthClientID     string   `yaml:"oauth_client_id"`
	OAuthClientSecret string   `yaml:"oauth_client_secret"`
	OAuthAllowEmail   []string `yaml:"oauth_allow_email"`
	OAuthAllowDomain  []string `yaml:"oauth_allow_domain"`
	// File is an optional path to a full {"security":{…}} JSON blob the
	// fields above merge on top of.
	File string `yaml:"security_file"`
}

// runLocalDaemon is the entry point for `calabi daemon --local`.
func runLocalDaemon(args []string) int {
	fs := flag.NewFlagSet("daemon --local", flag.ContinueOnError)
	_ = fs.Bool("local", false, "run the local supervisor daemon (this flag)")
	configPath := fs.String("config", envOr("CALABI_DAEMON_CONFIG", ""),
		"path to the local tunnels YAML config")
	if err := fs.Parse(reorderArgs(args, []string{"config"})); err != nil {
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "calabi daemon --local: missing --config <tunnels.yaml>")
		return 2
	}

	cfg, err := loadLocalConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi daemon --local:", err)
		return 1
	}
	// Zero tunnels is allowed: the daemon still establishes the control session
	// and serves the local console, where tunnels can be created live.

	logger := setupDaemonLogger()
	defer func() {
		if h := loggingHub(); h != nil {
			_ = h.Close()
		}
	}()

	// Single-instance lock, shared with the platform daemon — only one calabi
	// daemon of either flavour may run per machine (they'd otherwise compete
	// for the same device id / port claims).
	lock, err := cruntime.AcquireDaemonLock()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi daemon --local:", err)
		fmt.Fprintln(os.Stderr, "  stop the other instance first, or use `calabi daemon stop`.")
		return 3
	}
	defer lock.Release()

	server := cfg.Server
	if server == "" {
		server = envOr("CALABI_SERVER", defaultServer)
	}

	// Build the tunnel plan once: stable ids (config index) + normalized local
	// addr + bcrypt'd security blob. Invalid entries are dropped with a log so
	// one bad tunnel doesn't sink the rest.
	// May be empty (no tunnels in config, or all entries invalid — planTunnels
	// already logged the dropped ones). That's fine: start anyway and let the
	// console manage tunnels.
	planned := planTunnels(logger, cfg.Tunnels)

	// Mint a local-token so the SPA's eager /v1/local-token fetch succeeds.
	// Writes are still refused in standalone (localweb returns 501).
	if _, err := creds.MintLocalToken(); err != nil {
		logger.Warn("local-token mint failed", "err", err)
	}

	state := status.New(version, server)
	insp := newDaemonInspector()

	// The supervisor owns the mutable tunnel plan + reconcile signal and persists
	// console edits back to the YAML. It is the source of truth for both the
	// reconnect loop (which tunnels to register) and localweb (list + writes).
	sv := newLocalSupervisor(logger, *cfg, *configPath, planned, server)

	// Local traffic meter: the standalone substitute for metering-svc. Persists
	// per-day byte totals next to the pidfile so the console's today / month
	// traffic survive restarts. Started below once we have a context.
	meter := newUsageMeter(filepath.Join(filepath.Dir(lock.Path()), "usage.json"))
	// Connect (mesh) traffic meter — the 组网流量 counterpart, per-machine daily
	// buckets behind the overview's mesh today/month + the chart's second series.
	meshMeter := newMeshUsageMeter(filepath.Join(filepath.Dir(lock.Path()), "mesh-usage.json"))

	// Per-tunnel upstream health prober: the same loop the platform daemon runs,
	// reading the live tunnel set from status.State. Without it the console shows
	// a perpetual "Probing..." dot in standalone (localweb's stub returned no
	// health items). Surfaced under /v1/probe/health; started below with a ctx.
	health := probe.New(logger)
	health.SetSource(stateProbeSource{state: state})

	// Local console: serve the embedded SPA + a LOCAL /v1/* API (no bff-console)
	// with plain-browser access allowed. The SPA renders in standalone (its
	// /v1/me reports plan.code="standalone"); create / delete / edit-security
	// write through the supervisor (live reconcile + YAML persistence).
	// internal/localweb +
	// Connect (WireGuard mesh): build the runner now (not started) so the local
	// API can serve its status; it's launched below once we have a signal context.
	var meshR *meshRunner
	if cfg.Mesh.Enabled {
		if cfg.Mesh.complete() {
			meshR = newMeshRunner(logger, cfg.Mesh)
		} else {
			logger.Warn("mesh: enabled but coord/relay/auth_key incomplete — not starting Connect")
		}
	}
	var meshSrc localweb.MeshSource
	if meshR != nil {
		meshSrc = meshR // avoid a non-nil interface wrapping a nil *meshRunner
	}

	lw := localweb.New(localweb.Config{
		Lister:    sv,
		Writer:    sv,
		Inspector: insp,
		Usage:     meter,
		Health:    health,
		Mesh:      meshSrc,
		Server:    server,
	})
	console := startLocalConsole(logger, state, func(mux *http.ServeMux) {
		lw.Register(mux)
		mux.HandleFunc("/v1/usage/mesh", meshMeter.handleMeshUsage)
	})
	if console == "" {
		console = "http://" + envOr("CALABI_STATUS_ADDR", defaultStatusAddr)
	}

	ctx, cancel := withSignalContext()
	defer cancel()
	go meter.run(ctx, state, 5*time.Second)
	go meshMeter.run(ctx, func() []meshPeerBytes {
		if meshR == nil {
			return nil
		}
		st := meshR.MeshStatus()
		out := make([]meshPeerBytes, 0, len(st.Peers))
		for _, p := range st.Peers {
			out = append(out, meshPeerBytes{Key: p.PublicKey, Bytes: p.RxBytes + p.TxBytes, Path: p.Path})
		}
		return out
	}, 5*time.Second)
	go health.Run(ctx)

	// Connect (WireGuard mesh): bring the node onto its meshnet in the background
	// alongside the tunnels. Stopped on shutdown before the daemon returns.
	if meshR != nil {
		meshR.Start(ctx)
		defer meshR.Stop()
		logger.Info("mesh (Connect) started", "coord", cfg.Mesh.Coord, "relay", cfg.Mesh.Relay)
	}

	logger.Info("local daemon starting",
		"server", server, "tunnels", len(planned),
		"config", *configPath, "pidfile", lock.Path(),
		"console", console)
	if len(planned) == 0 {
		logger.Info("no tunnels configured — add them in the console", "console", console)
	}

	// Reconnect loop: exponential back-off capped at 30s, reset to 1s whenever
	// we had at least one live tunnel (a real drop should reconnect promptly; a
	// persistently-unreachable edge or all-bad config backs off instead of
	// spinning).
	const minBackoff = time.Second
	const maxBackoff = 30 * time.Second
	backoff := minBackoff
	for ctx.Err() == nil {
		connected, runErr := runLocalSession(ctx, logger, sv, server, state, insp)
		if ctx.Err() != nil {
			break
		}
		if connected {
			backoff = minBackoff
			logger.Info("session ended; reconnecting", "err", runErr)
		} else {
			logger.Warn("connect failed; retrying", "backoff", backoff.String(), "err", runErr)
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		if !connected {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
	logger.Info("local daemon stopped")
	return 0
}

// stateProbeSource adapts the live status.State into a probe.TunnelSource so the
// standalone daemon runs the same per-tunnel upstream health checks as the
// platform daemon. It reads the current live tunnels (proxy_id / type /
// local_addr) on each probe tick; pending placeholders are skipped (nothing to
// dial yet).
type stateProbeSource struct{ state *status.State }

func (s stateProbeSource) LiveTunnels() []probe.TunnelTarget {
	snap := s.state.SnapshotNow()
	out := make([]probe.TunnelTarget, 0, len(snap.Tunnels))
	for _, t := range snap.Tunnels {
		if t.Pending || t.ProxyID == "" || t.LocalAddr == "" {
			continue
		}
		out = append(out, probe.TunnelTarget{
			ProxyID:   t.ProxyID,
			Type:      t.Type,
			LocalAddr: t.LocalAddr,
		})
	}
	return out
}

// plannedTunnel is a config entry resolved once at boot: a stable id (1-based
// config index, stamped onto the live status.TunnelInfo so the SPA can join
// /v1/tunnels ↔ /tunnels), the YAML type string (for display), and the built
// session.Tunnel (normalized local addr + bcrypt'd security blob).
type plannedTunnel struct {
	id   int64
	kind string
	tun  session.Tunnel
	// yaml is the source form kept for persistence. For a hand-written tunnel
	// it's the original entry (structured `security:` preserved); for a
	// console-edited/created tunnel it carries security_config_json (the raw
	// bcrypt'd blob). See localSupervisor.persist.
	yaml localTunnelConfig
}

// planTunnels resolves the config into the boot-time tunnel plan, dropping
// invalid entries with a log. The id is the 1-based CONFIG index (stable across
// skips) so it stays consistent between the daemon and localweb's /v1/tunnels.
func planTunnels(logger *slog.Logger, tcs []localTunnelConfig) []plannedTunnel {
	out := make([]plannedTunnel, 0, len(tcs))
	for i, tc := range tcs {
		tun, err := toSessionTunnel(tc)
		if err != nil {
			logger.Error("skip tunnel: bad config", "name", tc.Name, "type", tc.Type, "err", err)
			continue
		}
		out = append(out, plannedTunnel{
			id:   int64(i + 1),
			kind: strings.ToLower(strings.TrimSpace(tc.Type)),
			tun:  tun,
			yaml: tc,
		})
	}
	return out
}

// runLocalSession does one dial → handshake → reconcile-loop cycle. The initial
// reconcile registers the whole plan; thereafter it re-reconciles whenever a
// console write nudges sv.reconcileCh (register added / close removed /
// close+re-register policy-changed tunnels), all on this one goroutine so the
// registration ordering is race-free. Returns (hadLiveTunnel, runErr).
func runLocalSession(ctx context.Context, logger *slog.Logger, sv *localSupervisor, server string, state *status.State, insp *daemonInspector) (bool, error) {
	// A standalone edge is self-signed: verifying its control cert needs the
	// edge's own CA, which a self-hoster often hasn't wired up. So default to
	// skipping verification (with a loud warning) rather than hard-failing — and
	// if a CA file IS configured but unreadable (e.g. a stale CALABI_EDGE_CA_FILE
	// pointing at a dev path), warn and skip instead of refusing to connect.
	// Pin the edge by setting a readable `ca_file` (or CALABI_EDGE_CA_FILE).
	caFile := firstNonEmpty(sv.base.CAFile, envOr("CALABI_EDGE_CA_FILE", ""))
	insecure := sv.base.Insecure || envBool("CALABI_INSECURE", defaultInsecure)
	if !insecure {
		if caFile == "" {
			logger.Warn("no edge CA configured — skipping TLS verification of the self-signed edge; set ca_file to verify")
			insecure = true
		} else if _, statErr := os.Stat(caFile); statErr != nil {
			// Keep the path OUT of the WARN: it's typically an absolutized
			// CALABI_EDGE_CA_FILE that would leak the operator's filesystem
			// layout (e.g. a dev cert path) into logs that may be shared. The
			// guidance needs no path; troubleshooting can read it at debug level.
			logger.Warn("edge CA file not found — skipping TLS verification; set a readable ca_file / CALABI_EDGE_CA_FILE to verify")
			logger.Debug("edge CA file stat failed", "ca_file", caFile, "err", statErr)
			insecure, caFile = true, ""
		}
	}

	mux, err := transport.Dial(transport.DialOptions{
		Addr:       server,
		Insecure:   insecure,
		CACertFile: caFile,
	})
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}

	cli := session.New(logger, mux, resolveLocalToken(&sv.base), "daemon-local")
	cli.SetDeviceID(resolveDeviceID()) // 0 on a standalone client (never registered)
	cli.AttachTracker(state)
	cli.AttachInspector(insp) // powers /v1/inspect/* in the local console

	if err := cli.Handshake(ctx); err != nil {
		mux.Close()
		return false, fmt.Errorf("handshake: %w", err)
	}

	// Session-scoped context so we can tear the Run loop down if every tunnel
	// fails to register (otherwise Run would block until a natural drop).
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()

	reg := newLocalRegistry()
	runErrCh := make(chan error, 1)
	// Start Run FIRST so NEW_PROXY_RESP frames are routed to RegisterTunnelLive
	// via the session's pending-response channel (a sequential pre-Run
	// RegisterTunnel would mis-read an interleaved NEW_CONN).
	go func() { runErrCh <- cli.Run(sctx, reg.resolve) }()

	// Initial registration: reg is empty, so every planned tunnel is "new".
	sv.reconcile(sctx, logger, cli, reg, state, server)
	planned := len(sv.snapshot())
	if planned > 0 && reg.count() == 0 && sctx.Err() == nil {
		// Had tunnels to register and every one failed — drop and back off
		// rather than hold a useless session. An EMPTY plan is fine: keep the
		// session up idle so the console can add tunnels onto it live.
		logger.Error("no tunnels registered; dropping session and backing off")
		scancel()
	}

	for {
		select {
		case runErr := <-runErrCh:
			// "established" = the session was usable: it carried a live tunnel,
			// or it was an intentionally-idle zero-tunnel session. Either way a
			// drop should reconnect promptly (reset backoff), not be treated as a
			// connect failure.
			established := planned == 0 || reg.count() > 0
			for _, pid := range reg.proxyIDs() {
				state.RemoveTunnel(pid)
			}
			return established, runErr
		case <-sv.reconcileCh:
			// A console write changed the plan — apply the diff live.
			sv.reconcile(sctx, logger, cli, reg, state, server)
		}
	}
}

// liveEntry tracks a tunnel currently registered on the live session: its
// edge-assigned proxy_id + the config_json it was registered with (so reconcile
// can detect a security-policy change and re-register just that tunnel).
type liveEntry struct {
	proxyID    string
	configJSON string
	localAddr  string // the upstream this tunnel was registered with; reconcile re-homes on change
}

// localRegistry is the per-session registry the Run dispatcher consults for
// NEW_CONN (byProxyID, read on the hot path) and reconcile drives (byID). reg
// is owned by the single session goroutine for writes (only reconcile mutates
// it); resolve reads byProxyID concurrently, so it's mutex-guarded.
type localRegistry struct {
	mu        sync.RWMutex
	byProxyID map[string]session.Tunnel
	byID      map[int64]liveEntry
}

func newLocalRegistry() *localRegistry {
	return &localRegistry{
		byProxyID: make(map[string]session.Tunnel),
		byID:      make(map[int64]liveEntry),
	}
}

func (r *localRegistry) resolve(proxyID string) (session.Tunnel, bool) {
	r.mu.RLock()
	t, ok := r.byProxyID[proxyID]
	r.mu.RUnlock()
	return t, ok
}

func (r *localRegistry) set(id int64, proxyID, configJSON string, t session.Tunnel) {
	r.mu.Lock()
	r.byProxyID[proxyID] = t
	r.byID[id] = liveEntry{proxyID: proxyID, configJSON: configJSON, localAddr: t.LocalAddr}
	r.mu.Unlock()
}

func (r *localRegistry) has(id int64) bool {
	r.mu.RLock()
	_, ok := r.byID[id]
	r.mu.RUnlock()
	return ok
}

// removeID drops both indexes for a tunnel id and returns its proxy_id ("" if
// absent).
func (r *localRegistry) removeID(id int64) string {
	r.mu.Lock()
	e, ok := r.byID[id]
	if ok {
		delete(r.byID, id)
		delete(r.byProxyID, e.proxyID)
	}
	r.mu.Unlock()
	return e.proxyID
}

// liveIDs returns the (id → liveEntry) snapshot reconcile diffs against the plan.
func (r *localRegistry) liveIDs() map[int64]liveEntry {
	r.mu.RLock()
	out := make(map[int64]liveEntry, len(r.byID))
	for id, e := range r.byID {
		out[id] = e
	}
	r.mu.RUnlock()
	return out
}

func (r *localRegistry) count() int {
	r.mu.RLock()
	n := len(r.byID)
	r.mu.RUnlock()
	return n
}

func (r *localRegistry) proxyIDs() []string {
	r.mu.RLock()
	out := make([]string, 0, len(r.byProxyID))
	for pid := range r.byProxyID {
		out = append(out, pid)
	}
	r.mu.RUnlock()
	return out
}

// loadLocalConfig reads + parses the YAML config (strict: unknown keys error
// so a typo'd field doesn't silently disable a policy).
func loadLocalConfig(path string) (*localConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg localConfig
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &cfg, nil
}

// resolveLocalToken picks the bearer for the edge:
//
//	token (a literal, or ${ENV_VAR} to read from the environment)
//	  > token_env (deprecated)
//	  > the usual resolveToken() chain (CALABI_TOKEN / creds / defaultToken)
//
// The single `token` field is all a user needs — put the secret inline, or write
// `token: ${CALABI_TOKEN}` to keep it out of the file. How it's read is our
// concern, not the user's; token_env stays only for older configs.
func resolveLocalToken(cfg *localConfig) string {
	if t := strings.TrimSpace(cfg.Token); t != "" {
		if env, ok := tokenEnvRef(t); ok {
			if v := os.Getenv(env); v != "" {
				return v
			}
			// Referenced var unset/empty → fall through to the chain below
			// rather than sending the literal "${VAR}" as the token.
		} else {
			return t
		}
	}
	if cfg.TokenEnv != "" { // deprecated; superseded by token: ${ENV_VAR}
		if v := os.Getenv(cfg.TokenEnv); v != "" {
			return v
		}
	}
	return resolveToken()
}

// tokenEnvRef reports whether s is an env-var reference of the form ${NAME} and
// returns NAME. Only the whole-string brace form counts, so a literal token that
// merely contains a '$' is never partially interpolated (tokens are opaque).
func tokenEnvRef(s string) (string, bool) {
	if strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
		if name := strings.TrimSpace(s[2 : len(s)-1]); name != "" {
			return name, true
		}
	}
	return "", false
}

// validateLocalUpstream enforces that a tunnel forwards to a LOCAL/intranet
// upstream, never an arbitrary public address (which would turn the client into
// an open relay).
//
// The rule itself lives in internal/probe (localaddr.go) because the wizard's
// reachability check needs exactly the same guard before it dials —
// probe.ValidateLocalTarget for the cases it covers.
func validateLocalUpstream(local string) error {
	return probe.ValidateLocalTarget(local)
}

// resolveSubdomainDomain mirrors the edge's host resolution: an explicit full
// Domain always wins; otherwise a requested subdomain PREFIX expands to
// <subdomain>.<base>. Returns "" (→ edge auto-allocates a random subdomain)
// when there is neither a domain nor a (subdomain + base) pair.
func resolveSubdomainDomain(domain, subdomain, base string) string {
	if d := strings.TrimSpace(domain); d != "" {
		return d
	}
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	base = strings.TrimSpace(base)
	if subdomain != "" && base != "" {
		return subdomain + "." + base
	}
	return ""
}

// toSessionTunnel maps one config entry to a session.Tunnel, building the
// security config_json (bcrypt'ing basic-auth passwords) when present.
func toSessionTunnel(tc localTunnelConfig) (session.Tunnel, error) {
	kind, err := parseProxyKind(tc.Type)
	if err != nil {
		return session.Tunnel{}, err
	}
	local := normalizeLocalAddr(tc.Local)
	if local == "" {
		return session.Tunnel{}, fmt.Errorf("missing `local` address")
	}
	name := strings.TrimSpace(tc.Name)
	if name == "" {
		name = tc.Type
	}
	var secJSON string
	switch {
	case strings.TrimSpace(tc.SecurityConfigJSON) != "":
		// Console-managed: a pre-built (bcrypt'd) blob, used verbatim.
		secJSON = tc.SecurityConfigJSON
	case tc.Security != nil:
		secJSON, err = tc.Security.toConfigJSON(kind == proto.ProxyKindHTTP)
		if err != nil {
			return session.Tunnel{}, fmt.Errorf("security: %w", err)
		}
	}
	return session.Tunnel{
		Name:               name,
		Type:               kind,
		LocalAddr:          local,
		Domain:             strings.TrimSpace(tc.Domain),
		Subdomain:          strings.ToLower(strings.TrimSpace(tc.Subdomain)),
		RemotePort:         tc.RemotePort,
		SecurityConfigJSON: secJSON,
	}, nil
}

// toConfigJSON reuses the CLI's securityFlags builder so the YAML produces a
// byte-identical `security` block. l7=false (tcp/udp/sni) rejects HTTP-only
// knobs rather than silently dropping them.
func (s *localSecurityConfig) toConfigJSON(l7 bool) (string, error) {
	if !l7 {
		if len(s.BasicAuth) > 0 || len(s.SetHeader) > 0 || len(s.DelHeader) > 0 ||
			strings.TrimSpace(s.OAuthProvider) != "" {
			return "", fmt.Errorf("basic_auth / set_header / del_header / oauth_* are HTTP-only (this tunnel is not type http)")
		}
	}
	sf := &securityFlags{
		l7:         l7,
		standalone: true, // local daemon always targets its own edge; suppress the managed-edge warning
		file:       s.File,
		ipAllow:    stringList(s.IPAllow),
		ipDeny:     stringList(s.IPDeny),
		rate:       s.Rate,
	}
	if l7 {
		sf.basicAuth = stringList(s.BasicAuth)
		sf.setHeader = stringList(s.SetHeader)
		sf.delHeader = stringList(s.DelHeader)
		sf.oauthProvider = s.OAuthProvider
		sf.oauthClientID = s.OAuthClientID
		sf.oauthClientSecret = s.OAuthClientSecret
		sf.oauthEmail = stringList(s.OAuthAllowEmail)
		sf.oauthDomain = stringList(s.OAuthAllowDomain)
	}
	return sf.buildConfigJSON()
}

// parseProxyKind maps the YAML `type` to a wire ProxyKind.
func parseProxyKind(t string) (proto.ProxyKind, error) {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "http":
		return proto.ProxyKindHTTP, nil
	case "https":
		// HTTPS tunnel = the LOCAL upstream speaks TLS; dialUpstream TLS-dials it
		// (the edge registers an HTTP domain the same as a plain http tunnel).
		return proto.ProxyKindHTTPS, nil
	case "tcp":
		return proto.ProxyKindTCP, nil
	case "udp":
		return proto.ProxyKindUDP, nil
	case "sni":
		return proto.ProxyKindSNI, nil
	default:
		return "", fmt.Errorf("unknown tunnel type %q (want http|https|tcp|udp|sni)", t)
	}
}

// normalizeLocalAddr accepts "host:port" verbatim or a bare numeric port (→
// 127.0.0.1:port). Delegates to internal/probe so the wizard's check normalizes
// an address exactly the way the tunnel that follows it will.
func normalizeLocalAddr(s string) string {
	return probe.NormalizeLocalTarget(s)
}

// localPublicAddr formats the public address for the /status page (display
// only — traffic flows regardless of this string).
func localPublicAddr(kind, edgeHost string, a session.Assigned) string {
	switch strings.ToLower(kind) {
	case "http", "https":
		if a.Domain != "" {
			return "https://" + a.Domain
		}
	case "sni":
		if a.Domain != "" {
			return "tls://" + a.Domain
		}
	case "tcp":
		return fmt.Sprintf("tcp://%s:%d", edgeHost, a.RemotePort)
	case "udp":
		return fmt.Sprintf("udp://%s:%d", edgeHost, a.RemotePort)
	}
	return ""
}

// hostOnly strips a trailing :port from a host:port (for public-addr display).
func hostOnly(server string) string {
	if i := lastIndexByte(server, ':'); i > 0 {
		return server[:i]
	}
	return server
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
