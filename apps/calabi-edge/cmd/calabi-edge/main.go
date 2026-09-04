// calabi-edge is the Calabi data-plane process.
//
// It accepts TLS-multiplexed client connections (control + data streams),
// a visitor HTTP listener that forwards traffic to clients by Host header,
// a TCP listener pool for L4 tunnels, a UDP listener pool +
// TLS-SNI passthrough listener, and HTTPS termination.
//
// Notable: transport is TLS-1.3 + yamux only.
//
// This file is the data-plane CORE and imports NO internal/platform/* package.
// All control-plane wiring lives behind a build tag; run() consumes the control
// plane only through the platformDeps bundle returned by wirePlatform (a stub in
// this build).
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/config"
	"github.com/calabi/calabi/apps/calabi-edge/internal/configreload"
	"github.com/calabi/calabi/apps/calabi-edge/internal/listener"
	"github.com/calabi/calabi/apps/calabi-edge/internal/metrics"
	"github.com/calabi/calabi/apps/calabi-edge/internal/ratelimit"
	"github.com/calabi/calabi/apps/calabi-edge/internal/router"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
	"github.com/calabi/calabi/apps/calabi-edge/internal/tlsutil"
	"github.com/calabi/calabi/pkg/observability"

	"github.com/prometheus/client_golang/prometheus"
)

const edgeVersion = "0.1.0-m3-sprint5"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "calabi-edge: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "path to config YAML (optional)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	// Self-hosters often run without a config file at all — a relay-only node has
	// no domain, no certificate and nothing else to configure. Env overrides for
	// mode / role / the relay block keep that possible now that the standalone
	// derp-node binary (which was ENTIRELY env-driven) is retired. Env wins over
	// the file. See internal/config/env.go.
	cfg, err = config.ApplyEnv(cfg)
	if err != nil {
		return err
	}
	logger := newLogger(cfg.Log)

	// Standalone normalization: a self-hosted (mode=standalone) edge has no
	// control plane, so its control-plane addresses are cleared; a BYOI edge
	// (bff-edge cert) is refused standalone and kept on platform semantics.
	// See config.NormalizeForMode +
	var byoiRefused bool
	cfg, byoiRefused = cfg.NormalizeForMode()
	if byoiRefused {
		logger.Warn("mode=standalone ignored: edge is configured for bff-edge (BYOI / control-plane cert); keeping platform semantics")
	}
	// Role selects which data plane(s) run (edge/derp merge). Reject a typo now
	// rather than silently run neither. Empty defaults to "edge" (unchanged).
	if err := cfg.ValidateRole(); err != nil {
		return err
	}
	// CALABI_ENV=production: none of the dev fallbacks (static token table,
	// the shipped placeholder credential, an ungranted platform relay) may be
	// active. Checked AFTER NormalizeForMode so "no control plane" reads as the
	// stated standalone intent rather than a missing dependency.
	// config/prodguard.go + F0.2.
	if err := cfg.ValidateProductionPosture(); err != nil {
		return err
	}
	// A relay with no label can run, but it cannot be registered in the org's
	// DERP map (region code is "self-"+label) and its usage reports have no
	// self-<label> region to attribute to — so no mesh node will ever home on
	// it. Warn loudly rather than start a relay nobody can reach.
	if cfg.RunsRelay() && cfg.Relay.Label == "" {
		logger.Warn("relay role has no relay.label: the relay runs but cannot be registered in the DERP map or reported for usage — set relay.label")
	}

	logger.Info("starting calabi-edge",
		"node_label", cfg.NodeLabel,
		"region", cfg.Region,
		"control_addr", cfg.Control.Addr,
		"http_addr", cfg.HTTP.Addr,
		"base_domain", cfg.HTTP.BaseDomain,
		"mode", func() string {
			if cfg.IsStandaloneMode() {
				return "standalone"
			}
			return "platform"
		}(),
	)

	cert, err := tlsutil.LoadOrGenerate(cfg.Control.CertPEM, cfg.Control.KeyPEM)
	if err != nil {
		return fmt.Errorf("tls bootstrap: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"calabi/1"},
	}

	obs := observability.New(logger, observability.Options{
		Service:   "calabi-edge",
		Version:   edgeVersion,
		AdminAddr: cfg.Admin.Addr,
	})
	metricsSet := metrics.New(obs.Registry())

	r := router.New()
	mgr := session.NewManager(logger, metricsSet)
	domains := router.NewSubdomainAllocator(cfg.HTTP.BaseDomain)
	// Persist the seq counter across restarts when state.dir is
	// configured (recommended). Without it, a fresh boot would rewind
	// to u000001 and collide with rows still in tunnel-svc — Claim
	// returns AlreadyExists, then Persist falls into the custom-domain
	// path demanding `calabi domains create ...`. With the file-backed
	// counter, restart picks up at u<last+1> with no extra bookkeeping.
	if cfg.State.Dir != "" {
		seqPath := filepath.Join(cfg.State.Dir, "subdomain.seq")
		if err := domains.UsePersistentSeq(seqPath, logger); err != nil {
			logger.Warn("subdomain seq persistence disabled; falling back to time-seeded counter",
				"path", seqPath, "err", err)
			domains.Seed(uint64(time.Now().Unix() % 1_000_000))
		} else {
			logger.Info("subdomain seq persisted", "path", seqPath)
		}
	} else {
		// No state dir → ugly-but-collision-free time-based offset.
		// See StateConfig docs for the recommended fix.
		domains.Seed(uint64(time.Now().Unix() % 1_000_000))
	}
	ports := router.NewPortPool(20000, 20999)

	// Port-pool utilization metric (2026-06-11): TCP/UDP tunnels each bind a
	// port from this finite pool (capped per-org by max_port_tunnels). Surface
	// in-use vs capacity as GaugeFuncs (read lazily on scrape) so ops can alert
	// before an edge exhausts its range.
	obs.Registry().MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "calabi_edge_port_pool_in_use",
			Help: "TCP/UDP remote ports currently occupied (allocated + boot-reserved).",
		}, func() float64 { return float64(ports.InUse()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "calabi_edge_port_pool_capacity",
			Help: "Total TCP/UDP remote ports in this edge's range.",
		}, func() float64 { return float64(ports.Capacity()) }),
	)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// edgeID is shared by config-svc subscription and presence reporting;
	// zero means "this edge has no numeric id in config" — we hash the
	// string node_id to get a stable int64 that won't collide with the
	// dev defaults.
	edgeID := cfg.Tunnel.EdgeNodeID
	if edgeID == 0 {
		edgeID = hashNodeIDForConfig(cfg.NodeLabel)
		// The hash always lands in the >= 1e9 BYOI reserved range, so with a
		// control plane wired this fallback is never what the operator meant:
		// in cluster mode the edge registers under an id bff-console's
		// /v1/edges hides from every client, and in bff-edge mode bff-edge
		// overwrites the wire id from the cert CN, leaving this node's local
		// self-id disagreeing with what the control plane recorded. Both boot
		// clean and fail invisibly. A config-less standalone / dev edge has no
		// id legitimately, so this warns rather than refusing to start.
		if cfg.Tunnel.Addr != "" || cfg.MultiRegion.IsBFFEdge() {
			logger.Warn("edge_node_id not set; derived from a hash of node_label, which lands in the BYOI reserved range — set a small unique edge_node_id",
				"node_label", cfg.NodeLabel, "derived_edge_node_id", edgeID)
		}
	}

	registrar := &routerBridge{r: r, logger: logger, tcpObs: metricsSet, udpObs: metricsSet}

	// presence-kick channel. The control listener pushes on session
	// close → the (platform) presence reporter drains it next select iteration
	// → identity-svc sees the device gone within seconds. Buffer of 32 absorbs
	// a brief storm of closes; a dropped kick is caught by the next regular
	// tick, so the contract degrades to "back to old behaviour", not "stale
	// forever". Created here in the core because the listener's OnSessionGone
	// hook feeds it; the platform reporter on the other end is optional.
	presenceKick := make(chan struct{}, 32)

	// Phase B global backpressure (2026-06-11): process-wide, org-agnostic
	// ceilings that protect THIS box regardless of how per-org caps sum up.
	// Opt-in via env (0/unset = unlimited, so dev behaves as before):
	//   EDGE_GLOBAL_MAX_CONNS            total concurrent visitor connections
	//   EDGE_GLOBAL_ACCEPT_RATE_PER_SEC  total new connections/sec accepted
	// On trip the listeners shed (close/drop). Core (env-driven) — independent
	// of the per-org, quota-fed Phase A limiters which the platform layer wires.
	gMaxConns := envInt64(logger, "EDGE_GLOBAL_MAX_CONNS")
	gAcceptRate := envInt64(logger, "EDGE_GLOBAL_ACCEPT_RATE_PER_SEC")
	globalLimiter := ratelimit.NewGlobalLimiter(gMaxConns, gAcceptRate)
	registrar.glob = globalLimiter
	if globalLimiter.Configured() {
		logger.Info("global backpressure wired",
			"max_conns", gMaxConns, "accept_rate_per_sec", gAcceptRate)
	}

	// Control-plane wiring. The platform build dials identity / tunnel / quota /
	// cert / config / usage / bff-edge and returns the deps below; a self-hosted node
	// build returns an all-nil bundle (data plane only). run() never imports a
	// platform package — it only consumes the returned interfaces.
	deps, err := wirePlatform(ctx, logger, platformInputs{
		cfg:          cfg,
		mgr:          mgr,
		domains:      domains,
		ports:        ports,
		registrar:    registrar,
		edgeID:       edgeID,
		presenceKick: presenceKick,
	})
	if err != nil {
		return err
	}
	defer closeAll(deps.closers)

	// Token verification: prefer the platform identity-svc verifier when wired,
	// fall back to the static-YAML table for dev / standalone / demo. The
	// static table is held behind a hot verifier so fsnotify reload can swap
	// accepted_tokens without a restart.
	staticVerifier := newHotTokenVerifier(cfg.AcceptedTokens)
	var verifier session.TokenVerifier = staticVerifier
	if deps.verifier != nil {
		verifier = deps.verifier
	}

	// Effective "trust client-supplied security policy" decision. Standalone
	// normalization above already guarantees a standalone edge has no control
	// plane wired; the self-hosted build additionally compiles none in. We still
	// derive the decision through TrustsClientPolicy(deps.controlPlaneWired) as
	// defense in depth — if a control plane is wired the guard refuses to trust.
	trustClientPolicy := cfg.TrustsClientPolicy(deps.controlPlaneWired)
	if trustClientPolicy {
		logger.Info("standalone mode: trusting client-supplied per-proxy security policy")
	}

	ctrl := listener.NewControl(logger, listener.ControlOptions{
		Addr:     cfg.Control.Addr,
		TLS:      tlsCfg,
		ServerID: cfg.NodeLabel,
		Region:   cfg.Region,
		// surface base_domain to daemons so they render TCP/UDP
		// public addrs as `<base>:<port>` instead of the dev-confusing
		// `localhost:<port>`. Reuses HTTPListener.BaseDomain since TCP and
		// HTTP traffic both terminate on the same edge IP — a separate
		// tcp.<base> CNAME is fine but isn't needed for the URL display.
		BaseDomain:         cfg.HTTP.BaseDomain,
		HTTPPort:           portFromAddr(cfg.HTTP.Addr),
		HTTPSPort:          portFromAddr(cfg.HTTPS.Addr),
		TrustClientPolicy:  trustClientPolicy,
		Manager:            mgr,
		Verifier:           verifier,
		Registrar:          registrar,
		Domains:            domains,
		Ports:              ports,
		Persister:          deps.persister,
		Router:             r,
		Observer:           metricsSet,
		BandwidthResolver:  deps.bandwidthResolver,
		ConnGuardInstaller: deps.connGuard,
		OnlineCapAdmit:     deps.onlineCap,
		PostHandshake:      deps.postHandshake,
		OnSessionGone: func() {
			// Non-blocking: if the buffer is full, the next regular
			// tick still catches the change.
			select {
			case presenceKick <- struct{}{}:
			default:
			}
		},
	})
	http := listener.NewHTTP(logger, listener.HTTPOptions{
		Addr:                  cfg.HTTP.Addr,
		Router:                r,
		Observer:              metricsSet,
		MeshResolver:          deps.meshResolver,
		SelfEdgeID:            edgeID,
		GlobalLimiter:         globalLimiter,
		ACMEChallengeResolver: deps.acmeChallengeResolver,
	})
	sni := listener.NewSNI(logger, listener.SNIOptions{
		Addr:          cfg.SNI.Addr,
		Router:        r,
		Observer:      metricsSet,
		MeshResolver:  deps.meshResolver,
		SelfEdgeID:    edgeID,
		GlobalLimiter: globalLimiter,
	})
	// peer-forward listener (owner side). Binds the VPC-internal
	// mesh.forward_addr and serves visitor connections relayed by a
	// same-region peer for tunnels THIS edge owns. Empty addr (mesh
	// disabled / single-edge region) makes Run a no-op.
	forward := listener.NewForward(logger, listener.ForwardOptions{
		Addr:     cfg.Mesh.ForwardAddr,
		Router:   r,
		Observer: metricsSet,
	})
	if cfg.MeshEnabled() {
		logger.Info("edge mesh enabled",
			"forward_addr", cfg.Mesh.ForwardAddr,
			"advertise_addr", cfg.Mesh.AdvertiseAddr)
	}

	// HTTPS terminator: compose the platform cert-svc source (deps.getCertificate,
	// nil when self-hosted / no cert-svc) with the core self-signed wildcard dev
	// fallback. Returns an addr-less no-op listener when HTTPS is disabled.
	httpsListener, err := buildHTTPSListener(logger, cfg, r, metricsSet,
		deps.getCertificate, deps.meshResolver, edgeID, globalLimiter)
	if err != nil {
		return err
	}

	// fsnotify hot-reload of the edge.yaml. Whitelist:
	// accepted_tokens, http.base_domain. Any other field change is
	// refused with a logged warning until the operator restarts.
	reloader := configreload.New(*configPath, cfg, &hotReloadApplier{
		verifier: staticVerifier,
		domains:  domains,
		logger:   logger,
	}, logger)

	errCh := make(chan error, 16)
	// Edge (tunnel) datapath — started only for role edge/both. For role=relay
	// these listeners are built above but never bind a port, so a relay-only node
	// serves no tunnels. Empty role ⇒ RunsEdge()=true ⇒ every existing edge is
	// unchanged.
	if cfg.RunsEdge() {
		go func() { errCh <- labelErr("control", ctrl.Run(ctx)) }()
		go func() { errCh <- labelErr("http", http.Run(ctx)) }()
		go func() { errCh <- labelErr("https", httpsListener.Run(ctx)) }()
		go func() { errCh <- labelErr("sni", sni.Run(ctx)) }()
		go func() { errCh <- labelErr("forward", forward.Run(ctx)) }()
	}
	// Relay-only: state the isolation claim in the log so it can be checked
	// against reality (`ss -ltnp` should show ONLY these two ports). Since the
	// standalone derp-node binary was retired this is what replaces "you can
	// it is a different process" — see internal/config/roleguard.go.
	if cfg.RunsRelay() && !cfg.RunsEdge() {
		logger.Info("relay-only node: NO TLS-terminating listener bound; this process serves the mesh relay data port and the STUN responder only",
			"derp_port", cfg.Relay.RelayDERPPort(), "stun_port", cfg.Relay.RelaySTUNPort())
	}
	// Mesh-relay datapath — started for role relay/both. Ciphertext-only, isolated
	// from the edge's TLS termination.
	if cfg.RunsRelay() {
		go func() { errCh <- labelErr("relay", runRelay(ctx, cfg.Relay, logger, deps.relayReporter)) }()
	}
	go func() { errCh <- labelErr("admin", obs.Run(ctx)) }()
	go func() { errCh <- labelErr("configreload", reloader.Run(ctx)) }()
	// Platform background goroutines (presence / edge-registrar / usage /
	// deny-sweeper / evict / mesh-resolver). Empty in the self-hosted build.
	for _, rn := range deps.runners {
		rn := rn
		go func() { errCh <- labelErr(rn.name, rn.run(ctx)) }()
	}

	// Flip ready once the foreground listeners have called Listen() and
	// returned no error. We approximate "all up" with a short delay; will plumb explicit ready signals from each listener.
	obs.SetReady(true)

	select {
	case <-ctx.Done():
		logger.Info("shutdown requested")
		obs.SetReady(false)
	case err := <-errCh:
		obs.SetReady(false)
		if err != nil {
			logger.Error("listener exited", "err", err)
			return err
		}
	}
	return nil
}

// buildHTTPSListener composes the HTTPS terminator. The platform cert-svc
// source (certFromPlatform, may be nil) is tried first; a self-signed wildcard
// for cfg.HTTP.BaseDomain is the dev/standalone fallback. Mirrors the pre-split
// inline logic exactly: cert-svc + self-signed (dev), cert-svc only (prod),
// self-signed only (standalone), or an addr-less no-op listener when HTTPS is
// disabled. The self-signed path is CORE so a self-hosted / standalone edge can
// terminate HTTPS without cert-svc.
func buildHTTPSListener(
	logger *slog.Logger,
	cfg config.Config,
	r *router.Router,
	metricsSet *metrics.Set,
	certFromPlatform func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	meshResolver listener.OwnerResolver,
	edgeID int64,
	globalLimiter *ratelimit.GlobalLimiter,
) (*listener.HTTPS, error) {
	if cfg.HTTPS.Addr == "" {
		// Pass an addr-less listener so the goroutine slot stays uniform.
		return listener.NewHTTPS(logger, listener.HTTPSOptions{}), nil
	}

	// loadSelfSigned builds (or loads from state.dir) a cached self-signed
	// wildcard cert for HTTP.BaseDomain. Dev / standalone only.
	loadSelfSigned := func() (*tls.Certificate, error) {
		certPath, keyPath := "", ""
		if cfg.State.Dir != "" {
			certPath = filepath.Join(cfg.State.Dir, "edge-https.crt")
			keyPath = filepath.Join(cfg.State.Dir, "edge-https.key")
		}
		cert, certErr := tlsutil.LoadOrGenerateWildcard(certPath, keyPath, cfg.HTTP.BaseDomain)
		if certErr != nil {
			return nil, certErr
		}
		cached := cert
		return &cached, nil
	}

	var getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	switch {
	case certFromPlatform != nil && cfg.HTTPS.SelfSigned && cfg.HTTP.BaseDomain != "":
		// Dev (multi-edge / bff-edge): serve cert-svc certs when the bridge has
		// one for the requested SNI, else fall back to a self-signed wildcard so
		// HTTPS works locally without provisioning a real cert. Gated by
		// https.self_signed — NEVER enable in prod (see HTTPSListener doc).
		fallback, certErr := loadSelfSigned()
		if certErr != nil {
			return nil, fmt.Errorf("https self-signed wildcard cert: %w", certErr)
		}
		getCert = func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c, err := certFromPlatform(hi); err == nil {
				return c, nil
			}
			return fallback, nil
		}
		logger.Warn("https listener: cert-svc certs + self-signed wildcard fallback (dev only)",
			"addr", cfg.HTTPS.Addr, "base_domain", cfg.HTTP.BaseDomain)
	case certFromPlatform != nil:
		// Production path: real certs streamed from cert-svc, hot rotated as new
		// orgs/domains come online.
		getCert = certFromPlatform
	case cfg.HTTP.BaseDomain != "":
		// Dev / standalone path: self-signed wildcard for the base domain.
		// Cached under state.dir so the trust-store import survives restarts;
		// without state.dir the cert is regenerated each boot.
		cached, certErr := loadSelfSigned()
		if certErr != nil {
			return nil, fmt.Errorf("https self-signed wildcard cert: %w", certErr)
		}
		getCert = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cached, nil }
		logger.Warn("https listener using self-signed wildcard cert (dev fallback)",
			"addr", cfg.HTTPS.Addr,
			"base_domain", cfg.HTTP.BaseDomain,
			"hint", "import the generated edge-https.crt under state.dir into your OS trust store to silence browser warnings")
	default:
		return nil, fmt.Errorf("config error: https.addr=%q requires either cert.addr (prod) or http.base_domain (dev self-signed)", cfg.HTTPS.Addr)
	}

	return listener.NewHTTPS(logger, listener.HTTPSOptions{
		Addr:           cfg.HTTPS.Addr,
		Router:         r,
		Observer:       metricsSet,
		GetCertificate: getCert,
		MeshResolver:   meshResolver,
		SelfEdgeID:     edgeID,
		GlobalLimiter:  globalLimiter,
	}), nil
}

// hotTokenVerifier implements session.TokenVerifier on top of an
// atomically-swappable token table. used a const map captured in
// the Config struct; makes the table swappable so the
// fsnotify reload can rotate accepted_tokens without a restart.
//
// Verify is on the session-establishment hot path — we avoid taking a
// lock by holding the table behind atomic.Pointer.
type hotTokenVerifier struct {
	tokens atomic.Pointer[map[string]config.TokenEntry]
}

func newHotTokenVerifier(initial []config.TokenEntry) *hotTokenVerifier {
	v := &hotTokenVerifier{}
	v.Replace(initial)
	return v
}

func (v *hotTokenVerifier) Replace(entries []config.TokenEntry) {
	m := make(map[string]config.TokenEntry, len(entries))
	for _, e := range entries {
		m[e.Token] = e
	}
	v.tokens.Store(&m)
}

func (v *hotTokenVerifier) Verify(token string) (string, string, string, bool) {
	m := v.tokens.Load()
	if m == nil {
		return "", "", "", false
	}
	e, ok := (*m)[token]
	if !ok {
		return "", "", "", false
	}
	return e.TenantID, e.WorkspaceID, e.ClientID, true
}

// hotReloadApplier wires the configreload package's whitelist callbacks
// to the live token verifier + subdomain allocator.
type hotReloadApplier struct {
	verifier *hotTokenVerifier
	domains  *router.SubdomainAllocator
	logger   *slog.Logger
}

func (a *hotReloadApplier) ApplyAcceptedTokens(tokens []config.TokenEntry) {
	a.verifier.Replace(tokens)
	a.logger.Info("reload: accepted_tokens", "count", len(tokens))
}

func (a *hotReloadApplier) ApplyBaseDomain(base string) {
	old := a.domains.Base()
	if old == base {
		return
	}
	a.domains.SetBase(base)
	a.logger.Info("reload: base_domain", "old", old, "new", base)
}

// routerBridge implements session.ProxyRegistrar against *router.Router.
// It also owns the side-effect of opening per-proxy sockets (TCP / UDP).
//
// HTTP and SNI proxies don't need a per-proxy socket — the global HTTP
// (Host-routed) and SNI (server_name-routed) listeners handle them. The
// bridge just registers the route and returns nil for Listener.
type routerBridge struct {
	r      *router.Router
	logger *slog.Logger
	tcpObs listener.TCPObserver
	udpObs listener.UDPObserver
	// glob is the process-wide backpressure (Phase B), passed to each
	// per-proxy TCP/UDP listener so their accept paths shed under machine
	// pressure. Set in run() after the limiter is built (registrar is
	// constructed earlier); nil = unlimited.
	glob *ratelimit.GlobalLimiter
}

func (b *routerBridge) RegisterHTTP(domain string, sess *session.Session, proxyID string) error {
	return b.r.RegisterHTTP(domain, sess, sess.ID, proxyID)
}

func (b *routerBridge) RegisterSNI(domain string, sess *session.Session, proxyID string) error {
	return b.r.RegisterSNI(domain, sess, sess.ID, proxyID)
}

func (b *routerBridge) RegisterTCP(port uint32, sess *session.Session, proxyID string) (io.Closer, error) {
	if err := b.r.RegisterTCP(port, sess, sess.ID, proxyID); err != nil {
		return nil, err
	}
	ln, err := listener.StartTCPProxy(b.logger, port, sess, proxyID, b.tcpObs, b.glob)
	if err != nil {
		// Roll back the route registration if the listener fails to bind.
		b.r.UnregisterByProxyID(proxyID)
		return nil, err
	}
	return ln, nil
}

func (b *routerBridge) RegisterUDP(port uint32, sess *session.Session, proxyID string) (io.Closer, error) {
	if err := b.r.RegisterUDP(port, sess, sess.ID, proxyID); err != nil {
		return nil, err
	}
	ln, err := listener.StartUDPProxy(b.logger, port, sess, proxyID, b.udpObs, b.glob)
	if err != nil {
		b.r.UnregisterByProxyID(proxyID)
		return nil, err
	}
	return ln, nil
}

func (b *routerBridge) UnregisterByProxyID(proxyID string) {
	b.r.UnregisterByProxyID(proxyID)
}

func newLogger(c config.LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(c.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	handlerOpts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.ToLower(c.Format) == "json" {
		h = slog.NewJSONHandler(os.Stdout, handlerOpts)
	} else {
		h = slog.NewTextHandler(os.Stdout, handlerOpts)
	}
	return slog.New(h)
}

func labelErr(name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", name, err)
}

// hashNodeIDForConfig mirrors tunnelstore.hashToID so the same edge_node_id
// is used in both tunnel-svc and config-svc registrations.
// advertisedAddr returns the host:port this edge registers in the edge
// directory — the address daemons get from /v1/edges and dial directly, and the
// host a platform relay's DERP endpoint is derived from.
//
// control.addr is a BIND address and public.addr an ADVERTISED one; they are
// not interchangeable, which is why falling back from one to the other is only
// safe in a specific case. On a single host ":7443" happens to work as a dial
// string (Go reads it as localhost), so dev configs legitimately omit
// public.addr. Anywhere the node reaches the control plane through bff-edge it
// is by definition NOT on the same host as its daemons, and advertising a bind
// address there registers the edge as reachable when nothing can reach it —
// that is what the second return value flags.
func advertisedAddr(cfg config.Config) (addr string, unreachable bool) {
	if a := strings.TrimSpace(cfg.Public.Addr); a != "" {
		return a, false
	}
	return cfg.Control.Addr, cfg.MultiRegion.IsBFFEdge()
}

func hashNodeIDForConfig(label string) int64 {
	if label == "" {
		return 1
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(label))
	v := int64(h.Sum64() & 0x7fffffffffffffff)
	if v == 0 {
		v = 1
	}
	return v
}

// onlineCapAdapter implements listener.OnlineCapAdmit by combining
// identity-svc (current online count) + quota-svc (the configured
// limit). Both upstreams MUST be wired — if either is nil the adapter
// returns Allowed=true so the edge keeps working in dev modes that
// don't bring up the full control plane.
//
// Fail-closed policy: the adapter returns Allowed=false on any
// transport / parse error. Admitting on error silently breaks the
// cap; we'd rather see a bug report ("can't connect") than a quota
// leak in the wild.
//
// Defined in the core (no platform import) so admit_test.go can exercise
// it without the platform build tag; the platform wiring feeds it the real
// identity / quota clients via the narrow interfaces below.
type onlineCapAdapter struct {
	identityCli onlineCapIdentity
	quotaCli    onlineCapQuota
	logger      *slog.Logger
}

// onlineCapIdentity is the bit of *identity.Verifier the adapter
// uses. Narrow interface so we can fake it in tests without dragging
// in the full identity client.
type onlineCapIdentity interface {
	GetOrgOnlineCount(ctx context.Context, orgID int64) (int32, error)
}

// onlineCapQuota narrows *quotaclient.Client to just the call we need.
type onlineCapQuota interface {
	OnlineClientLimit(ctx context.Context, orgID int64) (int64, error)
}

func (a *onlineCapAdapter) AdmitNewSession(ctx context.Context, tenantID string) listener.AdmitDecision {
	if a == nil || a.identityCli == nil || a.quotaCli == nil {
		// Adapter not fully wired — admit. The dev shortcut path
		// (no quota / no identity) lands here.
		return listener.AdmitDecision{Allowed: true, Limit: -1}
	}
	orgID, err := strconvAtoi64(tenantID)
	if err != nil || orgID <= 0 {
		// Non-numeric tenant (static-YAML dev tokens) — these clients
		// never had a real org row, so there's nothing meaningful to
		// gate against. Admit. The presence reporter will also stamp
		// org_id=0 on these rows so they don't pollute the per-org
		// count anyway.
		return listener.AdmitDecision{Allowed: true, Limit: -1}
	}

	limit, lerr := a.quotaCli.OnlineClientLimit(ctx, orgID)
	if lerr != nil {
		a.logger.Warn("online-cap: quota lookup failed, refusing session",
			"org_id", orgID, "err", lerr)
		return listener.AdmitDecision{
			Allowed: false,
			Reason:  "quota lookup failed; please retry shortly",
		}
	}
	if limit < 0 {
		// Unlimited.
		return listener.AdmitDecision{Allowed: true, Limit: -1}
	}

	current, cerr := a.identityCli.GetOrgOnlineCount(ctx, orgID)
	if cerr != nil {
		a.logger.Warn("online-cap: presence lookup failed, refusing session",
			"org_id", orgID, "err", cerr)
		return listener.AdmitDecision{
			Allowed: false,
			Reason:  "presence lookup failed; please retry shortly",
		}
	}
	if int64(current)+1 > limit {
		return listener.AdmitDecision{
			Allowed: false,
			Current: current,
			Limit:   int32(limit),
			Reason:  fmt.Sprintf("您的套餐最多允许 %d 台客户端同时在线 (当前 %d)。请升级套餐或退出闲置客户端。", limit, current),
		}
	}
	return listener.AdmitDecision{
		Allowed: true,
		Current: current,
		Limit:   int32(limit),
	}
}

// bandwidthLookup is the narrow interface the adapter needs from the
// quota client. Both *quotaclient.Client and *quotaclient.CachedClient
// satisfy it, so the adapter compiles with or without the cache.
type bandwidthLookup interface {
	BandwidthLimitsBytesPerSec(ctx context.Context, orgID int64) (sustainedBps, peakBps int64)
}

// quotaBandwidthAdapter bridges *quotaclient.Client (or its cached
// variant) to the listener.BandwidthResolver interface. tenantID is
// the string form of org_id wire shape (identity-
// svc emits numeric org ids); non-numeric tenants resolve to 0 = unlimited.
//
// Core type (no platform import): the self-hosted build constructs it with a
// nil cli, which still honours the EDGE_DEBUG_BANDWIDTH_BPS dev override and
// otherwise reports "unlimited".
type quotaBandwidthAdapter struct {
	cli    bandwidthLookup
	logger *slog.Logger
}

func (a *quotaBandwidthAdapter) BandwidthLimitsBytesPerSec(ctx context.Context, tenantID, _ string) (int64, int64) {
	// Test-only override: EDGE_DEBUG_BANDWIDTH_BPS=N forces all sessions
	// to N bytes/sec sustained (no peak tier) regardless of tenant /
	// quota-svc. Used by the e2e to assert the limiter wires
	// through to io.Copy.
	if dbg := os.Getenv("EDGE_DEBUG_BANDWIDTH_BPS"); dbg != "" {
		if n, err := strconvAtoi64(dbg); err == nil && n > 0 {
			return n, 0
		}
	}
	if a == nil || a.cli == nil {
		return 0, 0
	}
	orgID, err := strconvAtoi64(tenantID)
	if err != nil || orgID <= 0 {
		// Static-YAML / dev tenants like "dev" / "e2e" never had a real
		// org row; nothing to look up.
		return 0, 0
	}
	return a.cli.BandwidthLimitsBytesPerSec(ctx, orgID)
}

// connLimitsLookup is the slice of the quota client the conn-guard needs.
// Both *quotaclient.Client and *quotaclient.CachedClient satisfy it.
type connLimitsLookup interface {
	ConnLimits(ctx context.Context, orgID int64) (maxConns, tcpRatePerMin, httpRatePerMin int64)
	DailyLimits(ctx context.Context, orgID int64) (dailyTCPConns, dailyHTTPReqs int64)
}

// connGuardAdapter implements listener.ConnGuardInstaller (Phase A
// anti-abuse, 2026-06-11). At handshake it resolves the session's org
// connection caps from quota-svc and installs a *session.ConnGuard
// pointing at the process-global limiters.
//
// Degrades open: non-numeric tenants (static-YAML dev) are left
// unguarded, and the quota client returns zeros (= unlimited) on any
// lookup error — so a quota-svc hiccup never blocks a paying user's
// visitors. SetCap / SetRatePerMin treat 0 as "unlimited for this org".
//
// Core type (ratelimit is core); the platform wiring constructs it with the
// process-global limiters + the quota client. The self-hosted build leaves
// connGuard nil entirely (no per-org caps without quota-svc).
type connGuardAdapter struct {
	conns     *ratelimit.ConnLimiter
	httpRate  *ratelimit.RateLimiter
	tcpRate   *ratelimit.RateLimiter
	tcpDaily  *ratelimit.DailyCounter
	httpDaily *ratelimit.DailyCounter
	quota     connLimitsLookup
	logger    *slog.Logger
}

func (a *connGuardAdapter) InstallConnGuard(ctx context.Context, sess *session.Session, tenantID string) {
	if a == nil || a.quota == nil {
		return
	}
	orgID, err := strconvAtoi64(tenantID)
	if err != nil || orgID <= 0 {
		// Static-YAML / dev tenants never had a real org row — nothing to
		// gate against. Leave the session unguarded.
		return
	}
	maxConns, tcpRPM, httpRPM := a.quota.ConnLimits(ctx, orgID)
	dailyTCP, dailyHTTP := a.quota.DailyLimits(ctx, orgID)
	// Hot-update the per-org caps on the process-global limiters (shared
	// across every session of this org). 0 == unlimited on each setter.
	a.conns.SetCap(orgID, maxConns)
	a.tcpRate.SetRatePerMin(orgID, tcpRPM)
	a.httpRate.SetRatePerMin(orgID, httpRPM)
	a.tcpDaily.SetLimit(orgID, dailyTCP)
	a.httpDaily.SetLimit(orgID, dailyHTTP)
	sess.SetConnGuard(&session.ConnGuard{
		OrgID:     orgID,
		Conns:     a.conns,
		HTTPRate:  a.httpRate,
		TCPRate:   a.tcpRate,
		TCPDaily:  a.tcpDaily,
		HTTPDaily: a.httpDaily,
	})
	if maxConns > 0 || tcpRPM > 0 || httpRPM > 0 || dailyTCP > 0 || dailyHTTP > 0 {
		a.logger.Debug("conn guard installed",
			"org", orgID, "max_conns", maxConns,
			"tcp_rate_per_min", tcpRPM, "http_rate_per_min", httpRPM,
			"daily_tcp_conns", dailyTCP, "daily_http_reqs", dailyHTTP)
	}
}

// envInt64 reads a non-negative int64 from env var `key`. Unset / 0 /
// invalid returns 0 (treated as "unlimited" by the global limiter). A
// non-numeric value is logged and ignored. Used for the Phase B global
// backpressure ceilings (EDGE_GLOBAL_MAX_CONNS / _ACCEPT_RATE_PER_SEC).
func envInt64(logger *slog.Logger, key string) int64 {
	v := os.Getenv(key)
	if v == "" {
		return 0
	}
	n, err := strconvAtoi64(v)
	if err != nil || n < 0 {
		logger.Warn("ignoring invalid env value", "key", key, "value", v)
		return 0
	}
	return n
}

// strconvAtoi64 is a tiny shim so we don't drag strconv into the main
// imports for one call site.
func strconvAtoi64(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-numeric tenant id")
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}

// portFromAddr extracts the numeric port from a listen address like ":8080" or
// "0.0.0.0:8443"; returns 0 if empty or unparseable. Used to advertise the
// edge's public HTTP/HTTPS ports in AUTH_RESP.
func portFromAddr(addr string) uint32 {
	if addr == "" {
		return 0
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 0 || p > 65535 {
		return 0
	}
	return uint32(p)
}
