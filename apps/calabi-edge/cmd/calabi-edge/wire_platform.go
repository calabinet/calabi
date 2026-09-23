package main

// wire_platform.go is the control-plane seam. It ships in every build,
// including the open-source one — there is no build tag and no stub twin any
// more (F1 merged them). It dials identity / tunnel / quota / cert / config /
// usage — directly in cluster mode or through a single bff-edge mTLS gRPC
// connection in multi-region mode — and returns the platformDeps bundle that
// run() threads into the data-plane core. What makes an edge self-hosted is
// that none of those addresses are configured, so this seam wires nothing;
// it is a runtime condition, not a compile-time one.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"

	bffedge "github.com/calabinet/calabi/pkg/edge-proto/edgepb"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/accesslog"
	eventbus "github.com/calabinet/calabi/apps/calabi-edge/internal/bus"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/meshresolver"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/access"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/acmechallenge"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/bffedgeclient"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/certclient"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/configclient"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/identity"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/quotaclient"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/tunnelstore"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/usage"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/ratelimit"
)

// wirePlatform stands up the full control plane and returns the bundle of
// interface-typed deps + background runners + closers the core run() consumes.
// On any fatal wiring error it closes whatever it already opened (mirroring the
// pre-split defer stack) and returns the error.
func wirePlatform(ctx context.Context, logger *slog.Logger, in platformInputs) (*platformDeps, error) {
	cfg := in.cfg
	deps := &platformDeps{}
	var closers []io.Closer
	fail := func(err error) (*platformDeps, error) {
		closeAll(closers)
		return nil, err
	}

	// multi-region mode. When MultiRegion.Mode = "bff-edge" we open ONE
	// shared mTLS gRPC connection to bff-edge and route every control-plane call
	// (identity / tunnel / cert / quota / config) + every NATS subject through
	// it. Cluster mode (default) keeps behaviour — direct gRPC
	// to each svc ClusterIP, NATS to the in-cluster broker.
	var cpBFF *bffedgeclient.Conn
	if cfg.MultiRegion.IsBFFEdge() {
		bc, err := bffedgeclient.Dial(bffedgeclient.Config{
			Addr:           cfg.MultiRegion.BFFEdgeAddr,
			ClientCertPath: cfg.MultiRegion.ClientCert,
			ClientKeyPath:  cfg.MultiRegion.ClientKey,
			CAPath:         cfg.MultiRegion.CA,
			ServerName:     cfg.MultiRegion.ServerName,
		})
		if err != nil {
			return fail(fmt.Errorf("bff-edge dial: %w", err))
		}
		closers = append(closers, bc)
		cpBFF = bc
		logger.Info("bff-edge wired (multi-region mode)", "addr", cfg.MultiRegion.BFFEdgeAddr)
	}

	// Since F3 step 2b bff-edge is the ONLY way to a control plane, so this is
	// simply whether we dialed it. The old expression also counted the
	// direct-dial addresses, which no longer reach anything.
	deps.controlPlaneWired = cpBFF != nil

	// Token verification through bff-edge. With deps.verifier nil the node is a
	// self-hosted coordinator's, and main accepts devices by that coordinator's
	// grants instead (there is no static token table any more).
	var identityCli *identity.Verifier
	if cpBFF != nil {
		v := identity.Wrap(logger, cpBFF.Client)
		deps.verifier = v
		identityCli = v
		logger.Info("identity wired via bff-edge")
	}

	// Shared tunnel_id -> proxy_id map. The persister populates this on
	// NEW_PROXY success; the configclient.Applier looks it up so a DeleteTunnel
	// from another calabi-edge (or a CLI delete) can find + unregister the proxy.
	localIndex := &tunnelIDIndex{}

	// Optional tunnel-svc writeback. If unconfigured we keep behavior
	// (in-memory router only; no persisted tunnels).
	var tunnelCli *tunnelstore.Client
	tunnelWired := cpBFF != nil
	if tunnelWired {
		tc := tunnelstore.Wrap(logger, cpBFF.Client,
			cfg.EdgeNodeID, cfg.NodeLabel, cfg.Tunnel.BaseDomain)
		logger.Info("tunnel wired via bff-edge", "edge_node_id", tc.EdgeNodeID())
		tunnelCli = tc
		deps.persister = &tunnelPersisterAdapter{
			tc:        tc,
			logger:    logger.With("component", "persister"),
			edgeLabel: cfg.NodeLabel,
			index:     localIndex,
			ports:     in.ports,
		}

		// Two startup seeds, and they are NOT the same case — which is what the
		// single `if` they used to share got wrong.
		//
		// MaxManagedSubdomainSeq is an in-cluster admin RPC that bff-edge does not
		// serve, so a remote edge asking for it just waits out the deadline. It
		// stays skipped, and the file-backed sequence is the right fallback.
		//
		// ListEdgeClaimedPorts IS served by bff-edge, scoped to the caller's own
		// edge id from its certificate. Skipping it cost a real bug: `IsBFFEdge()`
		// is true for every edge that reaches tunnel-svc through the gateway —
		// PLATFORM edges outside the main region included, not just the BYOI nodes
		// the old comment had in mind — so those edges booted with a COLD pool,
		// handed out the first port in the range, and collided with whatever live
		// row still held it. The claim then failed with AlreadyExists and the
		// fallback path DELETED the console-created row: the user's tunnel
		// disappeared and a re-homed older row took its place.
		//
		// A cold pool was never "exactly right for a single-tenant edge" either. A
		// BYOI edge has tunnel rows with remote_port bound just the same, and will
		// re-issue them just the same.
		if cfg.MultiRegion.IsBFFEdge() {
			logger.Info("bff-edge mode: skipping the subdomain-seq DB seed (not served by the gateway); using local state",
				"base", cfg.Tunnel.BaseDomain)
		} else {
			// Seed the SubdomainAllocator above the highest u<N>.<base> seq already
			// in tunnel-svc. Without this, a file-backed seq that's out-of-sync (or
			// a fresh state.dir) can hand out a number whose "uN.<base>" form
			// collides with another row's domain.
			// TODO(multi-org): hardcoded org=1 for dev. Multi-tenant edges need to
			// iterate every org served (or add a dedicated RPC).
			if dbMax, err := tc.MaxManagedSubdomainSeq(context.Background(), cfg.Tunnel.BaseDomain, 1); err != nil {
				logger.Warn("subdomain seq DB-sync failed; staying on file-backed value",
					"base", cfg.Tunnel.BaseDomain, "err", err)
			} else if dbMax > 0 {
				in.domains.SeedIfBehind(dbMax)
				logger.Info("subdomain seq DB-synced", "base", cfg.Tunnel.BaseDomain, "db_max", dbMax)
			}
		}

		// seed the port pool with every port already claimed by a live
		// tunnel row on this edge, so a fresh boot doesn't re-issue numbers still
		// parked at another tunnel. Runs in EVERY mode — see above.
		//
		// Best-effort, but loudly so: an edge whose pool starts cold will delete
		// somebody's tunnel the first time it hands out a port that is still bound,
		// and that has to be findable in the log afterwards rather than inferred.
		if claimed, err := tc.ListEdgeClaimedPorts(context.Background()); err != nil {
			logger.Warn("port pool DB-seed FAILED; the pool starts cold and may re-issue a port "+
				"that a live tunnel still holds — the resulting claim conflict is recoverable "+
				"but logged as a WARN in the persister",
				"edge_node_id", tc.EdgeNodeID(), "err", err)
		} else {
			for _, p := range claimed {
				if p > 0 {
					in.ports.Reserve(uint32(p))
				}
			}
			logger.Info("port pool DB-seeded", "edge_node_id", tc.EdgeNodeID(), "reserved", len(claimed))
		}

		if cpBFF == nil {
			logger.Info("tunnel-svc wired", "edge_node_id", tc.EdgeNodeID())
		}
	} else {
		logger.Info("tunnel-svc not configured; routes are edge-local only")
	}

	// Post-handshake catch-up hook (pushes the client's owned tunnels on AUTH).
	// nil when tunnel-svc isn't wired.
	deps.postHandshake = makePostHandshake(logger, tunnelCli, cfg.Tunnel.BaseDomain)

	// Optional config-svc subscription. hot-apply local deletes;
	// remote deltas logged cross-edge proxying.
	switch {
	case cpBFF != nil:
		applier := &routeApplier{
			edgeNodeID: in.edgeID,
			registrar:  in.registrar,
			manager:    in.mgr,
			index:      localIndex,
			logger:     logger.With("component", "route-applier"),
			secrets:    oauthSecretsOf(tunnelCli),
			baseDomain: cfg.Tunnel.BaseDomain,
			ports:      in.ports,
		}
		cc, err := configclient.StartWithClient(ctx, logger,
			bffedgeclient.NewConfigAdapter(cpBFF.Client),
			configclient.Options{
				EdgeNodeID: in.edgeID,
				Region:     cfg.Region,
				Version:    version,
				Applier:    applier,
			})
		if err != nil {
			return fail(fmt.Errorf("config-svc subscribe via bff-edge: %w", err))
		}
		closers = append(closers, cc)
		logger.Info("config wired via bff-edge")
	default:
		logger.Info("config-svc not configured; running without live config push")
	}

	// Event bus: the bff-edge-backed one, which translates Subscribe into
	// SubscribeXxx streams and Publish into ReportUsage. The direct NATS dial
	// went with the direct control-plane dials in F3 step 2b — an edge outside
	// the cluster could never reach the cluster's NATS anyway, and inside it the
	// gateway is now the single path. nil cpBFF means no control plane at all
	// (standalone), and nothing on this side subscribes.
	var bus eventbus.Bus
	if cpBFF != nil {
		bus = bffedgeclient.NewBus(ctx, logger, cpBFF.Client)
		logger.Info("event bus wired via bff-edge")
		closers = append(closers, bus)
	}

	// Relay usage reporter (edge/derp merge + platform per-org). Two shapes,
	// one for each relay kind — see relayreporter.go:
	//
	//   platform (multi-tenant): bills PER org from each node's R0' grant, under
	//     the platform region code (counted toward the cap). Attribution needs
	//     grants, so require_auth MUST be on; otherwise every delta has meshnet 0
	//     and is dropped. bff-edge (or cluster NATS) accepts the per-org report as
	//     is — a platform edge is trusted to report any org's usage, exactly like
	//     it already does per tunnel in ReportUsage.
	//
	//   self-hosted (single-tenant BYOI): bills the one org under a "self-<label>"
	//     region (excluded from the cap). The org is NOT taken from config — a BYOI
	//     node needn't know its own org id; bff-edge stamps it from the mTLS cert.
	//     cfg.OrgID (0 for a BYOI edge) is only the cluster-mode fallback.
	//
	// Skipped when no relay label is set (nothing to attribute to), and when
	// there is no control plane to report to. The second one was missing until
	// 1.13: a standalone relay with a label — docs/self-hosting.md starts one
	// with CALABI_EDGE_RELAY_LABEL=home — got a reporter with a nil bus, and the
	// first minute that carried any traffic crashed the process.
	switch {
	case cfg.ServesMesh() && cfg.Mesh.Label != "" && bus == nil:
		logger.Info("relay usage is not reported: no control plane to report it to", "label", cfg.Mesh.Label)
	case cfg.ServesMesh() && cfg.Mesh.Label != "":
		if cfg.Mesh.IsPlatformKind() {
			region := cfg.Mesh.Label
			deps.relayReporter = newPlatformRelayUsageReporter(bus, region, logger)
			if !cfg.Mesh.RequireAuth {
				logger.Warn("platform relay usage will NOT be attributed: relay.require_auth is off, so nodes present no grant and the relay cannot tell whose bytes it forwards",
					"region", region)
			}
			logger.Info("relay usage reporter wired (platform, per-org)", "region", region)
		} else {
			region := "self-" + cfg.Mesh.Label
			deps.relayReporter = newRelayUsageReporter(bus, cfg.OrgID, region, logger)
			logger.Info("relay usage reporter wired (self-hosted)", "region", region, "cluster_fallback_org", cfg.OrgID)
		}
	}

	// Optional quota-svc client. Without it bandwidth limits are
	// off. wraps the raw client in CachedClient: 30s per-org TTL + usage
	// deny/allow subscription for instant invalidation.
	var quotaCached *quotaclient.CachedClient
	switch {
	case cpBFF != nil:
		quotaCli := quotaclient.Wrap(logger, bffedgeclient.NewQuotaAdapter(cpBFF.Client))
		quotaCached = quotaCli.WithCache(logger, bus, 0)
		closers = append(closers, quotaCached)
		logger.Info("quota wired via bff-edge", "cache_ttl", quotaclient.DefaultCacheTTL)
	}

	// Bandwidth resolver: nil quotaCached yields "unlimited" (still honours the
	// EDGE_DEBUG_BANDWIDTH_BPS dev override).
	deps.bandwidthResolver = &quotaBandwidthAdapter{cli: quotaCached, logger: logger}

	// Mesh-relay rate limiting. Wired only for a
	// PLATFORM-kind relay with a quota client: a self-hosted relay carries its
	// owner's traffic on their own VPS, which the platform neither may nor can
	// meter. Note this sits AFTER quotaCached exists — wiring it up with the
	// relay reporter above would have read a nil that is declared later.
	if cfg.ServesMesh() && cfg.Mesh.IsPlatformKind() {
		switch {
		case quotaCached == nil:
			logger.Info("relay rate limiting NOT wired: no quota client; the relay forwards unlimited")
		default:
			deps.relayRate = newRelayRateResolver(quotaCached, logger)
			logger.Info("relay rate limiting wired (per-device + per-org)", "label", cfg.Mesh.Label)
		}
	}

	// Online-cap admit (2026-05-28). Needs both identity-svc + quota-svc; the
	// adapter itself returns Allowed=true when either dep is nil.
	if identityCli != nil && quotaCached != nil {
		deps.onlineCap = &onlineCapAdapter{
			identityCli: identityCli,
			quotaCli:    quotaCached,
			logger:      logger.With("component", "online-cap"),
		}
		logger.Info("online-cap admit wired")
	}

	// Anti-abuse connection limiters (Phase A, 2026-06-11). Process-global,
	// keyed by org_id; per-org caps fed from quota-svc at handshake. Only wired
	// when quota-svc is available (there's no per-org cap source otherwise).
	if quotaCached != nil {
		deps.connGuard = &connGuardAdapter{
			conns:     ratelimit.NewConnLimiter(0),
			httpRate:  ratelimit.NewRateLimiter(0),
			tcpRate:   ratelimit.NewRateLimiter(0),
			tcpDaily:  ratelimit.NewDailyCounter(0),
			httpDaily: ratelimit.NewDailyCounter(0),
			quota:     quotaCached,
			logger:    logger.With("component", "conn-guard"),
		}
		logger.Info("connection anti-abuse limiter wired")
	}

	// intra-region edge mesh resolver. Enabled when mesh config is set AND
	// both control-plane deps are wired; nil otherwise (502-on-miss).
	var meshResolverImpl *meshresolver.Resolver
	if cfg.PeerForwardEnabled() {
		if tunnelCli != nil && identityCli != nil {
			meshResolverImpl = meshresolver.New(meshresolver.Config{
				SelfEdgeID: in.edgeID,
				Region:     cfg.Region,
				BaseDomain: cfg.Tunnel.BaseDomain,
				Owners:     meshOwnerSource{tc: tunnelCli},
				Dir:        meshEdgeDirectory{v: identityCli},
				Logger:     logger,
			})
			deps.meshResolver = meshResolverImpl
			logger.Info("mesh resolver enabled",
				"self_edge", in.edgeID, "region", cfg.Region, "base_domain", cfg.Tunnel.BaseDomain)
		} else {
			logger.Warn("mesh enabled in config but tunnel-svc / identity-svc not wired; peer forwarding disabled",
				"tunnel_wired", tunnelCli != nil, "identity_wired", identityCli != nil)
		}
	}

	// HTTPS cert source (cert-svc). nil leaves run() on its self-signed wildcard
	// dev/standalone fallback.
	var certCli *certclient.Client
	switch {
	case cpBFF != nil:
		// RefreshInterval left at zero: certclient.DefaultRefreshInterval. It was
		// a config knob until 1.15.0 and no deployed file ever set it.
		cc, cErr := certclient.StartWithClient(ctx, logger, cpBFF.Client, certclient.Options{
			OrgID: cfg.OrgID,
			Bus:   bus,
		})
		if cErr != nil {
			return fail(fmt.Errorf("cert via bff-edge: %w", cErr))
		}
		closers = append(closers, cc)
		certCli = cc
		logger.Info("cert wired via bff-edge")
	}
	if certCli != nil {
		deps.getCertificate = certCli.GetCertificate
	}

	// ACME http-01 challenge serving: subscribe to the tokens cert-svc
	// broadcasts during user self-service custom-domain issuance, so this
	// edge can answer the Let's Encrypt probe. Reuses the bus dialed above;
	// nil bus (no NATS) simply skips it. Non-fatal on subscribe error — the
	// edge still serves traffic, only http-01 issuance for domains it fronts
	// would fail.
	if bus != nil {
		if cs, csErr := acmechallenge.Start(logger, bus); csErr != nil {
			logger.Warn("acme http-01 challenge subscribe failed; self-service cert issuance via this edge disabled",
				"err", csErr)
		} else {
			closers = append(closers, cs)
			deps.acmeChallengeResolver = cs.Resolve
		}
	}

	// Tunnel access log (who connected to which tunnel, and what we did with
	// them). Installed ONLY when there is a bus to publish on: without one the
	// recorder would accumulate to its cap and hold rows nobody ever reads, and
	// a community/standalone edge has no store to send them to anyway. No sink
	// installed = the listeners' Note() is an atomic load that finds nothing.
	var accessReporter *access.Reporter
	if bus != nil {
		rec := access.New()
		accesslog.SetSink(rec)
		accessReporter = access.NewReporter(logger, bus, rec, in.edgeID, cfg.NodeLabel, 0)
	}

	// Usage reporter + deny hook. Reuses the bus dialed above.
	usageReporter := usage.NewReporter(logger, bus, in.mgr, in.edgeID, cfg.NodeLabel, usageReportInterval(logger))
	denyHook := usage.NewDenyHook(logger, bus)
	if err := denyHook.Start(); err != nil {
		return fail(fmt.Errorf("usage deny start: %w", err))
	}
	closers = append(closers, denyHook)

	// keep the edge directory entry fresh so daemons doing ListEdges
	// always see this node. Public addr falls back to Control.Addr in dev.
	// One host, one port, composed here: public.host plus the port the control
	// listener binds. A tunnel-serving node cannot reach this with an empty host
	// (ValidatePublicHost refuses it), so an empty one is a relay whose file
	// names no host — found through the coordinator's DERP map instead.
	publicAddr := cfg.AdvertisedAddr()
	if publicAddr == "" {
		logger.Warn("public.host not set: this node advertises no address of its own")
	} else {
		logger.Info("advertising this node", "addr", publicAddr)
	}

	// Background runners. Each self-disables when its dep is nil (presence /
	// registrar no-op without identity-svc; evict idles on a noop bus), so this
	// list is identical to the pre-split goroutine block.
	// A PLATFORM merged node advertises its in-process relay endpoint through the
	// edge directory, so the coordinator lists it in the platform DERP map (no
	// static map file). A self-hosted (BYOI) relay leaves these 0 — it registers
	// per-org via bff-edge (runRelayRegistrar below) instead, and must not appear
	// as a platform relay. Relay host = host(publicAddr).
	var platformRelayDerp, platformRelayStun int32
	if cfg.ServesMesh() && cfg.Mesh.IsPlatformKind() {
		platformRelayDerp = int32(cfg.Mesh.RelayDERPPort())
		platformRelayStun = int32(cfg.Mesh.RelaySTUNPort())
	}

	deps.runners = []namedRunner{
		{"usage-reporter", usageReporter.Run},
		{"access-reporter", func(ctx context.Context) error {
			if accessReporter == nil {
				// namedRunner contract: block until ctx, never return early —
				// a bare `return nil` kills the whole edge about a second
				// after boot, with exit 0 and no log line.
				<-ctx.Done()
				return nil
			}
			return accessReporter.Run(ctx)
		}},
		{"deny-sweeper", func(ctx context.Context) error { return runDenySweeper(ctx, logger, in.mgr, denyHook) }},
		{"presence-reporter", func(ctx context.Context) error {
			return runPresenceReporter(ctx, logger, identityCli, in.mgr, in.edgeID, cfg.NodeLabel, defaultPresenceInterval, in.presenceKick)
		}},
		{"edge-registrar", func(ctx context.Context) error {
			// A node that doesn't run the TUNNEL datapath must not appear in the
			// edge directory as a self-hosted edge: daemons pick their control
			// target from that list and would dial a :7443 nobody is listening
			// on. Its RELAY half registers separately, via bff-edge, and doesn't
			// need this row at all.
			//
			// A PLATFORM relay is the exception and still registers: coord builds
			// the platform DERP map FROM the edge directory (relay_derp_port on
			// the row), so skipping it there would take the relay out of the map.
			if !cfg.ServesTunnels() && !cfg.Mesh.IsPlatformKind() {
				logger.Info("relay-only self-hosted node: not registering in the edge directory (no tunnel listener to dial)")
				<-ctx.Done()
				return nil
			}
			// A platform relay that got this far with nothing to advertise has
			// no public.addr and no control listener to borrow one from. The row
			// exists so coord can put this relay in the DERP map, keyed on the
			// host in this very field — registering an empty one would list a
			// relay at nowhere. Say so and stay out of the map.
			if publicAddr == "" {
				logger.Error("not registering in the edge directory: nothing to advertise — set public.host to the address devices reach this relay at",
					"relay_derp_port", platformRelayDerp)
				<-ctx.Done()
				return nil
			}
			return runEdgeRegistrar(ctx, logger, identityCli, in.mgr, identity.EdgeRegistration{
				EdgeNodeID: in.edgeID,
				NodeLabel:  cfg.NodeLabel,
				Region:     cfg.Region,
				PublicAddr: publicAddr,
				// The suffix a tunnel created on this node gets. Console reads it
				// back from the directory to show "<prefix>.<this>" before the
				// tunnel exists.
				BaseDomain:    cfg.Tunnel.BaseDomain,
				InternalAddr:  cfg.Tunnel.PeerForward.AdvertiseAddr,
				RelayDerpPort: platformRelayDerp,
				RelayStunPort: platformRelayStun,
				Version:       version,
			})
		}},
		{"evict-consumer", func(ctx context.Context) error {
			return runEvictConsumer(ctx, logger, bus, in.mgr, in.edgeID)
		}},
	}

	// Edge cert auto-renewer (F1, byoi-seat-and-cert-lifecycle): keep THIS edge's
	// own short-lived mTLS client cert fresh over the bff-edge conn (hot-swap, no
	// restart). Only in bff-edge mode (the only mode that presents a client cert);
	// the runner no-ops for a platform edge (cert carries no org SAN).
	if cpBFF != nil {
		deps.runners = append(deps.runners, namedRunner{"edge-cert-renewer", func(ctx context.Context) error {
			return cpBFF.RunCertRenewal(ctx, logger)
		}})
	}

	if meshResolverImpl != nil {
		deps.runners = append(deps.runners, namedRunner{"mesh-resolver", meshResolverImpl.Run})
	}

	// Relay self-registration (edge/derp merge-B): a merged node self-registers
	// its relay endpoint into the org DERP map on a heartbeat, exactly like the
	// edge registrar above. bff-edge mode only — bff-edge derives the org from the
	// mTLS cert and attributes the relay to it (the node needn't know its own org).
	//
	// SELF-HOSTED only. A platform relay belongs in the PLATFORM DERP map, which is
	// process/config-provisioned (coord's map file), not self-registered per org —
	// and bff-edge's RegisterRelay is BYOI-only, so a platform edge calling it would
	// just collect a PermissionDenied every heartbeat. Gate it out.
	if cpBFF != nil && cfg.ServesMesh() && cfg.Mesh.Label != "" && !cfg.Mesh.IsPlatformKind() {
		relayHost, _, splitErr := net.SplitHostPort(publicAddr)
		if splitErr != nil {
			relayHost = publicAddr // publicAddr may already be a bare host
		}
		if relayHost == "" {
			logger.Warn("relay self-registration skipped: no public host (set public.host)")
		} else {
			client := cpBFF.Client
			req := &bffedge.RegisterRelayRequest{
				Label:    cfg.Mesh.Label,
				Host:     relayHost,
				DerpPort: int32(cfg.Mesh.RelayDERPPort()),
				StunPort: int32(cfg.Mesh.RelaySTUNPort()),
			}
			deps.runners = append(deps.runners, namedRunner{"relay-registrar", func(ctx context.Context) error {
				return runRelayRegistrar(ctx, logger, func(ctx context.Context) error {
					_, err := client.RegisterRelay(ctx, req)
					return err
				})
			}})
			logger.Info("relay self-registration wired",
				"region", "self-"+cfg.Mesh.Label, "host", relayHost, "derp_port", req.DerpPort)
		}
	}

	deps.closers = closers
	return deps, nil
}

// oauthSecretsOf adapts the tunnel-store client to the fetcher the policy
// resolver needs, and turns a nil client into a nil INTERFACE.
//
// Returning the typed nil directly would give a non-nil interface holding a nil
// pointer — the `secrets == nil` guard in resolveOAuthSecret would not fire and
// the edge would call a method on nothing. That guard is what makes a standalone
// edge log "cannot fetch the secret" instead of panicking.
func oauthSecretsOf(c *tunnelstore.Client) oauthSecretFetcher {
	if c == nil {
		return nil
	}
	return c
}
