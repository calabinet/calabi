package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/identity"
	platformquota "github.com/calabi/calabi/apps/calabi-coord/internal/platform/quota"
	platformstore "github.com/calabi/calabi/apps/calabi-coord/internal/platform/store"
	"github.com/calabi/calabi/pkg/svcboot"
)

// wire builds the coordinator for the PLATFORM (SaaS) edition.
//
// Auth is REAL when CALABI_COORD_IDENTITY_ADDR is set: a node presents a tk_ auth
// key, identity-svc verifies it, and the owning org becomes the node's meshnet
// (internal/platform/identity). Unset falls back to the dev StaticAuth so a
// local run works without the control plane.
//
// Stores are still in-memory — the DB-backed NodeStore + node persistence
// (mesh_nodes table vs Device-table extension, an open design point) land in
// MESH.8 behind the SAME core interfaces.
func wire(logger *slog.Logger) (*core.Coordinator, core.Authenticator, error) {
	nodes, acl, aclRevs, services, settings, relays, err := platformStores(logger)
	if err != nil {
		return nil, nil, err
	}
	ipam := core.NewMemIPAM()
	// Persisted nodes reload from the DB, but the in-memory IPAM starts fresh —
	// warm it past the overlays already in use so a NEW node can't be handed a
	// live node's address after a restart (MESH.8c).
	if ov, ok := nodes.(interface {
		AllOverlays(context.Context) ([]netip.Addr, error)
	}); ok {
		used, err := ov.AllOverlays(context.Background())
		if err != nil {
			return nil, nil, fmt.Errorf("warm ipam: %w", err)
		}
		ipam.Warm(used)
		if len(used) > 0 {
			logger.Info("ipam warmed from persisted nodes", "count", len(used))
		}
	}
	derpMap, derpHome, err := loadDERPMap(logger)
	if err != nil {
		return nil, nil, err
	}
	// Platform DERP regions come LIVE from the edge directory when identity-svc is
	// configured (edge/derp merge): every merged relay self-appears, so there is no
	// static map file to maintain. loadDERPMap's result is the FALLBACK — used
	// until edges report a relay, or if identity-svc is unreachable, so the fleet
	// is never left with an empty map. Purely static when identity is unset (dev).
	derp := core.CompositeDERP{Platform: derpMap, Relays: relays}
	if addr := env("IDENTITY_ADDR"); addr != "" {
		lister, derr := dialEdgeLister(addr)
		if derr != nil {
			logger.Error("coord: cannot dial identity-svc for the edge-derived DERP map; using the static map only", "addr", addr, "err", derr)
		} else {
			src := newPlatformDERPFromEdges(lister, derpMap, logger)
			derp = core.CompositeDERP{PlatformFn: src.Current, Relays: relays}
			edgeDERPWatcher = src.run // main starts it once the notifier exists
			// The operator's stated home region appears once its edge reports a
			// relay, even if the static fallback never named it — trust it.
			if h := env("DERP_HOME_REGION"); h != "" {
				derpHome = h
			}
			logger.Info("coord: platform DERP map derived from the edge directory (edge/derp merge)", "identity", addr, "fallback_regions", len(derpMap.Regions))
		}
	}
	coord := &core.Coordinator{
		Nodes: nodes,
		// Per-org ACL (MESH.8e-2): the meshnet's stored doc governs its netmap;
		// a meshnet with no doc falls back to the global default (allow-all, or
		// CALABI_COORD_POLICY_FILE if set — preserving the MESH.5 file behavior).
		Policy:       core.ACLFilter{Store: acl, Fallback: policyStore(logger)},
		ACL:          acl,
		ACLRevisions: aclRevs,
		Services:     services,
		Settings:     settings,
		IPAM:         ipam,
		// Platform regions PLUS this org's own relays (R2). Platform entries are
		// never dropped: DefaultDERPHome names one, and a self-hosted region must
		// never be a new node's default home. Platform regions are edge-derived
		// (dynamic) or static — see `derp` above.
		DERP:            derp,
		Relays:          relays,
		DefaultDERPHome: derpHome,
		Quota:           nodeQuota(logger),
		Presence:        core.NewPresence(),
		ServiceHealth:   core.NewServiceHealthTracker(),
		RelayGrants:     relayGrantIssuer(logger, newRelayScopeSource(logger)),
		RelayUsageSink:  newHookRelayUsageSink(logger),
		Logger:          logger,
	}

	if addr := env("IDENTITY_ADDR"); addr != "" {
		auth, err := identity.Dial(logger, addr)
		if err != nil {
			return nil, nil, fmt.Errorf("identity dial: %w", err)
		}
		logger.Info("calabi-coord auth via identity-svc (tk_ key -> org=meshnet)", "addr", addr)
		return coord, auth, nil
	}

	logger.Warn("CALABI_COORD_IDENTITY_ADDR unset; using dev StaticAuth (NOT for production) — set it to verify tk_ keys via identity-svc")
	return coord, devStaticAuth(), nil
}

// platformStores picks the platform mesh stores: the durable ent/DB store (a
// single *platformstore.Store backing BOTH the node registry and the per-org
// ACL doc, over one connection) when a DSN is configured (CALABI_COORD_DB_DSN or
// CALABI_DB_DSN), else in-memory stores (dev / local smoke, where state
// reasonably vanishes on restart). The DB store is what makes admin visibility,
// seat billing, and the console ACL editor meaningful across restarts
// (MESH.8c/8e). A configured-but-broken DSN aborts startup rather than silently
// losing persistence.
func platformStores(logger *slog.Logger) (core.NodeStore, core.ACLStore, core.ACLRevisionStore, core.ServiceStore, core.SettingsStore, core.RelayStore, error) {
	dsn := svcboot.DBDsn(envPrefix+"_DB_DSN", legacyEnvPrefix+"_DB_DSN")
	if dsn == "" {
		logger.Warn("no CALABI_COORD_DB_DSN / CALABI_DB_DSN; using in-memory node + ACL stores (state lost on restart)")
		return core.NewMemNodeStore(), core.NewMemACLStore(), core.NewMemACLRevisionStore(), core.NewMemServiceStore(), core.NewMemSettingsStore(), core.NewMemRelayStore(), nil
	}
	st, err := platformstore.Open(dsn)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("open mesh store: %w", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("migrate mesh store: %w", err)
	}
	logger.Info("mesh store: ent/DB (durable node registry + per-org ACL + ACL history + services + self-hosted relays)")
	return st, st, st, st, st, st, nil
}

// nodeQuota picks the platform node cap: the per-plan quota-svc cap when
// CALABI_COORD_QUOTA_ADDR is set (kind "mesh_node"), else the static CALABI_COORD_NODE_QUOTA
// fallback (unlimited if that's unset too). A failed quota-svc dial falls back
// to static rather than aborting startup — the mesh still runs, just uncapped
// by plan until the address is fixed.
func nodeQuota(logger *slog.Logger) core.NodeQuota {
	addr := envAlias("QUOTA_ADDR", "QUOTA_SVC_ADDR")
	if addr == "" {
		return staticNodeQuota(logger)
	}
	q, err := platformquota.Dial(logger, addr)
	if err != nil {
		logger.Error("quota-svc dial failed; falling back to static node quota", "addr", addr, "err", err)
		return staticNodeQuota(logger)
	}
	logger.Info("mesh node quota via quota-svc (per-plan max_mesh_nodes)", "addr", addr)
	return q
}
