package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/identity"
	platformquota "github.com/calabi/calabi/apps/calabi-coord/internal/platform/quota"
	platformstore "github.com/calabi/calabi/apps/calabi-coord/internal/platform/store"
	"github.com/calabi/calabi/pkg/svcboot"
)

// wire builds the coordinator for the PLATFORM (SaaS) deployment.
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
	nodes, acl, aclRevs, services, settings, relays, connRecs, err := platformStores(logger)
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
	// Subnet aliases (overlapping-LAN case) draw from the OTHER half of the
	// overlay, and carry the same restart hazard as node addresses: re-handing a
	// live alias would point a consumer's existing route at a different site's
	// LAN. Warm it the same way.
	aliasIPAM := core.NewMemAliasIPAM()
	if av, ok := nodes.(interface {
		AllRouteAliases(context.Context) ([]netip.Prefix, error)
	}); ok {
		used, err := av.AllRouteAliases(context.Background())
		if err != nil {
			return nil, nil, fmt.Errorf("warm alias ipam: %w", err)
		}
		aliasIPAM.Warm(used)
		// Log the LEVEL, not just the count. The pool is a /11 shared by every
		// meshnet on the platform and nothing else reports on it: a leak here
		// shows up as "some org's routes stopped getting aliases", months later
		// and three layers from the cause. One line per start is the cheapest
		// thing that would have caught it.
		free := aliasIPAM.FreeAddrs()
		total := uint64(1) << uint(32-11) // overlayAliasPool is a /11
		logger.Info("subnet-alias ipam warmed from persisted nodes",
			"aliases_held", len(used),
			"pool_free_addrs", free, "pool_total_addrs", total,
			"pool_used_pct", float64(total-free)*100/float64(total),
			"free_24_blocks", free/256)
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
		AliasIPAM: aliasIPAM,
		Nodes:     nodes,
		// Per-org ACL (MESH.8e-2): the meshnet's stored doc governs its netmap;
		// a meshnet with no doc falls back to the global default (allow-all, or
		// CALABI_COORD_POLICY_FILE if set — preserving the MESH.5 file behavior).
		Policy:       core.ACLFilter{Store: acl, Fallback: policyStore(logger)},
		ACL:          acl,
		ACLRevisions: aclRevs,
		Services:     services,
		Settings:     settings,
		ConnRecords:  connRecs,
		// Same store; nil on the in-memory path, where every operator setting
		// falls back to its default.
		PlatformSettings:               platformSettings(connRecs),
		ConnRecordRetentionDefaultDays: connRecordRetentionDefault(logger),
		IPAM:                           ipam,
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
		// Without identity-svc there is no console to approve a route in (the
		// self-hosted build on static keys, or a local dev run), so routes keep
		// taking effect by themselves, as documented for self-hosting. On the
		// platform each org decides (MeshnetSettings.AutoApproveRoutes).
		AutoApproveAllRoutes: env("IDENTITY_ADDR") == "",
		Logger:               logger,
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
	auth, err := devStaticAuth()
	if err != nil {
		return nil, nil, err
	}
	return coord, auth, nil
}

// platformStores picks the platform mesh stores: the durable ent/DB store (a
// single *platformstore.Store backing BOTH the node registry and the per-org
// ACL doc, over one connection) when a DSN is configured (CALABI_COORD_DB_DSN or
// CALABI_DB_DSN), else in-memory stores (dev / local smoke, where state
// reasonably vanishes on restart). The DB store is what makes admin visibility,
// seat billing, and the console ACL editor meaningful across restarts
// (MESH.8c/8e). A configured-but-broken DSN aborts startup rather than silently
// losing persistence.
func platformStores(logger *slog.Logger) (core.NodeStore, core.ACLStore, core.ACLRevisionStore, core.ServiceStore, core.SettingsStore, core.RelayStore, core.ConnRecordStore, error) {
	dsn := svcboot.DBDsn(envPrefix+"_DB_DSN", legacyEnvPrefix+"_DB_DSN")
	if dsn == "" {
		logger.Warn("no CALABI_COORD_DB_DSN / CALABI_DB_DSN; using in-memory node + ACL stores (state lost on restart)")
		// No connection-record store on this path, deliberately. An audit trail
		// that disappears on restart is worse than none: it reads as "nothing
		// happened" for the window it lost.
		return core.NewMemNodeStore(), core.NewMemACLStore(), core.NewMemACLRevisionStore(), core.NewMemServiceStore(), core.NewMemSettingsStore(), core.NewMemRelayStore(), nil, nil
	}
	st, err := platformstore.Open(dsn)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("open mesh store: %w", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("migrate mesh store: %w", err)
	}
	logger.Info("mesh store: ent/DB (durable node registry + per-org ACL + ACL history + services + self-hosted relays)")
	// The data-plane audit trail is on by default and switchable off, because it
	// is the kind of record an operator may be required NOT to keep. Off means
	// reports are accepted and dropped, so no daemon changes behaviour either way.
	var conn core.ConnRecordStore = st
	if strings.EqualFold(strings.TrimSpace(env("CONN_RECORDS")), "off") {
		logger.Info("mesh: connection records disabled by CALABI_COORD_CONN_RECORDS=off; reports will be accepted and discarded")
		conn = nil
	}
	return st, st, st, st, st, st, conn, nil
}

// platformSettings exposes the ent store as the operator-settings store when
// there is one. A type assertion rather than a second return value from
// platformStores: it is the same object, and threading it separately would give
// two names for one thing that could then be wired inconsistently.
func platformSettings(c core.ConnRecordStore) core.PlatformSettingStore {
	ps, _ := c.(core.PlatformSettingStore)
	return ps
}

// connRecordRetentionDefault is the retention used until an operator sets one in
// the admin console. The env var is the DEFAULT, not the value: a stored setting
// wins, so changing the console does not require a redeploy and an operator who
// set the env before the console existed is not surprised by it being ignored.
//
// Retention is not optional — a trail nobody trims becomes a liability of its
// own — so an unset or unparseable value falls back to 90 days rather than to
// "forever". The failure mode of a retention setting has to be keeping LESS than
// intended, never more.
func connRecordRetentionDefault(logger *slog.Logger) int {
	const def = 90
	raw := strings.TrimSpace(env("CONN_RECORD_RETENTION_DAYS"))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		logger.Warn("mesh: CALABI_COORD_CONN_RECORD_RETENTION_DAYS is not a positive number of days; using the default",
			"value", raw, "default_days", def)
		return def
	}
	clamped, changed := core.ClampConnRecordRetentionDays(n)
	if changed {
		logger.Warn("mesh: CALABI_COORD_CONN_RECORD_RETENTION_DAYS is outside the allowed range; clamped",
			"value", n, "used", clamped, "max", core.MaxConnRecordRetentionDays)
	}
	return clamped
}

// runConnRecordPurge trims the trail once at startup and daily after. Daily
// rather than hourly because the rows are hourly buckets: a sweep that runs more
// often than the data changes is load without an effect.
func runConnRecordPurge(ctx context.Context, logger *slog.Logger, coord *core.Coordinator) {
	if coord.ConnRecords == nil {
		return
	}
	purge := func() {
		// Re-read the setting on EVERY sweep rather than caching it at startup:
		// an operator who shortens retention in the console expects the next
		// sweep to honour it, not the next restart.
		days := coord.ConnRecordRetentionDays(ctx)
		n, err := coord.ConnRecords.PurgeConnRecordsBefore(ctx, time.Now().AddDate(0, 0, -days))
		if err != nil {
			logger.Warn("mesh: purging old connection records failed", "err", err)
			return
		}
		if n > 0 {
			logger.Info("mesh: purged connection records past retention", "rows", n, "keep_days", days)
		}
	}
	purge()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			purge()
		}
	}
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
