package core

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func TestRegisterCarriesAdvertisedRoutes(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	route := netip.MustParsePrefix("192.168.1.0/24")

	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "router", NodeKey: key(1), AdvertisedRoutes: []netip.Prefix{route}})
	b, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})

	nm, err := c.NetMapFor(ctx, b.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	if len(nm.Peers) != 1 || nm.Peers[0].Name != "router" {
		t.Fatalf("expected to see router, got %+v", nm.Peers)
	}
	if len(nm.Peers[0].AdvertisedRoutes) != 1 || nm.Peers[0].AdvertisedRoutes[0] != route {
		t.Fatalf("router advertised routes = %v, want [%s]", nm.Peers[0].AdvertisedRoutes, route)
	}
}

// Register stamps the deployment's default DERP home on a new node and surfaces
// it to peers via the netmap (MESH.4 — the console/admin "relay home" column).
func TestRegisterAssignsDefaultDERPHome(t *testing.T) {
	c := newTestCoord()
	c.DefaultDERPHome = "lax"
	ctx := context.Background()

	a, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register a: %v", err)
	}
	if a.DERPHome != "lax" {
		t.Fatalf("new node DERPHome = %q, want lax", a.DERPHome)
	}

	b, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})
	nm, err := c.NetMapFor(ctx, b.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	if len(nm.Peers) != 1 || nm.Peers[0].DERPHome != "lax" {
		t.Fatalf("peer DERPHome = %+v, want lax", nm.Peers)
	}
}

// A node enrolled before a home was configured (DERPHome empty) gets one
// backfilled when it reconnects; a node that already has a home keeps it.
func TestReRegisterBackfillsDERPHomeButKeepsExisting(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()

	a, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if a.DERPHome != "" {
		t.Fatalf("no default: DERPHome = %q, want empty", a.DERPHome)
	}
	c.DefaultDERPHome = "sgp" // deployment now has a home region
	a2, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if a2.DERPHome != "sgp" {
		t.Fatalf("backfill: DERPHome = %q, want sgp", a2.DERPHome)
	}
	c.DefaultDERPHome = "tyo" // an already-homed node is not overwritten
	a3, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if a3.DERPHome != "sgp" {
		t.Fatalf("keep existing: DERPHome = %q, want sgp (unchanged)", a3.DERPHome)
	}
}

func newTestCoord() *Coordinator {
	return &Coordinator{
		Nodes:  NewMemNodeStore(),
		Policy: AllowAllPolicy{},
		IPAM:   NewMemIPAM(),
		DERP:   StaticDERP{Map: DERPMap{Regions: []DERPRegion{{Code: "lax"}}}},
	}
}

func TestRegisterEnforcesNodeQuota(t *testing.T) {
	c := newTestCoord()
	c.Quota = StaticNodeQuota{Limit: 2}
	ctx := context.Background()

	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)}); err != nil {
		t.Fatalf("register a (1/2): %v", err)
	}
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)}); err != nil {
		t.Fatalf("register b (2/2): %v", err)
	}
	// Third distinct node exceeds the cap.
	_, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "c", NodeKey: key(3)})
	if !errors.Is(err, ErrNodeQuotaExceeded) {
		t.Fatalf("register c: err = %v, want ErrNodeQuotaExceeded", err)
	}
	// Re-enrolling an EXISTING node while at the cap must still succeed (it reuses
	// a slot, not a new one) — a daemon's reconnect can't be locked out by quota.
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a-again", NodeKey: key(1)}); err != nil {
		t.Fatalf("re-register a at cap: %v", err)
	}
	// A DIFFERENT meshnet has its own budget.
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 2, Name: "x", NodeKey: key(9)}); err != nil {
		t.Fatalf("register x in meshnet 2: %v", err)
	}
}

func TestDisabledNodeDropsFromNetmapAndCannotRejoin(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	a, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	b, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "c", NodeKey: key(3)})

	// Before disable: a sees both b and c.
	nm, _ := c.NetMapFor(ctx, a.ID)
	if len(nm.Peers) != 2 {
		t.Fatalf("pre-disable a sees %d peers, want 2", len(nm.Peers))
	}

	// Admin disables b.
	if err := c.Nodes.SetDisabled(ctx, b.ID, true); err != nil {
		t.Fatalf("disable b: %v", err)
	}

	// a's map now excludes b (only c remains).
	nm, _ = c.NetMapFor(ctx, a.ID)
	if len(nm.Peers) != 1 || nm.Peers[0].Name != "c" {
		t.Fatalf("post-disable a sees %+v, want just c", nm.Peers)
	}
	// b's own map is refused.
	if _, err := c.NetMapFor(ctx, b.ID); !errors.Is(err, ErrNodeDisabled) {
		t.Fatalf("NetMapFor(disabled b) = %v, want ErrNodeDisabled", err)
	}
	// b cannot re-enroll.
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)}); !errors.Is(err, ErrNodeDisabled) {
		t.Fatalf("re-register disabled b = %v, want ErrNodeDisabled", err)
	}

	// Re-enable restores everything.
	if err := c.Nodes.SetDisabled(ctx, b.ID, false); err != nil {
		t.Fatalf("re-enable b: %v", err)
	}
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)}); err != nil {
		t.Fatalf("re-register re-enabled b: %v", err)
	}
	nm, _ = c.NetMapFor(ctx, a.ID)
	if len(nm.Peers) != 2 {
		t.Fatalf("post-reenable a sees %d peers, want 2", len(nm.Peers))
	}
}

func TestDisabledNodeFreesSeat(t *testing.T) {
	c := newTestCoord()
	c.Quota = StaticNodeQuota{Limit: 2}
	ctx := context.Background()

	a, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})

	// 2 seats used, at the cap → a third is refused.
	if u, _ := c.SeatUsage(ctx, 1); u.Active != 2 || u.Disabled != 0 || u.Limit != 2 || u.Total != 2 {
		t.Fatalf("usage before disable = %+v, want used2/disabled0/limit2/total2", u)
	}
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "c", NodeKey: key(3)}); !errors.Is(err, ErrNodeQuotaExceeded) {
		t.Fatalf("c at cap = %v, want ErrNodeQuotaExceeded", err)
	}

	// Disabling a parks it: 1 active seat, so c now fits.
	if err := c.Nodes.SetDisabled(ctx, a.ID, true); err != nil {
		t.Fatalf("disable a: %v", err)
	}
	if u, _ := c.SeatUsage(ctx, 1); u.Active != 1 || u.Disabled != 1 || u.Total != 2 {
		t.Fatalf("usage after disable = %+v, want used1/disabled1/total2", u)
	}
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "c", NodeKey: key(3)}); err != nil {
		t.Fatalf("c after a disabled (a seat freed): %v", err)
	}
	if u, _ := c.SeatUsage(ctx, 1); u.Active != 2 || u.Disabled != 1 || u.Total != 3 {
		t.Fatalf("usage after c joins = %+v, want used2/disabled1/total3", u)
	}
}

func TestRegisterUnlimitedWhenNoQuota(t *testing.T) {
	c := newTestCoord() // Quota nil == unlimited
	ctx := context.Background()
	for i := byte(1); i <= 5; i++ {
		if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, NodeKey: key(i)}); err != nil {
			t.Fatalf("register %d with nil quota: %v", i, err)
		}
	}
}

func key(b byte) meshproto.NodeKey {
	var k meshproto.NodeKey
	for i := range k {
		k[i] = b
	}
	return k
}

func TestRegisterAllocatesDistinctOverlay(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()

	a, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register a: %v", err)
	}
	b, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})
	if err != nil {
		t.Fatalf("register b: %v", err)
	}
	if a.Overlay == b.Overlay {
		t.Fatalf("overlay collision: both got %s", a.Overlay)
	}
	if a.Overlay.String() != "100.64.0.1" {
		t.Fatalf("first overlay = %s, want 100.64.0.1", a.Overlay)
	}
}

func TestRegisterIdempotentByKey(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()

	a1, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	// Re-enroll the SAME key (a daemon reconnecting): must reuse id + overlay, not
	// allocate a new address or leave a second node behind.
	a2, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a-renamed", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if a2.ID != a1.ID {
		t.Fatalf("re-register id = %d, want %d (same node)", a2.ID, a1.ID)
	}
	if a2.Overlay != a1.Overlay {
		t.Fatalf("re-register overlay = %s, want %s (stable)", a2.Overlay, a1.Overlay)
	}
	if a2.Name != "a-renamed" {
		t.Fatalf("re-register name = %q, want a-renamed (mutable fields refreshed)", a2.Name)
	}
	nodes, _ := c.Nodes.ListMeshnet(ctx, 1)
	if len(nodes) != 1 {
		t.Fatalf("meshnet has %d nodes after re-register, want 1 (no stale duplicate)", len(nodes))
	}
	// A different key in the same meshnet still gets its own address.
	b, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})
	if err != nil {
		t.Fatalf("register b: %v", err)
	}
	if b.Overlay == a1.Overlay {
		t.Fatalf("distinct key reused overlay %s", b.Overlay)
	}
}

func TestRegisterRejectsZeroKey(t *testing.T) {
	c := newTestCoord()
	if _, err := c.Register(context.Background(), RegisterInput{Meshnet: 1}); err == nil {
		t.Fatal("expected error for zero node_key")
	}
}

func TestNetMapFullMeshMinusSelfAndTenantIsolation(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()

	// Meshnet 1: a, b. Meshnet 2: x.
	a, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 2, Name: "x", NodeKey: key(3)})

	nm, err := c.NetMapFor(ctx, a.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	if nm.Self.ID != a.ID {
		t.Fatalf("self = %d, want %d", nm.Self.ID, a.ID)
	}
	// a should see only b (same meshnet), never x (meshnet 2), never itself.
	if len(nm.Peers) != 1 {
		t.Fatalf("peers = %d, want 1 (only b)", len(nm.Peers))
	}
	if nm.Peers[0].Name != "b" {
		t.Fatalf("peer = %q, want b", nm.Peers[0].Name)
	}
	if len(nm.DERP.Regions) != 1 || nm.DERP.Regions[0].Code != "lax" {
		t.Fatalf("derp map not propagated: %+v", nm.DERP)
	}
}

// SetDERPHome accepts the region a node measured as closest (MESH.4 B2b) and
// distributes it to peers via the netmap, replacing the deployment default.
func TestSetDERPHomeAcceptsMeasuredRegion(t *testing.T) {
	c := newTestCoord()
	c.DERP = StaticDERP{Map: DERPMap{Regions: []DERPRegion{{Code: "lax"}, {Code: "sgp"}}}}
	c.DefaultDERPHome = "lax"
	ctx := context.Background()

	a, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if a.DERPHome != "lax" {
		t.Fatalf("stamped home = %q, want the deployment default lax", a.DERPHome)
	}

	changed, err := c.SetDERPHome(ctx, a.ID, "sgp")
	if err != nil || !changed {
		t.Fatalf("SetDERPHome(sgp) = changed:%v err:%v, want changed", changed, err)
	}
	// Reporting the same home again is a no-op — the node re-reports every minute
	// and must not churn every peer's netmap.
	changed, err = c.SetDERPHome(ctx, a.ID, "sgp")
	if err != nil || changed {
		t.Fatalf("re-reporting the same home = changed:%v err:%v, want no change", changed, err)
	}
	// An empty report means "not measured yet": keep whatever home the node has.
	if changed, err := c.SetDERPHome(ctx, a.ID, ""); err != nil || changed {
		t.Fatalf("empty home = changed:%v err:%v, want no change", changed, err)
	}

	// Peers see the measured home.
	b, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})
	nm, err := c.NetMapFor(ctx, b.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	if len(nm.Peers) != 1 || nm.Peers[0].DERPHome != "sgp" {
		t.Fatalf("peer's derp_home = %+v, want sgp", nm.Peers)
	}
}

// A node may only home at a relay the coordinator actually published: derp_home
// tells every peer where to relay, so an unknown region would point them at a
// relay that doesn't exist.
func TestSetDERPHomeRejectsUnknownRegion(t *testing.T) {
	c := newTestCoord() // map has only "lax"
	c.DefaultDERPHome = "lax"
	ctx := context.Background()
	a, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})

	changed, err := c.SetDERPHome(ctx, a.ID, "atlantis")
	if !errors.Is(err, ErrUnknownDERPRegion) {
		t.Fatalf("SetDERPHome(atlantis) err = %v, want ErrUnknownDERPRegion", err)
	}
	if changed {
		t.Fatal("a rejected region must not change the home")
	}
	got, _ := c.Nodes.Get(ctx, a.ID)
	if got.DERPHome != "lax" {
		t.Fatalf("home after a rejected report = %q, want lax untouched", got.DERPHome)
	}
}

// A rename sticks: the node's next re-registration reports its hostname again,
// and that must NOT overwrite the name an admin chose (a daemon restart would
// otherwise silently undo every rename).
func TestRenameNodeSurvivesReRegistration(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	n, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "daemon", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	renamed, err := c.RenameNode(ctx, n.ID, "  Office-NAS  ")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if renamed.Name != "office-nas" { // normalized: trimmed + lowercased
		t.Fatalf("name = %q, want office-nas", renamed.Name)
	}
	if !renamed.NamePinned {
		t.Fatal("rename must pin the name")
	}

	// The daemon reconnects and re-registers with its hostname.
	again, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "daemon", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if again.Name != "office-nas" {
		t.Fatalf("re-registration overwrote the admin name: %q", again.Name)
	}
	if again.HostName != "daemon" {
		t.Fatalf("host name = %q, want the node's self-reported daemon", again.HostName)
	}
}

// Names are MagicDNS labels peers resolve, so two nodes may not share one, and
// a name that isn't a usable label is refused.
func TestRenameNodeRejectsTakenAndInvalid(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	a, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "alpha", NodeKey: key(1)})
	b, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "beta", NodeKey: key(2)})

	if _, err := c.RenameNode(ctx, b.ID, "ALPHA"); !errors.Is(err, ErrNodeNameTaken) {
		t.Fatalf("rename to a taken name (case-insensitively) err = %v, want ErrNodeNameTaken", err)
	}
	for _, bad := range []string{"", "   ", "-lead", "trail-", "has space", "üñî", strings.Repeat("x", 64)} {
		if _, err := c.RenameNode(ctx, b.ID, bad); !errors.Is(err, ErrInvalidNodeName) {
			t.Errorf("rename to %q err = %v, want ErrInvalidNodeName", bad, err)
		}
	}
	// Renaming to its own current name is a no-op, not a conflict with itself.
	if _, err := c.RenameNode(ctx, a.ID, "alpha"); err != nil {
		t.Fatalf("no-op rename: %v", err)
	}
	// A name freed by renaming its holder can then be taken.
	if _, err := c.RenameNode(ctx, a.ID, "alpha2"); err != nil {
		t.Fatalf("rename a: %v", err)
	}
	if _, err := c.RenameNode(ctx, b.ID, "alpha"); err != nil {
		t.Fatalf("taking the freed name: %v", err)
	}
}

// The same name in ANOTHER meshnet is fine — uniqueness is per meshnet, and
// resolution never crosses one.
func TestRenameNodeNameUniquePerMeshnet(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "nas", NodeKey: key(1)})
	other, _ := c.Register(ctx, RegisterInput{Meshnet: 2, Name: "box", NodeKey: key(2)})
	if _, err := c.RenameNode(ctx, other.ID, "nas"); err != nil {
		t.Fatalf("same name in a different meshnet should be allowed: %v", err)
	}
}

// Routes are a CLAIM until an admin approves them — but shipping approval must
// not cut the subnet routers that work today, so a node nobody has reviewed
// keeps having its claims honoured.
func TestRouteApprovalGrandfathersUnreviewedNodes(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	lan := netip.MustParsePrefix("192.168.1.0/24")
	other := netip.MustParsePrefix("10.0.0.0/8")

	n, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "router", NodeKey: key(1),
		AdvertisedRoutes: []netip.Prefix{lan, other}})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(n.ApprovedRoutes) != 2 || n.RoutesReviewed {
		t.Fatalf("an unreviewed node should route what it claims: %+v reviewed=%v", n.ApprovedRoutes, n.RoutesReviewed)
	}

	// The admin narrows it to one route.
	got, err := c.ApproveRoutes(ctx, 1, n.ID, []netip.Prefix{lan})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if len(got.ApprovedRoutes) != 1 || got.ApprovedRoutes[0] != lan || !got.RoutesReviewed {
		t.Fatalf("after review: %+v reviewed=%v", got.ApprovedRoutes, got.RoutesReviewed)
	}

	// The node re-registers claiming both again: the admin's decision stands.
	again, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "router", NodeKey: key(1),
		AdvertisedRoutes: []netip.Prefix{lan, other}})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if len(again.ApprovedRoutes) != 1 || again.ApprovedRoutes[0] != lan {
		t.Fatalf("re-registration overrode the admin: %+v", again.ApprovedRoutes)
	}

	// It stops claiming the approved route → the approval goes with it (a node
	// that no longer offers a CIDR must stop receiving its traffic).
	dropped, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "router", NodeKey: key(1),
		AdvertisedRoutes: []netip.Prefix{other}})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if len(dropped.ApprovedRoutes) != 0 {
		t.Fatalf("approval survived the claim being withdrawn: %+v", dropped.ApprovedRoutes)
	}
}

// An approval can only pick from what the node claims — it is a decision about
// claims, not a way to invent them — and never crosses a meshnet boundary.
func TestApproveRoutesRejectsUnclaimedAndCrossTenant(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	lan := netip.MustParsePrefix("192.168.1.0/24")
	n, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "router", NodeKey: key(1),
		AdvertisedRoutes: []netip.Prefix{lan}})

	if _, err := c.ApproveRoutes(ctx, 1, n.ID, []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}); !errors.Is(err, ErrRouteNotAdvertised) {
		t.Fatalf("unclaimed route err = %v, want ErrRouteNotAdvertised", err)
	}
	if _, err := c.ApproveRoutes(ctx, 2, n.ID, []netip.Prefix{lan}); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("cross-tenant approve err = %v, want ErrNodeNotFound", err)
	}
	// Rejected attempts left the node alone.
	got, _ := c.Nodes.Get(ctx, n.ID)
	if len(got.ApprovedRoutes) != 1 || got.RoutesReviewed {
		t.Fatalf("refused approvals changed state: %+v reviewed=%v", got.ApprovedRoutes, got.RoutesReviewed)
	}
}

// Only APPROVED routes reach peers' allowed_ips: an unapproved claim must not
// pull anyone's traffic.
func TestNetMapCarriesOnlyApprovedRoutes(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	lan := netip.MustParsePrefix("192.168.1.0/24")
	other := netip.MustParsePrefix("10.0.0.0/8")
	router, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "router", NodeKey: key(1),
		AdvertisedRoutes: []netip.Prefix{lan, other}})
	peer, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "peer", NodeKey: key(2)})
	if _, err := c.ApproveRoutes(ctx, 1, router.ID, []netip.Prefix{lan}); err != nil {
		t.Fatal(err)
	}

	nm, err := c.NetMapFor(ctx, peer.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	if len(nm.Peers) != 1 {
		t.Fatalf("peers = %+v", nm.Peers)
	}
	if len(nm.Peers[0].ApprovedRoutes) != 1 || nm.Peers[0].ApprovedRoutes[0] != lan {
		t.Fatalf("peer's approved routes = %+v, want just the approved LAN", nm.Peers[0].ApprovedRoutes)
	}
}

// "Whose device is this" comes from the key that enrolled it (resolved, never
// self-asserted), and follows whoever installed it last.
func TestRegisterStampsOwner(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	n, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1), OwnerUserID: 42})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if n.OwnerUserID != 42 {
		t.Fatalf("owner = %d, want 42", n.OwnerUserID)
	}
	again, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1), OwnerUserID: 7})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if again.OwnerUserID != 7 {
		t.Fatalf("owner after re-enrollment = %d, want the person who installed it last (7)", again.OwnerUserID)
	}
}

// Device approval gates NEW devices only. Turning the switch on grandfathers
// the fleet already enrolled — a security feature that parks working devices
// retroactively is just an outage.
func TestDeviceApprovalGrandfathersAndGatesNewDevices(t *testing.T) {
	c := newTestCoord()
	c.Settings = NewMemSettingsStore()
	ctx := context.Background()

	old, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "old", NodeKey: key(1)})
	if !old.Approved {
		t.Fatal("a device enrolled before approval was required must be approved")
	}
	if err := c.UpdateSettings(ctx, 1, MeshnetSettings{RequireDeviceApproval: true}); err != nil {
		t.Fatalf("enable approval: %v", err)
	}
	got, _ := c.Nodes.Get(ctx, old.ID)
	if !got.Approved {
		t.Fatal("enabling approval must not park an existing device")
	}

	// A new device enrolls but reaches nothing until approved.
	fresh, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "fresh", NodeKey: key(2)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if fresh.Approved {
		t.Fatal("a new device must start unapproved while the switch is on")
	}
	if !fresh.Overlay.IsValid() {
		t.Fatal("a pending device should still hold an address (its daemon runs normally)")
	}

	nm, err := c.NetMapFor(ctx, fresh.ID)
	if err != nil {
		t.Fatalf("pending device should still get a netmap: %v", err)
	}
	if len(nm.Peers) != 0 {
		t.Fatalf("a pending device must see nobody: %+v", nm.Peers)
	}
	nmOld, _ := c.NetMapFor(ctx, old.ID)
	if len(nmOld.Peers) != 0 {
		t.Fatalf("nobody should see a pending device: %+v", nmOld.Peers)
	}

	// Approving wires it up both ways.
	if _, err := c.SetNodeApproved(ctx, 1, fresh.ID, true); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if nm, _ := c.NetMapFor(ctx, fresh.ID); len(nm.Peers) != 1 {
		t.Fatalf("approved device should see its peer: %+v", nm.Peers)
	}
	if nm, _ := c.NetMapFor(ctx, old.ID); len(nm.Peers) != 1 {
		t.Fatalf("peers should now see the approved device: %+v", nm.Peers)
	}
	// Cross-tenant approval is refused.
	if _, err := c.SetNodeApproved(ctx, 2, fresh.ID, false); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("cross-tenant approve err = %v, want ErrNodeNotFound", err)
	}
}

// With no settings store (community build) nothing gates: devices enroll as they
// always did.
func TestDeviceApprovalWithoutSettingsStore(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	n, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if err != nil || !n.Approved {
		t.Fatalf("node = %+v err = %v, want an approved node", n, err)
	}
}
