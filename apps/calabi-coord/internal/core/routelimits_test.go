package core

import (
	"context"
	"net/netip"
	"testing"
)

func TestSplitAdvertisedRefusesWiderThanSlash24(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.22/32"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("fd00::/8"), // IPv6 is not aliased, so not limited
	}
	keep, refused := splitAdvertised(in)
	if len(keep) != 3 || len(refused) != 2 {
		t.Fatalf("keep=%v refused=%v; want 3 kept (incl. the IPv6) and 2 refused", keep, refused)
	}
	for _, p := range refused {
		if p.Bits() >= advertiseMinBitsV4 {
			t.Fatalf("refused %v, which is not too broad", p)
		}
	}
}

// An over-wide route must cost the node the ROUTE, never the registration: a
// machine that cannot enrol loses its overlay address, its peer-to-peer traffic
// and its other routes over one netmask.
func TestRegisterKeepsTheNodeAndDropsOnlyTheWideRoute(t *testing.T) {
	c := newTestCoord()
	n, err := c.Register(context.Background(), RegisterInput{
		Meshnet: 1, NodeKey: key(1), Name: "router",
		AdvertisedRoutes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("192.168.1.0/24"),
		},
		AliasedRoutes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("192.168.1.0/24"),
		},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !n.Overlay.IsValid() {
		t.Fatal("node did not get an overlay address")
	}
	if len(n.AdvertisedRoutes) != 1 || n.AdvertisedRoutes[0] != netip.MustParsePrefix("192.168.1.0/24") {
		t.Fatalf("AdvertisedRoutes = %v, want only the /24", n.AdvertisedRoutes)
	}
	// The alias request for the dropped route must go with it, or the console
	// shows a pending request that can never be granted.
	for _, p := range n.AliasedRoutes {
		if p.Bits() < advertiseMinBitsV4 {
			t.Fatalf("AliasedRoutes still holds %v", p)
		}
	}
	for _, p := range n.ApprovedRoutes {
		if p.Bits() < advertiseMinBitsV4 {
			t.Fatalf("ApprovedRoutes still holds %v", p)
		}
	}
}

// A node that already has a wide route approved in the store must lose it on its
// next registration rather than keeping it forever because it predates the rule.
func TestReRegisterDropsAPreviouslyApprovedWideRoute(t *testing.T) {
	ctx := context.Background()
	c := newTestCoord()
	wide := netip.MustParsePrefix("192.168.0.0/16")
	narrow := netip.MustParsePrefix("192.168.1.0/24")

	n, err := c.Register(ctx, RegisterInput{Meshnet: 1, NodeKey: key(1), Name: "router",
		AdvertisedRoutes: []netip.Prefix{narrow}})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Simulate the pre-rule state: the store holds the wide route as approved.
	n.AdvertisedRoutes = append(n.AdvertisedRoutes, wide)
	n.ApprovedRoutes = append(n.ApprovedRoutes, wide)
	if _, err := c.Nodes.Upsert(ctx, n); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	again, err := c.Register(ctx, RegisterInput{Meshnet: 1, NodeKey: key(1), Name: "router",
		AdvertisedRoutes: []netip.Prefix{narrow, wide}})
	if err != nil {
		t.Fatalf("re-Register: %v", err)
	}
	for _, p := range append(append([]netip.Prefix{}, again.AdvertisedRoutes...), again.ApprovedRoutes...) {
		if p == wide {
			t.Fatalf("the pre-existing /16 survived re-registration: advertised=%v approved=%v",
				again.AdvertisedRoutes, again.ApprovedRoutes)
		}
	}
}

// An exit device advertises the default route. It is neither too broad (it is
// never aliased) nor an intrusion into the overlay (longest prefix match keeps
// every node's own /32), so both limits must let it through - from 2026-09-06
// they refused it and no device on any platform could serve as an exit. It must
// still never be approved without an admin: it carries its consumers' entire
// internet traffic.
func TestExitRouteIsPublishedButNeverAutoApproved(t *testing.T) {
	c := newTestCoord()
	autoApproveRoutes(t, c, 1) // the org switched approval off; exits still wait
	exit := netip.MustParsePrefix("0.0.0.0/0")
	lan := netip.MustParsePrefix("192.168.1.0/24")
	n, err := c.Register(context.Background(), RegisterInput{
		Meshnet: 1, NodeKey: key(1), Name: "gateway",
		AdvertisedRoutes: []netip.Prefix{exit, lan},
		AliasedRoutes:    []netip.Prefix{lan},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !containsPrefix(n.AdvertisedRoutes, exit) || !containsPrefix(n.AdvertisedRoutes, lan) {
		t.Fatalf("AdvertisedRoutes = %v, want the exit route and the LAN", n.AdvertisedRoutes)
	}
	// A never-reviewed node in an otherwise empty meshnet: its LAN is
	// auto-approved as before, its exit route is not.
	if containsPrefix(n.ApprovedRoutes, exit) {
		t.Fatalf("ApprovedRoutes = %v: the exit route was auto-approved", n.ApprovedRoutes)
	}
	if !containsPrefix(n.ApprovedRoutes, lan) {
		t.Fatalf("ApprovedRoutes = %v: the LAN lost its auto-approval", n.ApprovedRoutes)
	}

	approved, err := c.ApproveRoutes(context.Background(), 1, n.ID, []netip.Prefix{exit, lan})
	if err != nil {
		t.Fatalf("an admin approving the exit route: %v", err)
	}
	if !containsPrefix(approved.ApprovedRoutes, exit) {
		t.Fatalf("after approval ApprovedRoutes = %v", approved.ApprovedRoutes)
	}
}

// The exemption is for the default route only: anything else wide, or inside
// the mesh's own address space, is still refused.
func TestExitExemptionCoversOnlyTheDefaultRoute(t *testing.T) {
	for _, s := range []string{"0.0.0.0/1", "128.0.0.0/1", "100.64.0.0/10", "100.64.0.9/32"} {
		p := netip.MustParsePrefix(s)
		if keep, refused := splitAdvertised([]netip.Prefix{p}); len(keep) != 0 || len(refused) != 1 {
			t.Errorf("%s: keep=%v refused=%v, want it refused", s, keep, refused)
		}
	}
	for _, s := range []string{"0.0.0.0/0", "::/0"} {
		p := netip.MustParsePrefix(s)
		if keep, _ := splitAdvertised([]netip.Prefix{p}); len(keep) != 1 {
			t.Errorf("%s was refused", s)
		}
	}
}
