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
