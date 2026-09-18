package core

import (
	"context"
	"net/netip"
	"testing"
)

// autoApproveRoutes switches route approval off for the given meshnets, as an
// org owner does in the console.
func autoApproveRoutes(t *testing.T, c *Coordinator, meshnets ...MeshnetID) {
	t.Helper()
	if c.Settings == nil {
		c.Settings = NewMemSettingsStore()
	}
	for _, m := range meshnets {
		if err := c.Settings.SetSettings(context.Background(), m, MeshnetSettings{AutoApproveRoutes: true}); err != nil {
			t.Fatal(err)
		}
	}
}

// By default a route is a claim until an admin approves it. Before this, a
// device's routes took effect on their own unless an admin had once touched
// that device — so in practice for every new device, which is what a user
// noticed on the platform.
func TestRoutesWaitForAnAdminByDefault(t *testing.T) {
	c := newTestCoord()
	c.Settings = NewMemSettingsStore() // a meshnet that never touched its settings
	ctx := context.Background()
	lan := netip.MustParsePrefix("192.168.1.0/24")

	router, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "router", NodeKey: key(1), AdvertisedRoutes: []netip.Prefix{lan}})
	if err != nil {
		t.Fatal(err)
	}
	if len(router.ApprovedRoutes) != 0 || !containsPrefix(router.AdvertisedRoutes, lan) {
		t.Fatalf("new device: advertised=%v approved=%v, want the claim recorded and nothing approved", router.AdvertisedRoutes, router.ApprovedRoutes)
	}
	// Re-registering does not approve it either.
	again, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "router", NodeKey: key(1), AdvertisedRoutes: []netip.Prefix{lan}})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.ApprovedRoutes) != 0 {
		t.Fatalf("re-registration approved %v on its own", again.ApprovedRoutes)
	}

	peer, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "peer", NodeKey: key(2)})
	nm, err := c.NetMapFor(ctx, peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range nm.Peers {
		if p.NodeKey == router.NodeKey && containsPrefix(PublishedRoutes(&p), lan) {
			t.Fatal("an unapproved route reached a peer's netmap")
		}
	}

	if _, err := c.ApproveRoutes(ctx, 1, router.ID, []netip.Prefix{lan}); err != nil {
		t.Fatal(err)
	}
	nm, _ = c.NetMapFor(ctx, peer.ID)
	found := false
	for _, p := range nm.Peers {
		if p.NodeKey == router.NodeKey && containsPrefix(PublishedRoutes(&p), lan) {
			found = true
		}
	}
	if !found {
		t.Fatal("after approval the route is not in the peer's netmap")
	}
}

// Turning approval on must not cut routes that already work: a device's earlier
// automatic approvals stay. Only what it claims from then on waits.
func TestTurningApprovalOnKeepsRoutesThatWork(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	autoApproveRoutes(t, c, 1)
	lan := netip.MustParsePrefix("192.168.1.0/24")
	office := netip.MustParsePrefix("10.20.30.0/24")

	n, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "router", NodeKey: key(1), AdvertisedRoutes: []netip.Prefix{lan}})
	if err != nil {
		t.Fatal(err)
	}
	if !containsPrefix(n.ApprovedRoutes, lan) {
		t.Fatalf("with approval off the LAN should be approved: %v", n.ApprovedRoutes)
	}

	if err := c.Settings.SetSettings(ctx, 1, MeshnetSettings{AutoApproveRoutes: false}); err != nil {
		t.Fatal(err)
	}
	again, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "router", NodeKey: key(1), AdvertisedRoutes: []netip.Prefix{lan, office}})
	if err != nil {
		t.Fatal(err)
	}
	if !containsPrefix(again.ApprovedRoutes, lan) {
		t.Fatalf("turning approval on dropped a working route: %v", again.ApprovedRoutes)
	}
	if containsPrefix(again.ApprovedRoutes, office) {
		t.Fatalf("a route claimed after approval was turned on was approved without an admin: %v", again.ApprovedRoutes)
	}
}

// A settings read that fails must not let routes through: it delays a NEW route
// until an admin looks, which is the cheap failure.
func TestSettingsReadFailureMakesNewRoutesWait(t *testing.T) {
	c := newTestCoord()
	c.Settings = failingSettings{}
	n, err := c.Register(context.Background(), RegisterInput{Meshnet: 1, Name: "router", NodeKey: key(1),
		AdvertisedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}})
	if err != nil {
		t.Fatalf("a settings blip must not stop enrollment: %v", err)
	}
	if len(n.ApprovedRoutes) != 0 {
		t.Fatalf("approved %v while the org's setting could not be read", n.ApprovedRoutes)
	}
}

// A coordinator with no console to approve in (self-hosted, static keys) keeps
// routes working as its documentation describes: subnets and exit devices alike.
func TestCoordinatorWithoutAConsoleApprovesEverything(t *testing.T) {
	c := newTestCoord()
	c.Settings = NewMemSettingsStore()
	c.AutoApproveAllRoutes = true
	lan := netip.MustParsePrefix("192.168.1.0/24")
	exit := netip.MustParsePrefix("0.0.0.0/0")
	n, err := c.Register(context.Background(), RegisterInput{Meshnet: 1, Name: "gateway", NodeKey: key(1),
		AdvertisedRoutes: []netip.Prefix{lan, exit}})
	if err != nil {
		t.Fatal(err)
	}
	if !containsPrefix(n.ApprovedRoutes, lan) || !containsPrefix(n.ApprovedRoutes, exit) {
		t.Fatalf("ApprovedRoutes = %v, want the LAN and the exit route", n.ApprovedRoutes)
	}
}
