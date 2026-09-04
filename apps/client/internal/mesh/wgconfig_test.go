package mesh

import (
	"net/netip"
	"testing"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func TestBuildWGConfig(t *testing.T) {
	nm := NetMap{
		Self: Peer{NodeKey: mustKey(1), Overlay: netip.MustParseAddr("100.64.0.1")},
		Peers: []Peer{{
			NodeKey:    mustKey(2),
			Overlay:    netip.MustParseAddr("100.64.0.2"),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
			DERPHome:   "lax",
		}},
	}

	cfg := BuildWGConfig(nm)
	if cfg.NodeKey != mustKey(1) || cfg.OverlayAddr.String() != "100.64.0.1" {
		t.Fatalf("self: key/overlay wrong: %+v", cfg)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(cfg.Peers))
	}
	p := cfg.Peers[0]
	if p.PublicKey != mustKey(2) {
		t.Fatalf("peer key mismatch")
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != "100.64.0.2/32" {
		t.Fatalf("allowed_ips = %v", p.AllowedIPs)
	}
	if p.DERPHome != "lax" || p.PersistentKeepalive != meshKeepalive {
		t.Fatalf("derp/keepalive wrong: %+v", p)
	}
	// DERP-only mode: no direct endpoint yet.
	if p.Endpoint.IsValid() {
		t.Fatalf("endpoint should be zero in DERP-only mode, got %s", p.Endpoint)
	}

	// Once an endpoint is known (MESH.4), it becomes the direct-path hint.
	nm.Peers[0].Endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:41641")}
	if got := BuildWGConfig(nm).Peers[0].Endpoint.String(); got != "203.0.113.5:41641" {
		t.Fatalf("endpoint = %s, want 203.0.113.5:41641", got)
	}
}

func TestResolveExitNode(t *testing.T) {
	nm := NetMap{
		Self: Peer{Name: "me", NodeKey: mustKey(1), Overlay: netip.MustParseAddr("100.64.0.1")},
		Peers: []Peer{
			{Name: "office", NodeKey: mustKey(2), Overlay: netip.MustParseAddr("100.64.0.2")},
			{Name: "home", NodeKey: mustKey(3), Overlay: netip.MustParseAddr("100.64.0.3")},
		},
	}
	cases := []struct {
		sel  string
		want meshproto.NodeKey
	}{
		{"office", mustKey(2)},              // by name
		{"100.64.0.3", mustKey(3)},          // by overlay IP
		{"me", meshproto.NodeKey{}},         // never resolves to self
		{"nope", meshproto.NodeKey{}},       // unknown name
		{"100.64.0.9", meshproto.NodeKey{}}, // unknown overlay
		{"", meshproto.NodeKey{}},           // empty selection
	}
	for _, c := range cases {
		if got := ResolveExitNode(nm, c.sel); got != c.want {
			t.Fatalf("ResolveExitNode(%q) = %v, want %v", c.sel, got, c.want)
		}
	}
}

func TestIsDefaultRoute(t *testing.T) {
	for s, want := range map[string]bool{
		"0.0.0.0/0":      true,
		"::/0":           true,
		"100.64.0.0/10":  false,
		"192.168.1.0/24": false,
		"8.8.8.8/32":     false,
	} {
		if got := isDefaultRoute(netip.MustParsePrefix(s)); got != want {
			t.Fatalf("isDefaultRoute(%s) = %v, want %v", s, got, want)
		}
	}
}

// --- subnet-route withdrawal (the "stale route blackholes the subnet" bug) ---
//
// Routes used to be added and never removed: a CIDR a peer stopped advertising
// kept its OS route pointing at the tun, while the peer write had already dropped
// it from allowed-ips — so that subnet was blackholed until the client restarted
// and the tun (with its routes) went away.

func TestDiffSubnetRoutes(t *testing.T) {
	a := netip.MustParsePrefix("10.9.0.0/24")
	b := netip.MustParsePrefix("192.168.7.0/24")
	c := netip.MustParsePrefix("172.20.0.0/16")

	cases := []struct {
		name     string
		have     []netip.Prefix
		want     []netip.Prefix
		wantAdd  []netip.Prefix
		wantDrop []netip.Prefix
	}{
		{"first apply installs everything", nil, []netip.Prefix{a, b}, []netip.Prefix{a, b}, nil},
		{"an unchanged netmap touches nothing", []netip.Prefix{a, b}, []netip.Prefix{a, b}, nil, nil},
		{"a new route is added alone", []netip.Prefix{a}, []netip.Prefix{a, b}, []netip.Prefix{b}, nil},
		{
			// The reported bug: the peer stopped advertising b.
			"a withdrawn route is removed", []netip.Prefix{a, b}, []netip.Prefix{a}, nil, []netip.Prefix{b},
		},
		{
			// The same bug's worst case. The old code carried `len(extra) > 0`, so
			// a peer that withdrew EVERYTHING skipped the block entirely and left
			// every route behind.
			"withdrawing everything still removes everything", []netip.Prefix{a, b}, nil, nil, []netip.Prefix{a, b},
		},
		{"a swap is one add and one del", []netip.Prefix{a}, []netip.Prefix{c}, []netip.Prefix{c}, []netip.Prefix{a}},
		{"a prefix repeated in want is added once", nil, []netip.Prefix{a, a}, []netip.Prefix{a}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			add, del := diffSubnetRoutes(tc.have, tc.want)
			if !prefixesEqual(add, tc.wantAdd) {
				t.Errorf("add = %v, want %v", add, tc.wantAdd)
			}
			if !prefixesEqual(del, tc.wantDrop) {
				t.Errorf("del = %v, want %v", del, tc.wantDrop)
			}
		})
	}
}

func TestNextSubnetState(t *testing.T) {
	a := netip.MustParsePrefix("10.9.0.0/24")
	b := netip.MustParsePrefix("192.168.7.0/24")

	cases := []struct {
		name           string
		want, add, del []netip.Prefix
		addOK, delOK   bool
		state          []netip.Prefix
	}{
		{"both batches applied", []netip.Prefix{a}, []netip.Prefix{a}, []netip.Prefix{b}, true, true, []netip.Prefix{a}},
		{
			// Keep the un-removed prefix in the state or the next apply diffs to
			// empty and the blackhole becomes permanent — the very bug being fixed,
			// just triggered by a transient OS error instead of by design.
			"a failed withdrawal is retried next time", []netip.Prefix{a}, nil, []netip.Prefix{b}, true, false,
			[]netip.Prefix{a, b},
		},
		{
			"a failed install is retried next time", []netip.Prefix{a, b}, []netip.Prefix{b}, nil, false, true,
			[]netip.Prefix{a},
		},
		{"both failed", []netip.Prefix{a}, []netip.Prefix{a}, []netip.Prefix{b}, false, false, []netip.Prefix{b}},
		{"nothing selected, nothing pending", nil, nil, nil, true, true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nextSubnetState(tc.want, tc.add, tc.del, tc.addOK, tc.delOK)
			if !prefixesEqual(got, tc.state) {
				t.Fatalf("state = %v, want %v", got, tc.state)
			}
		})
	}
}

// A subnet identical to one of THIS machine's own networks is dropped by
// selectSubnetRoutes and never installed — so the withdrawal path must never be
// able to delete it either. Getting this wrong would take out the operator's LAN
// route the moment a peer stopped advertising it.
func TestWithdrawalNeverTouchesALocallyDroppedSubnet(t *testing.T) {
	lan := netip.MustParsePrefix("192.168.1.0/24")
	remote := netip.MustParsePrefix("10.9.0.0/24")
	overlay := netip.MustParsePrefix(meshOverlayCIDR)
	peers := []WGPeer{{PublicKey: mustKey(2), AllowedIPs: []netip.Prefix{
		netip.MustParsePrefix("100.64.0.2/32"), // overlay: not a subnet route
		lan,                                    // collides with our own LAN: dropped
		remote,
	}}}

	keep, dropped := selectSubnetRoutes(peers, overlay, []netip.Prefix{lan})
	if len(dropped) != 1 || dropped[0].Advertised != lan {
		t.Fatalf("expected %s to be dropped, got %v", lan, dropped)
	}

	// The peer now goes away entirely — the strongest withdrawal there is.
	_, del := diffSubnetRoutes(keep, nil)
	for _, p := range del {
		if p == lan {
			t.Fatalf("withdrawal would delete this machine's own LAN route %s", lan)
		}
	}
	if !prefixesEqual(del, []netip.Prefix{remote}) {
		t.Fatalf("del = %v, want just %v", del, remote)
	}
}

func prefixesEqual(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
