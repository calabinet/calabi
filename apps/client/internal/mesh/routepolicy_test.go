package mesh

// routepolicy_test.go — the CONSUMER side of subnet routes.
//
// Accepting a peer's advertised route is not free: the prefix lands in this
// machine's kernel routing table. A route covering a host that also TALKS to
// this node hijacks the return path — the reply goes into the tun, the far side
// drops it (the source isn't in this node's allowed-ips), and the connection
// times out with nothing in any log. Publishing is the advertiser's decision and
// approval is the admin's; this is the third party neither speaks for.

import (
	"net/netip"
	"testing"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// peerWith builds a one-peer config whose allowed-ips are exactly these.
func peerWith(aips ...string) WGConfig {
	ps := make([]netip.Prefix, 0, len(aips))
	for _, a := range aips {
		ps = append(ps, pfx(a))
	}
	return WGConfig{Peers: []WGPeer{{PublicKey: mustKey(2), AllowedIPs: ps}}}
}

func allowed(cfg WGConfig) []string {
	if len(cfg.Peers) == 0 {
		return nil
	}
	out := make([]string, 0, len(cfg.Peers[0].AllowedIPs))
	for _, p := range cfg.Peers[0].AllowedIPs {
		out = append(out, p.String())
	}
	return out
}

func eq(a, b []string) bool {
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

func TestApplyRoutePolicy(t *testing.T) {
	cases := []struct {
		name   string
		cfg    WGConfig
		policy RoutePolicy
		want   []string
	}{
		{
			// The default. A node still meshes — it just doesn't take other
			// people's subnets into its routing table.
			"refusing routes keeps the overlay",
			peerWith("100.64.0.2/32", "192.168.1.0/24"),
			RoutePolicy{Accept: false},
			[]string{"100.64.0.2/32"},
		},
		{
			"accepting takes them all",
			peerWith("100.64.0.2/32", "192.168.1.0/24", "10.9.0.0/24"),
			RoutePolicy{Accept: true},
			[]string{"100.64.0.2/32", "192.168.1.0/24", "10.9.0.0/24"},
		},
		{
			// The reported case: one /32 poisons the return path, the rest are fine.
			"an exclusion is surgical",
			peerWith("100.64.0.2/32", "192.168.1.22/32", "10.9.0.0/24"),
			RoutePolicy{Accept: true, Excludes: []netip.Prefix{pfx("192.168.1.22/32")}},
			[]string{"100.64.0.2/32", "10.9.0.0/24"},
		},
		{
			// An exclusion names a REGION of address space. Matching only exact
			// strings would let the /32 that caused the trouble slip through a /24
			// exclusion — the shape the operator was trying to shut off.
			"an exclusion covers more-specific prefixes inside it",
			peerWith("100.64.0.2/32", "192.168.1.22/32", "192.168.1.0/24"),
			RoutePolicy{Accept: true, Excludes: []netip.Prefix{pfx("192.168.1.0/24")}},
			[]string{"100.64.0.2/32"},
		},
		{
			// ...but not the other way round: excluding one host must not take out
			// the whole subnet route the operator still wants.
			"a narrow exclusion does not swallow the broader route",
			peerWith("100.64.0.2/32", "192.168.1.0/24"),
			RoutePolicy{Accept: true, Excludes: []netip.Prefix{pfx("192.168.1.22/32")}},
			[]string{"100.64.0.2/32", "192.168.1.0/24"},
		},
		{
			// The exit node is THIS machine's own explicit choice (ExitNode). A
			// switch about other people's subnets has no business revoking it.
			"the default route survives even with routes refused",
			peerWith("100.64.0.2/32", "0.0.0.0/0"),
			RoutePolicy{Accept: false},
			[]string{"100.64.0.2/32", "0.0.0.0/0"},
		},
		{
			// Overlay addresses are how a peer is reached at all. Filtering them
			// would leave the node in a mesh it cannot talk on.
			"an exclusion cannot cut the overlay",
			peerWith("100.64.0.2/32"),
			RoutePolicy{Accept: true, Excludes: []netip.Prefix{pfx("100.64.0.0/10")}},
			[]string{"100.64.0.2/32"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := applyRoutePolicy(tc.cfg, tc.policy)
			if !eq(allowed(got), tc.want) {
				t.Fatalf("allowed-ips = %v, want %v", allowed(got), tc.want)
			}
		})
	}
}

// Refusals are reported so the daemon can say WHY a route the user expected
// isn't there — the failure mode this whole feature exists to make debuggable.
func TestApplyRoutePolicyReportsRefusals(t *testing.T) {
	cfg := peerWith("100.64.0.2/32", "192.168.1.22/32", "10.9.0.0/24")
	_, refused := applyRoutePolicy(cfg, RoutePolicy{
		Accept:   true,
		Excludes: []netip.Prefix{pfx("192.168.1.22/32")},
	})
	if len(refused) != 1 {
		t.Fatalf("refused %d routes, want 1: %+v", len(refused), refused)
	}
	if refused[0].Prefix != pfx("192.168.1.22/32") {
		t.Fatalf("refused %s, want 192.168.1.22/32", refused[0].Prefix)
	}
	if refused[0].Reason == "" {
		t.Fatal("a refusal with no reason is useless in a log")
	}
	if refused[0].Peer != mustKey(2) {
		t.Fatalf("refusal names peer %s, want the advertiser", refused[0].Peer)
	}
}

// The common case (accept everything, no exclusions) must not rebuild the peer
// slice — this runs on every netmap push.
func TestApplyRoutePolicyIsAPassthroughWhenUnrestricted(t *testing.T) {
	cfg := peerWith("100.64.0.2/32", "192.168.1.0/24")
	got, refused := applyRoutePolicy(cfg, RoutePolicy{Accept: true})
	if refused != nil {
		t.Fatalf("refused %v with an unrestricted policy", refused)
	}
	if &got.Peers[0].AllowedIPs[0] != &cfg.Peers[0].AllowedIPs[0] {
		t.Fatal("unrestricted policy copied the allowed-ips instead of passing them through")
	}
}

// A refused prefix must be gone from allowed-ips, not merely missing an OS
// route: half-refusing would still let the peer SOURCE traffic from that range.
func TestRefusedRoutesAlsoLoseTheirOSRoute(t *testing.T) {
	cfg := peerWith("100.64.0.2/32", "192.168.1.22/32")
	filtered, _ := applyRoutePolicy(cfg, RoutePolicy{Accept: false})
	keep, _ := selectSubnetRoutes(filtered.Peers, pfx(meshOverlayCIDR), nil)
	if len(keep) != 0 {
		t.Fatalf("refused route still produced OS routes: %v", keep)
	}
}

// Logging is gated on the refusal set CHANGING — the coordinator re-pushes an
// unchanged netmap every 15 minutes and a standing decision isn't news.
func TestRefusedFingerprint(t *testing.T) {
	cfg := peerWith("100.64.0.2/32", "192.168.1.22/32")
	p := RoutePolicy{Accept: false}
	_, a := applyRoutePolicy(cfg, p)
	_, b := applyRoutePolicy(cfg, p)
	if refusedFingerprint(a) != refusedFingerprint(b) {
		t.Fatal("an unchanged netmap must produce an unchanged fingerprint (it would re-log forever)")
	}
	if refusedFingerprint(nil) != "" {
		t.Fatal("no refusals must fingerprint empty, or the first clean netmap logs nothing but looks like a change")
	}
	_, c := applyRoutePolicy(peerWith("100.64.0.2/32", "10.9.0.0/24"), p)
	if refusedFingerprint(c) == refusedFingerprint(a) {
		t.Fatal("a different refused set must change the fingerprint")
	}
}
