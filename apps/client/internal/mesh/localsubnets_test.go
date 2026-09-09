package mesh

import (
	"net/netip"
	"testing"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func TestLocalSubnetWins(t *testing.T) {
	locals := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}
	cases := []struct {
		name string
		pfx  string
		want bool // whether this machine is already attached to that space
		hit  string
	}{
		{"identical /24", "192.168.1.0/24", true, "192.168.1.0/24"},
		{"unmasked but same subnet", "192.168.1.5/24", true, "192.168.1.0/24"},
		// The three that changed. A host or sub-range inside a network we are on
		// is reachable on the wire; routing it into the mesh is the bug.
		{"host inside our own LAN", "192.168.1.222/32", true, "192.168.1.0/24"},
		{"our OWN address", "192.168.1.22/32", true, "192.168.1.0/24"},
		{"sub-range inside our own LAN", "192.168.1.128/25", true, "192.168.1.0/24"},
		{"host inside 10/8 we are on", "10.1.2.3/32", true, "10.0.0.0/8"},
		// Broader is still kept: longest-prefix means it never wins locally.
		{"broader is NOT covered", "192.168.0.0/16", false, ""},
		{"disjoint private", "172.16.0.0/12", false, ""},
		{"public", "8.8.8.0/24", false, ""},
		{"ipv6 never matches ipv4 local", "fd00::/8", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := localSubnetWins(netip.MustParsePrefix(c.pfx), locals)
			if ok != c.want {
				t.Fatalf("localSubnetWins(%s) ok=%v, want %v", c.pfx, ok, c.want)
			}
			if ok && got != netip.MustParsePrefix(c.hit) {
				t.Fatalf("localSubnetWins(%s) hit=%s, want %s", c.pfx, got, c.hit)
			}
		})
	}
}

// The shape that shipped: a subnet router on the SAME LAN advertising the NAS
// beside it (and, as it happens, this very machine). Both must be refused — the
// NAS is on the wire, and routing our own address into the tun is incoherent in
// every reading.
func TestLocalSubnetWinsRefusesASameLanSubnetRouter(t *testing.T) {
	locals := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	overlay := netip.MustParsePrefix("100.64.0.0/10")
	router := meshproto.NodeKey{9}
	peers := []WGPeer{{PublicKey: router, AllowedIPs: []netip.Prefix{
		netip.MustParsePrefix("100.64.0.4/32"),    // the router's own overlay IP
		netip.MustParsePrefix("192.168.1.222/32"), // the NAS, on our wire
		netip.MustParsePrefix("192.168.1.22/32"),  // us
	}}}

	keep, dropped := selectSubnetRoutes(peers, overlay, locals)
	if len(keep) != 0 {
		t.Fatalf("keep=%v, want nothing routed into the mesh", keep)
	}
	if len(dropped) != 2 {
		t.Fatalf("dropped=%v, want both /32s", dropped)
	}
	for _, d := range dropped {
		if d.Local != locals[0] || !d.Peer.Equal(router) {
			t.Errorf("dropped %+v: want local %s from the router peer", d, locals[0])
		}
	}
}

func TestSelectSubnetRoutes(t *testing.T) {
	overlay := netip.MustParsePrefix("100.64.0.0/10")
	locals := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}

	keyA := meshproto.NodeKey{1}
	keyB := meshproto.NodeKey{2}
	peers := []WGPeer{
		{PublicKey: keyA, AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.5/32"),    // overlay /32 -> covered by /10, skipped
			netip.MustParsePrefix("10.99.0.0/16"),     // remote subnet-router, not local -> keep
			netip.MustParsePrefix("192.168.1.222/32"), // host on a LAN we are ON -> dropped
			netip.MustParsePrefix("192.168.1.0/24"),   // IDENTICAL to local LAN -> dropped
		}},
		{PublicKey: keyB, AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),      // default route -> exit step, skipped here
			netip.MustParsePrefix("172.20.0.0/16"),  // keep
			netip.MustParsePrefix("10.99.0.0/16"),   // dup of keyA's -> skipped
			netip.MustParsePrefix("192.168.0.0/16"), // BROADER than our /24 -> keep
		}},
	}

	keep, dropped := selectSubnetRoutes(peers, overlay, locals)

	wantKeep := []netip.Prefix{
		netip.MustParsePrefix("10.99.0.0/16"),
		netip.MustParsePrefix("172.20.0.0/16"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	if len(keep) != len(wantKeep) {
		t.Fatalf("keep=%v, want %v", keep, wantKeep)
	}
	for i := range wantKeep {
		if keep[i] != wantKeep[i] {
			t.Fatalf("keep[%d]=%s, want %s (full: %v)", i, keep[i], wantKeep[i], keep)
		}
	}

	if len(dropped) != 2 {
		t.Fatalf("dropped=%v, want the host and the identical subnet", dropped)
	}
	for _, d := range dropped {
		if d.Local != locals[0] || !d.Peer.Equal(keyA) {
			t.Errorf("dropped %+v: want local %s from peer A", d, locals[0])
		}
	}
}

// The exit-node LAN carve must keep RFC1918 private space local, but must NOT
// swallow the mesh overlay (100.64.0.0/10) — that has to flow into the tun.
func TestPrivateV4Blocks(t *testing.T) {
	contains := func(a netip.Addr) bool {
		for _, b := range privateV4Blocks {
			if b.Contains(a) {
				return true
			}
		}
		return false
	}
	in := []string{"10.1.2.3", "172.16.5.5", "172.31.255.255", "192.168.1.1"}
	out := []string{"100.64.0.1", "8.8.8.8", "172.32.0.1", "169.254.1.1", "9.9.9.9"}
	for _, s := range in {
		if !contains(netip.MustParseAddr(s)) {
			t.Errorf("%s should be kept local (in privateV4Blocks)", s)
		}
	}
	for _, s := range out {
		if contains(netip.MustParseAddr(s)) {
			t.Errorf("%s must NOT be in privateV4Blocks (overlay/public/link-local)", s)
		}
	}
}
