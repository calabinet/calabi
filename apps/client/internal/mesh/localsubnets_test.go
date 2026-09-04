package mesh

import (
	"net/netip"
	"testing"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func TestExactLocalCollision(t *testing.T) {
	locals := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}
	cases := []struct {
		name string
		pfx  string
		want bool // whether it is an EXACT same-subnet collision (local wins)
		hit  string
	}{
		{"identical /24", "192.168.1.0/24", true, "192.168.1.0/24"},
		{"unmasked but same subnet", "192.168.1.5/24", true, "192.168.1.0/24"},
		{"more-specific host is NOT a collision", "192.168.1.222/32", false, ""},
		{"more-specific sub-range is NOT a collision", "192.168.1.128/25", false, ""},
		{"broader is NOT a collision", "192.168.0.0/16", false, ""},
		{"identical 10/8", "10.0.0.0/8", true, "10.0.0.0/8"},
		{"host inside 10/8 is NOT a collision", "10.1.2.3/32", false, ""},
		{"disjoint private", "172.16.0.0/12", false, ""},
		{"public", "8.8.8.0/24", false, ""},
		{"ipv6 never matches ipv4 local", "fd00::/8", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := exactLocalCollision(netip.MustParsePrefix(c.pfx), locals)
			if ok != c.want {
				t.Fatalf("exactLocalCollision(%s) ok=%v, want %v", c.pfx, ok, c.want)
			}
			if ok && got != netip.MustParsePrefix(c.hit) {
				t.Fatalf("exactLocalCollision(%s) hit=%s, want %s", c.pfx, got, c.hit)
			}
		})
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
			netip.MustParsePrefix("192.168.1.222/32"), // remote host INSIDE our LAN -> more specific, KEEP
			netip.MustParsePrefix("192.168.1.0/24"),   // IDENTICAL to local LAN -> dropped (local wins)
		}},
		{PublicKey: keyB, AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),     // default route -> exit step, skipped here
			netip.MustParsePrefix("172.20.0.0/16"), // keep
			netip.MustParsePrefix("10.99.0.0/16"),  // dup of keyA's -> skipped
		}},
	}

	keep, dropped := selectSubnetRoutes(peers, overlay, locals)

	// A more-specific host route (192.168.1.222/32) inside the local /24 is kept:
	// longest-prefix diverts only that address, the rest of the LAN stays local.
	wantKeep := []netip.Prefix{
		netip.MustParsePrefix("10.99.0.0/16"),
		netip.MustParsePrefix("192.168.1.222/32"),
		netip.MustParsePrefix("172.20.0.0/16"),
	}
	if len(keep) != len(wantKeep) {
		t.Fatalf("keep=%v, want %v", keep, wantKeep)
	}
	for i := range wantKeep {
		if keep[i] != wantKeep[i] {
			t.Fatalf("keep[%d]=%s, want %s (full: %v)", i, keep[i], wantKeep[i], keep)
		}
	}

	// Only the exact same-subnet advertisement is dropped.
	if len(dropped) != 1 {
		t.Fatalf("dropped=%v, want exactly one (the identical subnet)", dropped)
	}
	d := dropped[0]
	if d.Advertised != netip.MustParsePrefix("192.168.1.0/24") ||
		d.Local != netip.MustParsePrefix("192.168.1.0/24") ||
		!d.Peer.Equal(keyA) {
		t.Fatalf("dropped[0]=%+v, want advertised/local 192.168.1.0/24 from peer A", d)
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
