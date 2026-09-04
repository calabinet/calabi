package mesh

import (
	"net/netip"
	"testing"
)

// filterCandidateIPs keeps public + private/LAN addresses (peers on one LAN reach
// each other by them) and drops loopback, link-local, multicast, the mesh overlay
// range, and duplicates — order preserved (first seen wins).
func TestFilterCandidateIPs(t *testing.T) {
	in := []netip.Addr{
		netip.MustParseAddr("192.168.1.10"), // private LAN — keep
		netip.MustParseAddr("203.0.113.5"),  // global v4 — keep
		netip.MustParseAddr("100.64.0.3"),   // mesh overlay — drop
		netip.MustParseAddr("127.0.0.1"),    // loopback — drop
		netip.MustParseAddr("169.254.1.2"),  // link-local v4 — drop
		netip.MustParseAddr("192.168.1.10"), // duplicate — drop
		netip.MustParseAddr("fe80::1"),      // link-local v6 — drop
		netip.MustParseAddr("2001:db8::1"),  // global v6 — keep
		netip.MustParseAddr("::1"),          // loopback v6 — drop
		netip.MustParseAddr("224.0.0.1"),    // multicast — drop
	}
	want := []netip.Addr{
		netip.MustParseAddr("192.168.1.10"),
		netip.MustParseAddr("203.0.113.5"),
		netip.MustParseAddr("2001:db8::1"),
	}
	got := filterCandidateIPs(in)
	if len(got) != len(want) {
		t.Fatalf("got %v (%d), want %v (%d)", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%v, want %v (full %v)", i, got[i], want[i], got)
		}
	}
}

// A v4-mapped v6 address is normalized and judged as its v4 self (so a mapped
// overlay address is still dropped).
func TestFilterCandidateIPsUnmapsV4(t *testing.T) {
	got := filterCandidateIPs([]netip.Addr{
		netip.MustParseAddr("::ffff:100.64.0.9"),  // mapped overlay — drop
		netip.MustParseAddr("::ffff:203.0.113.7"), // mapped global — keep as v4
	})
	if len(got) != 1 || got[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("got %v, want [203.0.113.7]", got)
	}
}
