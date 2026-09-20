package mesh

import (
	"net/netip"
	"reflect"
	"testing"

	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

func TestIptablesAliasRules(t *testing.T) {
	rules := iptablesAliasRules([]SubnetAlias{
		{Alias: netip.MustParsePrefix("100.96.5.0/24"), Real: netip.MustParsePrefix("192.168.1.0/24")},
		// Unmasked input must still produce a masked rule — NETMAP maps networks.
		{Alias: netip.MustParsePrefix("100.96.6.7/24"), Real: netip.MustParsePrefix("10.0.0.9/24")},
		// Dropped: different sizes cannot be a 1:1 rewrite.
		{Alias: netip.MustParsePrefix("100.96.7.0/24"), Real: netip.MustParsePrefix("10.1.0.0/16")},
		// Dropped: v0 is IPv4 only.
		{Alias: netip.MustParsePrefix("fd00::/64"), Real: netip.MustParsePrefix("fd01::/64")},
	})
	want := [][]string{
		{"-t", "nat", "-A", "PREROUTING", "-d", "100.96.5.0/24", "-j", "NETMAP", "--to", "192.168.1.0/24"},
		{"-t", "nat", "-A", "PREROUTING", "-d", "100.96.6.0/24", "-j", "NETMAP", "--to", "10.0.0.0/24"},
	}
	var got [][]string
	for _, r := range rules {
		got = append(got, r.args("-A", ""))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules =\n%v\nwant\n%v", got, want)
	}
}

// Both halves or neither. Half a mapping would install a rewrite to nowhere,
// which is worse than leaving that subnet unaliased.
func TestFromNetMapParsesSubnetAliases(t *testing.T) {
	pb := &meshpb.NetMap{
		Self: &meshpb.Peer{NodeKey: keyB64(1), OverlayAddr: "100.64.0.4"},
		SubnetAliases: []*meshpb.SubnetAlias{
			{Alias: "100.96.5.0/24", Real: "192.168.1.0/24"},
			{Alias: "garbage", Real: "192.168.2.0/24"},    // unparseable alias
			{Alias: "100.96.6.0/24", Real: "not-a-cidr"},  // unparseable real
			{Alias: "100.96.7.0/24", Real: "10.0.0.0/16"}, // size mismatch
			{Alias: "100.96.8.9/24", Real: "10.1.2.3/24"}, // unmasked, still fine
		},
	}
	nm, err := FromNetMap(pb)
	if err != nil {
		t.Fatal(err)
	}
	want := []SubnetAlias{
		{Alias: netip.MustParsePrefix("100.96.5.0/24"), Real: netip.MustParsePrefix("192.168.1.0/24")},
		{Alias: netip.MustParsePrefix("100.96.8.0/24"), Real: netip.MustParsePrefix("10.1.2.0/24")},
	}
	if !reflect.DeepEqual(nm.SubnetAliases, want) {
		t.Fatalf("aliases = %v, want %v", nm.SubnetAliases, want)
	}
}

// The coordinator re-pushes an unchanged netmap every 15 minutes. Re-running
// iptables each time would churn the NAT table for nothing, so the callback
// compares fingerprints — which must not depend on the order the wire used.
func TestAliasFingerprintIsOrderIndependent(t *testing.T) {
	a := SubnetAlias{Alias: netip.MustParsePrefix("100.96.5.0/24"), Real: netip.MustParsePrefix("192.168.1.0/24")}
	b := SubnetAlias{Alias: netip.MustParsePrefix("100.96.6.0/24"), Real: netip.MustParsePrefix("10.0.0.0/24")}
	if aliasFingerprint([]SubnetAlias{a, b}) != aliasFingerprint([]SubnetAlias{b, a}) {
		t.Error("fingerprint changed with the order of the same set")
	}
	if aliasFingerprint(nil) != "" {
		t.Error("the empty set must fingerprint as empty, or a node with no aliases looks changed")
	}
	if aliasFingerprint([]SubnetAlias{a}) == aliasFingerprint([]SubnetAlias{b}) {
		t.Error("different sets share a fingerprint")
	}
}

// The consumer side must need NO new code for an alias to work. Two things make
// that true, and both are easy to break from a distance: an alias is inside the
// overlay CIDR the client already routes into the tun, and it is not private
// space, so the exit-node LAN carve leaves it alone.
func TestAliasPrefixesNeedNoConsumerSideChange(t *testing.T) {
	alias := netip.MustParsePrefix("100.96.5.0/24") // from coord's overlayAliasPool

	if !netip.MustParsePrefix(meshOverlayCIDR).Contains(alias.Addr()) {
		t.Fatalf("%s is outside %s — consumers would need a new OS route", alias, meshOverlayCIDR)
	}
	for _, b := range privateV4Blocks {
		if b.Contains(alias.Addr()) {
			t.Errorf("%s falls in the exit-node LAN carve %s: it would be pinned to the physical link", alias, b)
		}
	}
	// And it survives the consumer's route policy: it collides with nothing, so
	// the local-wins rule has no reason to drop it.
	if _, dropped := localSubnetWins(alias, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}); dropped {
		t.Errorf("%s was dropped as a local collision", alias)
	}
	keep, drop := selectSubnetRoutes(
		[]WGPeer{{AllowedIPs: []netip.Prefix{alias}}},
		netip.MustParsePrefix(meshOverlayCIDR),
		[]netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	)
	_ = keep
	if len(drop) != 0 {
		t.Errorf("selectSubnetRoutes dropped the alias: %v", drop)
	}
}
