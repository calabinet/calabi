package mesh

import (
	"net/netip"
	"testing"
)

func TestRDPOwnerAndPolicy(t *testing.T) {
	local := netip.MustParseAddr("100.64.0.12")
	owner := netip.MustParseAddr("100.64.0.11")
	other := "100.64.0.13"
	tun := &filteredTUN{filter: &PacketFilter{}, flows: newFlowTable()}
	tun.rdp.Store(&rdpOwnerFilter{local, map[netip.Addr]bool{owner: true}})
	for _, proto := range []uint8{protoTCP, protoUDP} {
		for _, src := range []string{owner.String(), other} {
			p := ipv4(src, proto, 3389, 0)
			copy(p[16:20], local.AsSlice())
			if tun.allowInbound(p) != (src == owner.String()) {
				t.Fatalf("rdp guard failed %s", src)
			}
			p = ipv4(src, proto, 17401, 0)
			copy(p[16:20], local.AsSlice())
			if !tun.allowInbound(p) {
				t.Fatal("assistance blocked")
			}
		}
	}
	p := ipv4(owner.String(), protoTCP, 3389, 0)
	copy(p[16:20], local.AsSlice())
	tun.filter.SetRules(true, nil)
	if tun.allowInbound(p) {
		t.Fatal("same owner bypassed ACL")
	}
}
