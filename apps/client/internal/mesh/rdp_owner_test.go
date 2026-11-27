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
	tun.remoteLogin.Store(&remoteLoginFilter{local: local, owners: map[netip.Addr]bool{owner: true}, ports: map[uint16]bool{3389: true}, rdp: true})
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

func TestRemoteLoginInboundOwnershipAndPort(t *testing.T) {
	local := netip.MustParseAddr("100.64.0.12")
	owner := netip.MustParseAddr("100.64.0.11")
	other := netip.MustParseAddr("100.64.0.13")
	tun := &filteredTUN{filter: &PacketFilter{}, flows: newFlowTable()}
	tun.remoteLogin.Store(&remoteLoginFilter{
		local: local, owners: map[netip.Addr]bool{owner: true}, ports: map[uint16]bool{22: true, 2222: true},
		grants: map[remoteLoginGrant]bool{{other, 2222}: true},
	})
	packet := func(source netip.Addr, proto uint8, port uint16) []byte {
		p := ipv4(source.String(), proto, port, 0)
		copy(p[16:20], local.AsSlice())
		return p
	}
	for _, test := range []struct {
		source netip.Addr
		port   uint16
		allow  bool
	}{{owner, 22, true}, {other, 22, false}, {other, 2222, true}, {other, 17401, true}} {
		if got := tun.allowInbound(packet(test.source, protoTCP, test.port)); got != test.allow {
			t.Fatalf("source %v port %d: allowed = %v, want %v", test.source, test.port, got, test.allow)
		}
	}
	tun.filter.SetRules(true, nil)
	if tun.allowInbound(packet(other, protoTCP, 2222)) {
		t.Fatal("remote login grant bypassed the regular ACL")
	}
}
