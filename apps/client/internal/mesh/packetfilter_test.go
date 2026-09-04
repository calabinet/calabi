package mesh

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// ipv4 builds a minimal IPv4 packet with an optional TCP/UDP header.
func ipv4(src string, proto uint8, dstPort uint16, fragOffset uint16) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[6:8], fragOffset)
	p[9] = proto
	copy(p[12:16], netip.MustParseAddr(src).AsSlice())
	if dstPort > 0 {
		l4 := make([]byte, 4)
		binary.BigEndian.PutUint16(l4[2:4], dstPort)
		p = append(p, l4...)
	}
	return p
}

func ipv6(src string, next uint8, dstPort uint16) []byte {
	p := make([]byte, 40)
	p[0] = 0x60
	p[6] = next
	copy(p[8:24], netip.MustParseAddr(src).AsSlice())
	if dstPort > 0 {
		l4 := make([]byte, 4)
		binary.BigEndian.PutUint16(l4[2:4], dstPort)
		p = append(p, l4...)
	}
	return p
}

func rule(cidr string, ports ...PortRange) FilterRule {
	return FilterRule{SrcCIDRs: []netip.Prefix{netip.MustParsePrefix(cidr)}, DstPorts: ports}
}

// A disabled filter is pass-through — that is what a client talking to a
// coordinator without filters must do, or upgrading it would cut all traffic.
func TestFilterDisabledAllowsEverything(t *testing.T) {
	var f PacketFilter
	if !f.Allow(ipv4("100.64.0.9", protoTCP, 22, 0)) {
		t.Fatal("the zero filter must allow everything")
	}
	f.SetRules(false, []FilterRule{rule("100.64.0.1/32", PortRange{First: 443, Last: 443, Proto: "tcp"})})
	if !f.Allow(ipv4("203.0.113.9", protoTCP, 22, 0)) {
		t.Fatal("rules with enabled=false must not filter")
	}
}

// Enabled with NO rules denies everything: that is what an ACL naming this node
// in no rule actually says.
func TestFilterEnabledEmptyDeniesAll(t *testing.T) {
	var f PacketFilter
	f.SetRules(true, nil)
	if f.Allow(ipv4("100.64.0.1", protoTCP, 443, 0)) {
		t.Fatal("an empty enabled filter must deny")
	}
}

func TestFilterMatchesSourceAndPort(t *testing.T) {
	var f PacketFilter
	f.SetRules(true, []FilterRule{
		rule("100.64.0.1/32", PortRange{First: 443, Last: 443, Proto: "tcp"}),
		rule("192.168.1.0/24", PortRange{First: 5000, Last: 5100, Proto: "udp"}),
	})
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"allowed src+port+proto", ipv4("100.64.0.1", protoTCP, 443, 0), true},
		{"right src, wrong port", ipv4("100.64.0.1", protoTCP, 22, 0), false},
		{"right src+port, wrong proto", ipv4("100.64.0.1", protoUDP, 443, 0), false},
		{"wrong src", ipv4("100.64.0.2", protoTCP, 443, 0), false},
		{"subnet src in range", ipv4("192.168.1.7", protoUDP, 5050, 0), true},
		{"subnet src out of range", ipv4("192.168.1.7", protoUDP, 5101, 0), false},
	}
	for _, c := range cases {
		if got := f.Allow(c.pkt); got != c.want {
			t.Errorf("%s: allow = %v, want %v", c.name, got, c.want)
		}
	}
}

// Protocols without ports (ICMP) — and fragments whose L4 header isn't in this
// packet — are admitted ONLY by a rule that opens everything anyway. A narrow
// rule must not become a hole for them.
func TestFilterPortlessTraffic(t *testing.T) {
	narrow := &PacketFilter{}
	narrow.SetRules(true, []FilterRule{rule("100.64.0.1/32", PortRange{First: 443, Last: 443, Proto: "tcp"})})
	if narrow.Allow(ipv4("100.64.0.1", protoICMP, 0, 0)) {
		t.Fatal("ICMP must not pass a tcp/443-only rule")
	}
	if narrow.Allow(ipv4("100.64.0.1", protoTCP, 0, 0x0020)) {
		t.Fatal("a non-initial fragment must not pass a port-specific rule")
	}

	open := &PacketFilter{}
	open.SetRules(true, []FilterRule{rule("100.64.0.1/32", PortRange{First: 0, Last: 65535})})
	if !open.Allow(ipv4("100.64.0.1", protoICMP, 0, 0)) {
		t.Fatal("ICMP should pass an allow-everything rule (ping must keep working)")
	}
	if !open.Allow(ipv4("100.64.0.1", protoTCP, 0, 0x0020)) {
		t.Fatal("fragments should pass an allow-everything rule")
	}
}

func TestFilterIPv6(t *testing.T) {
	var f PacketFilter
	f.SetRules(true, []FilterRule{rule("fd00::/8", PortRange{First: 80, Last: 80, Proto: "tcp"})})
	if !f.Allow(ipv6("fd00::1", protoTCP, 80)) {
		t.Fatal("v6 packet should match a v6 rule")
	}
	if f.Allow(ipv6("fd00::1", protoTCP, 81)) {
		t.Fatal("wrong port must be dropped")
	}
	// A v4 rule must not admit v6 traffic (Prefix.Contains handles this, but the
	// consequence of getting it wrong is a silent bypass).
	var v4only PacketFilter
	v4only.SetRules(true, []FilterRule{rule("0.0.0.0/0", PortRange{First: 0, Last: 65535})})
	if v4only.Allow(ipv6("fd00::1", protoTCP, 80)) {
		t.Fatal("0.0.0.0/0 must not match a v6 source")
	}
}

// Unparseable input is DROPPED when filtering is on: not knowing a packet's
// ports is not a reason to let it through.
func TestFilterDropsMalformed(t *testing.T) {
	var f PacketFilter
	f.SetRules(true, []FilterRule{rule("0.0.0.0/0", PortRange{First: 0, Last: 65535})})
	for _, bad := range [][]byte{
		{},
		{0x45}, // truncated v4
		append([]byte{0x45}, make([]byte, 10)...), // still too short
		{0x35, 1, 2, 3}, // version 3
	} {
		if f.Allow(bad) {
			t.Errorf("malformed packet (% x) must be dropped", bad)
		}
	}
	// A truncated TCP header (port unreadable) is also a drop — in BOTH families,
	// which must not disagree about what an unreadable port means.
	short4 := append(ipv4("100.64.0.1", protoTCP, 0, 0), 0x00, 0x01)
	if f.Allow(short4) {
		t.Error("a truncated IPv4 L4 header must be dropped")
	}
	var f6 PacketFilter
	f6.SetRules(true, []FilterRule{rule("::/0", PortRange{First: 0, Last: 65535})})
	short6 := append(ipv6("fd00::1", protoTCP, 0), 0x00, 0x01)
	if f6.Allow(short6) {
		t.Error("a truncated IPv6 L4 header must be dropped")
	}
	// ...while an unrecognized next-header is "no port", allowed only by the
	// open-everything rule above.
	if !f6.Allow(ipv6("fd00::1", 58 /* ICMPv6 */, 0)) {
		t.Error("ICMPv6 should pass an allow-everything rule")
	}
}
