package mesh

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// ipv4Flow builds an IPv4 packet with both endpoints and both ports, which is
// what reply matching needs (the package's other builder only sets the source).
func ipv4Flow(src, dst string, proto uint8, srcPort, dstPort uint16) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	p[9] = proto
	copy(p[12:16], netip.MustParseAddr(src).AsSlice())
	copy(p[16:20], netip.MustParseAddr(dst).AsSlice())
	l4 := make([]byte, 4)
	binary.BigEndian.PutUint16(l4[0:2], srcPort)
	binary.BigEndian.PutUint16(l4[2:4], dstPort)
	return append(p, l4...)
}

// tunOf builds a filteredTUN over a filter, with no real device: only the
// packet-decision paths are exercised.
func tunOf(enabled bool, rules ...FilterRule) *filteredTUN {
	f := &PacketFilter{}
	f.SetRules(enabled, rules)
	return &filteredTUN{filter: f, flows: newFlowTable()}
}

// The bug this exists for. A node named only as a rule's SOURCE gets ZERO
// compiled rules, and an enabled filter with no rules denies everything — so
// under the most ordinary ACL in the world
//
//	{"src": ["tag:laptop"], "dst": ["tag:server"], "ports": ["22"]}
//
// the laptop could send its SYN and would then drop the server's SYN-ACK.
// Nothing would work. The reply to a conversation we started must come back.
func TestReplyToOurOwnConnectionIsAllowed(t *testing.T) {
	tn := tunOf(true) // enabled, zero rules = deny all unsolicited

	reply := ipv4Flow("100.64.0.2", "100.64.0.1", protoTCP, 22, 51000)
	if tn.allowInbound(reply) {
		t.Fatal("setup: an unsolicited packet must be denied by an empty enabled filter")
	}

	// We open the connection.
	out := ipv4Flow("100.64.0.1", "100.64.0.2", protoTCP, 51000, 22)
	if tp, ok := parseTuple(out); ok {
		tn.flows.observeOutbound(tp)
	} else {
		t.Fatal("outbound packet did not parse")
	}

	if !tn.allowInbound(reply) {
		t.Fatal("the reply to a connection this machine opened was dropped")
	}
}

// The allowance is the exact reversed 5-tuple, not "this host may talk to us".
// A peer we contacted must not get a free path to anything else.
func TestEstablishedAllowanceIsNarrow(t *testing.T) {
	tn := tunOf(true)
	out := ipv4Flow("100.64.0.1", "100.64.0.2", protoTCP, 51000, 22)
	tp, _ := parseTuple(out)
	tn.flows.observeOutbound(tp)

	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{"other local port", ipv4Flow("100.64.0.2", "100.64.0.1", protoTCP, 22, 51001)},
		{"other remote port", ipv4Flow("100.64.0.2", "100.64.0.1", protoTCP, 23, 51000)},
		{"other host", ipv4Flow("100.64.0.3", "100.64.0.1", protoTCP, 22, 51000)},
		{"other protocol", ipv4Flow("100.64.0.2", "100.64.0.1", protoUDP, 22, 51000)},
	} {
		if tn.allowInbound(tc.pkt) {
			t.Errorf("%s: admitted by the established allowance; it must not be", tc.name)
		}
	}
}

// A rule still admits unsolicited traffic — the flow table is an addition, not
// a replacement.
func TestRulesStillAdmitUnsolicited(t *testing.T) {
	tn := tunOf(true, rule("100.64.0.2/32", PortRange{First: 22, Last: 22}))
	if !tn.allowInbound(ipv4Flow("100.64.0.2", "100.64.0.1", protoTCP, 40000, 22)) {
		t.Error("a rule-allowed inbound connection was dropped")
	}
	if tn.allowInbound(ipv4Flow("100.64.0.2", "100.64.0.1", protoTCP, 40000, 23)) {
		t.Error("a port no rule names was admitted")
	}
}

// A quiet conversation eventually stops being an excuse to reach us.
func TestEstablishedAllowanceExpires(t *testing.T) {
	tn := tunOf(true)
	now := time.Now()
	tn.flows.now = func() time.Time { return now }

	out := ipv4Flow("100.64.0.1", "100.64.0.2", protoUDP, 51000, 53)
	tp, _ := parseTuple(out)
	tn.flows.observeOutbound(tp)

	reply := ipv4Flow("100.64.0.2", "100.64.0.1", protoUDP, 53, 51000)
	if !tn.allowInbound(reply) {
		t.Fatal("the reply was dropped while the flow was still live")
	}

	now = now.Add(flowTTLUDP + time.Second)
	if tn.allowInbound(reply) {
		t.Error("an expired flow still admitted traffic")
	}
	if n := tn.flows.len(); n != 0 {
		t.Errorf("expired entry was not reaped on lookup: %d left", n)
	}
}

// Traffic in either direction keeps the conversation alive, so a long-running
// session doesn't get cut at the TTL boundary.
func TestEstablishedAllowanceRefreshes(t *testing.T) {
	tn := tunOf(true)
	now := time.Now()
	tn.flows.now = func() time.Time { return now }

	tp, _ := parseTuple(ipv4Flow("100.64.0.1", "100.64.0.2", protoUDP, 51000, 53))
	tn.flows.observeOutbound(tp)
	reply := ipv4Flow("100.64.0.2", "100.64.0.1", protoUDP, 53, 51000)

	for i := 0; i < 5; i++ {
		now = now.Add(flowTTLUDP - time.Second)
		if !tn.allowInbound(reply) {
			t.Fatalf("round %d: an active conversation was cut", i)
		}
	}
}

// ICMP carries no ports, so ping replies ride on the host pair alone. Without
// this a ping to a peer would time out under any filter that doesn't open
// everything (matchPort only admits port-less packets via a full-range rule).
func TestICMPReplyIsAllowed(t *testing.T) {
	tn := tunOf(true)
	out := ipv4Flow("100.64.0.1", "100.64.0.2", protoICMP, 0, 0)
	tp, _ := parseTuple(out)
	tn.flows.observeOutbound(tp)

	if !tn.allowInbound(ipv4Flow("100.64.0.2", "100.64.0.1", protoICMP, 0, 0)) {
		t.Error("an ICMP reply to our own ping was dropped")
	}
	if tn.allowInbound(ipv4Flow("100.64.0.3", "100.64.0.1", protoICMP, 0, 0)) {
		t.Error("ICMP from a host we never pinged was admitted")
	}
}

// The table must not grow without bound, and filling up must never turn into
// "allow everything".
func TestFlowTableIsCapped(t *testing.T) {
	f := newFlowTable()
	for i := 0; i < maxFlows+500; i++ {
		f.observeOutbound(tuple{
			proto:   protoTCP,
			src:     netip.MustParseAddr("100.64.0.1"),
			dst:     netip.MustParseAddr("100.64.0.2"),
			srcPort: uint16(1 + i%65535),
			dstPort: 443,
		})
	}
	if n := f.len(); n > maxFlows {
		t.Fatalf("table grew past the cap: %d > %d", n, maxFlows)
	}
}

// A disabled filter stays pass-through: flow tracking must not change what a
// coordinator without filters does.
func TestFlowTrackingDoesNotAffectDisabledFilter(t *testing.T) {
	tn := tunOf(false)
	if !tn.allowInbound(ipv4Flow("100.64.0.9", "100.64.0.1", protoTCP, 1234, 22)) {
		t.Error("a disabled filter dropped a packet")
	}
}
