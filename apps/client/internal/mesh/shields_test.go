package mesh

import (
	"net/netip"
	"testing"
)

// Shields are this MACHINE'S own refusal, so they must hold in the case that is
// by far the most common: an org that has never written an access rule. There
// the coordinator compiles no filter and enabled is false — and filteredTUN.Write
// skips the whole inspection path when PacketFilter.Enabled() says false. A
// shields switch that only worked in orgs with rules would look on and do
// nothing, which is worse than not having it.
func TestShieldsBlockInboundWithNoCompiledFilter(t *testing.T) {
	f := &PacketFilter{} // no SetRules at all: this is a mesh with no ACL
	if f.Enabled() {
		t.Fatal("setup: a fresh filter must be disabled")
	}
	pkt := ipv4("100.64.0.9", protoTCP, 22, 0)
	if !f.Allow(pkt) {
		t.Fatal("setup: with no rules and no shields everything is allowed")
	}

	f.SetShields(true)

	if !f.Enabled() {
		t.Fatal("shields must make the filter ENABLED, or filteredTUN skips inspection entirely")
	}
	if f.Allow(pkt) {
		t.Fatal("an inbound packet got through while shields were up")
	}

	f.SetShields(false)
	if f.Enabled() {
		t.Fatal("dropping shields on a filter with no rules must go back to disabled")
	}
	if !f.Allow(pkt) {
		t.Fatal("traffic did not come back after shields were dropped")
	}
}

// Shields outrank the org's rules: an admin's "accept" is permission to try, not
// an obligation on the receiver to answer.
func TestShieldsOutrankAnAllowingRule(t *testing.T) {
	f := &PacketFilter{}
	f.SetRules(true, []FilterRule{{
		SrcCIDRs: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		DstPorts: []PortRange{{First: 0, Last: 65535}},
	}})
	pkt := ipv4("100.64.0.9", protoTCP, 22, 0)
	if !f.Allow(pkt) {
		t.Fatal("setup: the rule should admit this packet")
	}

	f.SetShields(true)
	if f.Allow(pkt) {
		t.Fatal("a rule that allows everything beat the machine's own shields")
	}

	// And a netmap push must not clear them — SetRules and SetShields are
	// separate pieces of state, from separate authorities.
	f.SetRules(true, []FilterRule{{
		SrcCIDRs: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		DstPorts: []PortRange{{First: 0, Last: 65535}},
	}})
	if f.Allow(pkt) {
		t.Fatal("a netmap push cleared the machine's own shields")
	}
}

// "Block INCOMING connections", not "disconnect". What this machine starts keeps
// working, and the answers have to come back — otherwise the switch is a kill
// switch under a misleading name, and every outbound ssh/http from a shielded
// laptop would hang instead of working.
func TestShieldsStillAllowRepliesToOurOwnConnections(t *testing.T) {
	tn := tunOf(false) // no ACL in this org — the ordinary case
	tn.filter.SetShields(true)

	reply := ipv4Flow("100.64.0.2", "100.64.0.1", protoTCP, 22, 51000)
	if tn.allowInbound(reply) {
		t.Fatal("an unsolicited inbound packet got past shields")
	}

	// This machine opens the connection.
	tp, ok := parseTuple(ipv4Flow("100.64.0.1", "100.64.0.2", protoTCP, 51000, 22))
	if !ok {
		t.Fatal("outbound packet did not parse")
	}
	tn.flows.observeOutbound(tp)

	if !tn.allowInbound(reply) {
		t.Fatal("shields dropped the reply to a connection this machine opened")
	}
}

// SetShields reports whether it changed anything, so the datapath can log the
// transition once instead of on every netmap push (the coordinator re-pushes an
// unchanged netmap every 15 minutes).
func TestSetShieldsReportsChangeOnce(t *testing.T) {
	f := &PacketFilter{}
	if !f.SetShields(true) {
		t.Fatal("first turn-on should report a change")
	}
	if f.SetShields(true) {
		t.Fatal("re-applying the same value reported a change")
	}
	if !f.Shields() {
		t.Fatal("Shields() does not report the state")
	}
	if !f.SetShields(false) {
		t.Fatal("turn-off should report a change")
	}
}
