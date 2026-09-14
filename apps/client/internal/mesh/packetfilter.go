package mesh

import (
	"encoding/binary"
	"net/netip"
	"sync"
)

// Node-side enforcement of the coordinator's packet filter (MESH.5b). Until this
// existed, an ACL decided which peers a node could SEE; a peer that was visible
// at all could reach every port on it. This is the second gate: of the traffic
// that gets through the netmap, only what a rule names may actually arrive.
//
// It runs on INBOUND packets, after WireGuard has decrypted and authenticated
// them, on their way into the tun. That placement is the point: the sender's
// copy of the rules is advice, the receiver's is enforcement — a compromised or
// stale peer still hits this.
//
// What it deliberately does NOT do: filter outbound traffic (the far side
// enforces its own inbound rules, and dropping locally would only hide the
// error), or reassemble fragments (see parseIP).

// PacketFilter is a node's inbound rule set. The zero value is DISABLED, which
// means "allow everything" — matching a coordinator that doesn't compile filters
// (see NetMap.FilterEnabled). Safe for concurrent use: SetRules runs on the
// netmap goroutine while Allow runs on every inbound packet.
type PacketFilter struct {
	mu      sync.RWMutex
	enabled bool
	rules   []FilterRule
	// shields is this MACHINE'S OWN refusal, independent of the org's rules:
	// "nobody may open a connection to me". It is the one access-control
	// decision that belongs to the person at the keyboard rather than to an
	// admin, and it is enforced here rather than at the coordinator on purpose:
	//
	//   - it must hold when the coordinator is unreachable or its netmap stale,
	//   - it must hold in an org that has never written an ACL, where the
	//     compiled filter is "allow everything",
	//
	// and neither is true of a rule the coordinator would have to send us.
	//
	// It does NOT block replies to conversations this machine STARTED — that
	// check lives one level up, in filteredTUN.allowInbound, and runs before
	// this. Outbound still works; only inbound CONNECTIONS are refused. Same
	// meaning as Tailscale's "Block incoming connections".
	shields bool
}

// SetRules replaces the rule set. enabled=false disables filtering entirely
// (older coordinator); enabled=true with no rules denies everything, which is
// what an ACL that names this node in no rule actually says.
// Returns true when the effective rule set changed, so the caller can log the
// transition once instead of on every netmap push.
func (f *PacketFilter) SetRules(enabled bool, rules []FilterRule) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	changed := f.enabled != enabled || len(f.rules) != len(rules)
	f.enabled, f.rules = enabled, rules
	return changed
}

// SetShields turns this machine's own "refuse all inbound connections" switch on
// or off. Returns true when it changed, so the caller can log the transition.
func (f *PacketFilter) SetShields(on bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	changed := f.shields != on
	f.shields = on
	return changed
}

// Shields reports the machine's own switch (for status/logging).
func (f *PacketFilter) Shields() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.shields
}

// Enabled reports whether ANY inbound filtering is active (for status/logging,
// and for filteredTUN's fast path).
//
// Shields count. Missing that is the whole bug this method exists to avoid: the
// common case is an org with no ACL, where the coordinator sends no filter and
// enabled is false — and filteredTUN.Write skips the entire inspection path when
// this returns false. A shields switch that only worked in orgs that happen to
// have written access rules would be worse than none, because it would look on.
func (f *PacketFilter) Enabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enabled || f.shields
}

// Allow decides one inbound IP packet. A packet it cannot parse is DROPPED when
// filtering is on: an unparseable packet is one whose ports we don't know, and
// guessing "allow" on the failure path is how a filter gets bypassed.
func (f *PacketFilter) Allow(pkt []byte) bool {
	if !f.Enabled() {
		return true
	}
	t, ok := parseTuple(pkt)
	if !ok {
		return false
	}
	return f.allow(t)
}

// allow applies the RULES to an already-parsed packet. Callers that also track
// established flows (filteredTUN) parse once and go through here.
func (f *PacketFilter) allow(t tuple) bool {
	f.mu.RLock()
	enabled, shields, rules := f.enabled, f.shields, f.rules
	f.mu.RUnlock()
	// The machine's own refusal outranks the org's rules — an admin's "accept"
	// is permission to try, not an obligation on the receiver to answer. Checked
	// before `enabled` so it also holds where no filter was ever compiled.
	if shields {
		return false
	}
	if !enabled {
		return true
	}
	for _, r := range rules {
		if !matchSrc(r.SrcCIDRs, t.src) {
			continue
		}
		if matchPort(r.DstPorts, t.proto, t.dstPort) {
			return true
		}
	}
	return false
}

func matchSrc(cidrs []netip.Prefix, src netip.Addr) bool {
	for _, c := range cidrs {
		if c.Contains(src) {
			return true
		}
	}
	return false
}

// matchPort reports whether any range admits this protocol+port. A rule with an
// empty Proto matches any protocol; a port of 0 (a protocol without ports, like
// ICMP, or a fragment whose header we don't have) is admitted ONLY by a
// full-range any-protocol rule — i.e. by a rule that opens everything anyway.
func matchPort(ranges []PortRange, proto uint8, port uint16) bool {
	for _, r := range ranges {
		if r.Proto != "" && r.Proto != protoName(proto) {
			continue
		}
		if port == 0 {
			if r.First == 0 && r.Last == 65535 && r.Proto == "" {
				return true
			}
			continue
		}
		if port >= r.First && port <= r.Last {
			return true
		}
	}
	return false
}

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

func protoName(p uint8) string {
	switch p {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	default:
		return ""
	}
}

// parseIP pulls the source address, L4 protocol and destination port out of an
// IPv4/IPv6 packet. Returns ok=false for anything malformed or truncated.
//
// Two cases return a port of 0 rather than failing, so they are decided by the
// rules instead of by the parser: protocols without ports (ICMP), and IPv4
// fragments after the first — a non-initial fragment carries no L4 header, and
// reassembling in the filter would mean holding attacker-controlled state.
// tuple is everything the filter and the flow table need from one IP packet.
// Both halves of a conversation parse into tuples that are exact mirrors, which
// is what lets the flow table match a reply to the packet that provoked it.
type tuple struct {
	src, dst         netip.Addr
	proto            uint8
	srcPort, dstPort uint16
}

func parseTuple(pkt []byte) (tuple, bool) {
	if len(pkt) < 1 {
		return tuple{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		return parseIPv4(pkt)
	case 6:
		return parseIPv6(pkt)
	default:
		return tuple{}, false
	}
}

func parseIPv4(pkt []byte) (tuple, bool) {
	if len(pkt) < 20 {
		return tuple{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return tuple{}, false
	}
	t := tuple{
		proto: pkt[9],
		src:   netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}),
		dst:   netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}),
	}
	// Fragment offset != 0 → no L4 header in this packet.
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return t, true
	}
	sp, dp, ok := l4Ports(pkt[ihl:], t.proto)
	if !ok {
		return tuple{}, false
	}
	t.srcPort, t.dstPort = sp, dp
	return t, true
}

func parseIPv6(pkt []byte) (tuple, bool) {
	if len(pkt) < 40 {
		return tuple{}, false
	}
	var s, d [16]byte
	copy(s[:], pkt[8:24])
	copy(d[:], pkt[24:40])
	t := tuple{proto: pkt[6], src: netip.AddrFrom16(s), dst: netip.AddrFrom16(d)}
	// Extension headers are not walked: an unrecognized next-header yields "no
	// port" (from l4DstPort's default branch), so only an open-everything rule
	// admits it. Walking them correctly — fragmentation included — is where
	// packet filters grow their own CVEs.
	//
	// A TRUNCATED tcp/udp header is a different case and is dropped, same as in
	// IPv4: we couldn't read the port, and the two families must not disagree
	// about that.
	sp, dp, ok := l4Ports(pkt[40:], t.proto)
	if !ok {
		return tuple{}, false
	}
	t.srcPort, t.dstPort = sp, dp
	return t, true
}

// l4Ports reads both ports of a TCP/UDP header. ok=false means the header is
// truncated; a protocol without ports yields (0, 0, true).
func l4Ports(rest []byte, proto uint8) (src, dst uint16, ok bool) {
	switch proto {
	case protoTCP, protoUDP:
		if len(rest) < 4 {
			return 0, 0, false
		}
		return binary.BigEndian.Uint16(rest[0:2]), binary.BigEndian.Uint16(rest[2:4]), true
	default:
		return 0, 0, true
	}
}
