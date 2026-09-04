package core

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Compiling the meshnet's ACL into a per-node PACKET FILTER (MESH.5b) — the step
// that makes "who can reach what" mean ports rather than hosts.
//
// Two properties matter more than the code:
//
//  1. It is compiled PER RECEIVING NODE and enforced by that node on INBOUND
//     traffic. The receiver is the only party whose refusal can't be talked out
//     of: a sender that is compromised, or simply running an old netmap, still
//     hits the receiver's own copy of the rules. (Same stance as the edge's
//     server-authoritative policy.)
//  2. The ports come from the rule's own `ports` field: a literal (`5432`) or a
//     reference to the RECEIVING node's declared service (`svc:web` → whatever
//     port THAT node declared for "web"). That is what the declaration in the
//     console is finally worth: the rule names a service and the filter knows
//     the number, while WHICH machines are in scope stays an admin's choice in
//     `dst`.
//
// The netmap layer (which peers you can see at all) stays as it was; this is a
// second, narrower gate behind it.

// PortRange is an inclusive span for one protocol. Proto is "tcp", "udp", or ""
// for any.
type PortRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
	Proto string `json:"proto"`
}

// FilterRule allows any source in SrcCIDRs to reach any of DstPorts on the
// node the filter was compiled for.
type FilterRule struct {
	SrcCIDRs []string    `json:"src_cidrs"`
	DstPorts []PortRange `json:"dst_ports"`
}

// allPorts is the "any port, any protocol" span.
func allPorts() PortRange { return PortRange{First: 0, Last: 65535} }

// CompilePacketFilter builds the inbound filter for `self` from the meshnet's
// policy. A nil policy is the allow-all default (no stored doc) and compiles to
// a single "everything from everywhere" rule, so a meshnet that has never
// written rules behaves exactly as it does today.
//
// Sources are the OVERLAY addresses of the peers a rule's src selectors match,
// plus those peers' advertised subnet routes — traffic forwarded by a subnet
// router arrives with the LAN address as its source, so leaving those out would
// silently break MESH.7 routing the moment a filter is applied.
func CompilePacketFilter(self *Node, peers []*Node, p *ACLPolicy) []FilterRule {
	if self == nil {
		return nil
	}
	if p == nil {
		return []FilterRule{{SrcCIDRs: []string{"0.0.0.0/0", "::/0"}, DstPorts: []PortRange{allPorts()}}}
	}
	var out []FilterRule
	for _, r := range p.ACLs {
		if !strings.EqualFold(strings.TrimSpace(r.Action), "accept") {
			continue
		}
		if len(r.Ports) > 0 {
			out = appendIf(out, compileRule(r, self, peers, p.Groups))
			continue
		}
		// Legacy document (no Ports field): each dst selector carried its own
		// port(s), so they compile separately. Kept so docs stored before the
		// split keep enforcing exactly what they enforced yesterday — the write
		// path refuses this shape, the read path never does.
		for _, dsel := range r.Dst {
			if !matchSelector(dsel, self, p.Groups) {
				continue
			}
			ports := portsForSelector(dsel, self)
			if len(ports) == 0 {
				continue
			}
			srcs := sourceCIDRs(r.Src, peers, p.Groups)
			if len(srcs) == 0 {
				continue // a rule whose sources match nobody grants nothing
			}
			out = append(out, FilterRule{SrcCIDRs: srcs, DstPorts: ports})
		}
	}
	return out
}

// compileRule builds the one filter rule a current-format ACL rule contributes
// to self, or nil when it contributes nothing (self isn't a destination, no
// source matches, or the ports resolve to nothing on this machine).
func compileRule(r ACLRule, self *Node, peers []*Node, groups map[string][]string) *FilterRule {
	if !matchAny(r.Dst, self, groups) {
		return nil
	}
	ports := resolvePorts(r.Ports, self)
	if len(ports) == 0 {
		// Reached when the rule opens "svc:x" and self declares no confirmed x.
		// Correct: a machine not offering the service opens nothing for it.
		return nil
	}
	srcs := sourceCIDRs(r.Src, peers, groups)
	if len(srcs) == 0 {
		return nil
	}
	return &FilterRule{SrcCIDRs: srcs, DstPorts: ports}
}

func appendIf(out []FilterRule, r *FilterRule) []FilterRule {
	if r == nil {
		return out
	}
	return append(out, *r)
}

// resolvePorts turns a rule's port specs into concrete ranges ON self. Specs
// that name a service resolve against self's own declarations, so one rule can
// cover machines that each chose a different port.
func resolvePorts(specs []string, self *Node) []PortRange {
	var out []PortRange
	for _, spec := range specs {
		out = append(out, portsForSpec(spec, self)...)
	}
	return out
}

// portsForSpec resolves one port spec against self. Unparseable specs resolve to
// nothing rather than to everything — the write path rejects them, so reaching
// here means a hand-edited document, and the safe reading of a spec we cannot
// understand is "grants no port".
func portsForSpec(spec string, self *Node) []PortRange {
	s, ok := parsePortSpec(spec)
	if !ok {
		return nil
	}
	if s.service == "" {
		return []PortRange{{First: s.first, Last: s.last, Proto: s.proto}}
	}
	var out []PortRange
	for _, svc := range self.Services {
		if svc.Name == s.service && svc.Port > 0 && svc.Port <= 65535 {
			out = append(out, PortRange{First: uint16(svc.Port), Last: uint16(svc.Port), Proto: svc.Proto})
		}
	}
	return out
}

// portSpec is a parsed Ports entry: either a literal range (service == "") or a
// reference to a service declared by the receiving node.
type portSpec struct {
	proto       string // "", "tcp" or "udp"
	first, last uint16
	service     string
}

// parsePortSpec accepts, case-insensitively:
//
//	"*"           every port, every protocol
//	"443"         one port, any protocol
//	"8000-8100"   an inclusive range, any protocol
//	"tcp:443"     one port, TCP only (also "udp:53", "tcp:8000-8100", "tcp:*")
//	"svc:<name>"  the receiving node's own declared port(s) for that service,
//	              with the protocol it declared
//
// It is the single definition of the spelling: validation and compilation both
// call it, so a spec that saves is a spec that compiles.
func parsePortSpec(spec string) (portSpec, bool) {
	s := strings.ToLower(strings.TrimSpace(spec))
	if s == "" {
		return portSpec{}, false
	}
	if name, ok := strings.CutPrefix(s, "svc:"); ok {
		// Service names are labels (ValidateService), so anything else could
		// never match a declaration. Catching it here turns a typo into a save
		// error instead of a rule that quietly opens no port.
		name = NormalizeNodeName(name)
		if ValidateNodeName(name) != nil {
			return portSpec{}, false
		}
		return portSpec{service: name}, true
	}
	out := portSpec{}
	for _, proto := range []string{"tcp", "udp"} {
		if rest, ok := strings.CutPrefix(s, proto+":"); ok {
			out.proto = proto
			s = strings.TrimSpace(rest)
			break
		}
	}
	if s == "*" {
		out.first, out.last = 0, 65535
		return out, true
	}
	lo, hi, isRange := strings.Cut(s, "-")
	first, ok := parsePortNumber(lo)
	if !ok {
		return portSpec{}, false
	}
	last := first
	if isRange {
		if last, ok = parsePortNumber(hi); !ok || last < first {
			return portSpec{}, false
		}
	}
	out.first, out.last = first, last
	return out, true
}

func parsePortNumber(s string) (uint16, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}

// portsForSelector resolves what a dst selector opens ON self, for LEGACY
// documents only (rules with no `ports` field). New rules never reach it.
//   - "host:443" / "tag:x:443" → that one port (any protocol)
//   - "svc:web"                → the ports self declared for the service "web",
//     with the service's protocol. A node that doesn't declare it opens nothing.
//   - anything else            → every port (the selector names a host, not a service)
func portsForSelector(sel string, self *Node) []PortRange {
	sel = strings.TrimSpace(sel)
	if port, ok := trailingPort(sel); ok {
		return []PortRange{{First: port, Last: port}}
	}
	if name, ok := strings.CutPrefix(sel, "svc:"); ok {
		var out []PortRange
		for _, s := range self.Services {
			if s.Name == name && s.Port > 0 && s.Port <= 65535 {
				out = append(out, PortRange{First: uint16(s.Port), Last: uint16(s.Port), Proto: s.Proto})
			}
		}
		return out
	}
	return []PortRange{allPorts()}
}

// trailingPort extracts a ":<port>" suffix (see stripSelectorPort, which decides
// the same way).
func trailingPort(sel string) (uint16, bool) {
	i := strings.LastIndexByte(sel, ':')
	if i <= 0 || i == len(sel)-1 {
		return 0, false
	}
	n, err := strconv.Atoi(sel[i+1:])
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}

// sourceCIDRs turns src selectors into the concrete addresses traffic may come
// from: each matching peer's overlay /32 plus the subnet routes it advertises.
// A "*" selector short-circuits to everything — the common "any node" rule
// shouldn't compile into a list that grows with the meshnet.
func sourceCIDRs(sels []string, peers []*Node, groups map[string][]string) []string {
	for _, s := range sels {
		if strings.TrimSpace(s) == "*" {
			return []string{"0.0.0.0/0", "::/0"}
		}
	}
	seen := map[string]bool{}
	var out []string
	add := func(cidr string) {
		if cidr != "" && !seen[cidr] {
			seen[cidr] = true
			out = append(out, cidr)
		}
	}
	for _, peer := range peers {
		if peer == nil || peer.Disabled || !matchAny(sels, peer, groups) {
			continue
		}
		if peer.Overlay.IsValid() {
			add(hostCIDR(peer.Overlay))
		}
		for _, r := range peer.AdvertisedRoutes {
			add(r.String())
		}
	}
	sort.Strings(out)
	return out
}

func hostCIDR(a netip.Addr) string {
	if a.Is4() {
		return a.String() + "/32"
	}
	return a.String() + "/128"
}

// PacketFilterFor compiles the inbound filter for one node of a meshnet, using
// the same node+service data and the same live policy as the netmap it ships
// with.
func (c *Coordinator) packetFilterFor(self *Node, peers []*Node, doc *ACLPolicy) []FilterRule {
	return CompilePacketFilter(self, peers, doc)
}
