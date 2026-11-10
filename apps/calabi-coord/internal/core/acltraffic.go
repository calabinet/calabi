package core

import (
	"cmp"
	"context"
	"errors"
	"net/netip"
	"slices"
	"sort"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

var ErrInvalidAccessPort = errors.New("access check needs TCP/UDP with a port from 1 to 65535, or ICMP without a port")

var aclTrafficProtocols = [...]string{"tcp", "udp", meshproto.ACLICMP, "other"}

type AccessTransport struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
	Allowed  bool   `json:"allowed"`
	Rule     int    `json:"rule"` // zero-based; -1 for default access or no match
	Reason   string `json:"reason"`
}

// ACLTrafficDiff counts changed directional ranges. The lists are capped
// independently so a long list of removals cannot hide newly allowed access.
type ACLTrafficDiff struct {
	AddedCount   int            `json:"added_count"`
	RemovedCount int            `json:"removed_count"`
	Added        []AccessChange `json:"added"`
	Removed      []AccessChange `json:"removed"`
}

type AccessChange struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
	PortRange
}

const maxAccessChanges = 200

func checkTransport(nodes []*Node, src, dst *Node, doc *ACLPolicy, live bool, target *AccessTransport) {
	switch {
	case src.ID == dst.ID:
		target.Reason = "same_device"
		return
	case src.Disabled || dst.Disabled:
		target.Reason = "disabled"
		return
	case !src.Approved || !dst.Approved:
		target.Reason = "pending"
		return
	}
	target.Reason = "no_match"
	if !src.Overlay.IsValid() {
		return
	}
	peers := accessPeers(safeRealRoutes(nodes), dst, doc)
	if hasACLAction(doc, "deny") {
		denyPeers := peers
		if !reachable(doc, src, dst) {
			// An explicit denial can still explain a refusal where no allow
			// rule makes this pair visible to each other.
			denyPeers = append(denyPeers, src)
		}
		visitACLRules(dst, denyPeers, doc, "deny", func(index int, rule FilterRule) bool {
			if allowsTransport(rule, src.Overlay, target) {
				target.Rule, target.Reason = index, "explicit_deny"
				return false
			}
			return true
		})
		if target.Rule >= 0 {
			return
		}
	}
	if !reachable(doc, src, dst) {
		return
	}
	filter, err := compileEffectiveFilter(dst, peers, doc)
	if err != nil {
		return
	}
	if live && !slices.ContainsFunc(filter, func(rule FilterRule) bool {
		if !filterIncludesAddr(rule, src.Overlay) {
			return false
		}
		return slices.ContainsFunc(rule.DstPorts, func(span PortRange) bool {
			return supportsACLRange(dst, span) && matchesTransport(span, target)
		})
	}) {
		return
	}
	visitPacketFilterRules(dst, peers, doc, func(index int, rule FilterRule) bool {
		if allowsTransport(rule, src.Overlay, target) {
			target.Allowed, target.Rule = true, index
			target.Reason = "rule"
			if index < 0 {
				target.Reason = "default"
			}
			return false
		}
		return true
	})
}

func allowsTransport(rule FilterRule, addr netip.Addr, target *AccessTransport) bool {
	if !filterIncludesAddr(rule, addr) {
		return false
	}
	return slices.ContainsFunc(rule.DstPorts, func(span PortRange) bool {
		return matchesTransport(span, target)
	})
}

func matchesTransport(span PortRange, target *AccessTransport) bool {
	if target.Protocol == meshproto.ACLICMP {
		return span == allPorts() || span.Proto == meshproto.ACLICMP || span.Proto == meshproto.ACLPortless
	}
	return (span.Proto == "" || span.Proto == target.Protocol) && span.First <= target.Port && target.Port <= span.Last
}

func filterIncludesAddr(rule FilterRule, addr netip.Addr) bool {
	for _, cidr := range rule.SrcCIDRs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func accessPeers(nodes []*Node, dst *Node, doc *ACLPolicy) []*Node {
	var peers []*Node
	for _, src := range nodes {
		if src.ID != dst.ID && src.Approved && !src.Disabled && reachable(doc, src, dst) {
			peers = append(peers, src)
		}
	}
	return peers
}

// Index host prefixes once per receiver. Scanning every other device's host
// prefix again for each source would make an all-to-all preview cubic.
type accessPortIndex struct {
	hosts    map[netip.Addr][]PortRange
	networks map[netip.Prefix][]PortRange
	visible  map[int64]bool
}

func indexAccessPorts(nodes []*Node, dst *Node, doc *ACLPolicy, live bool) (accessPortIndex, error) {
	peers := accessPeers(nodes, dst, doc)
	rules, err := compileEffectiveFilter(dst, peers, doc)
	if err != nil && !live {
		return accessPortIndex{}, err
	}
	out := accessPortIndex{
		hosts:    make(map[netip.Addr][]PortRange),
		networks: make(map[netip.Prefix][]PortRange),
		visible:  make(map[int64]bool, len(peers)),
	}
	for _, peer := range peers {
		out.visible[peer.ID] = true
	}
	for _, rule := range rules {
		if live && slices.ContainsFunc(rule.DstPorts, func(span PortRange) bool { return !supportsACLRange(dst, span) }) {
			rule.DstPorts = slices.DeleteFunc(slices.Clone(rule.DstPorts), func(span PortRange) bool {
				return !supportsACLRange(dst, span)
			})
		}
		for _, cidr := range rule.SrcCIDRs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			if prefix.IsSingleIP() {
				out.hosts[prefix.Addr()] = append(out.hosts[prefix.Addr()], rule.DstPorts...)
			} else {
				out.networks[prefix] = append(out.networks[prefix], rule.DstPorts...)
			}
		}
	}
	return out, nil
}

func (i accessPortIndex) ranges(src *Node) []PortRange {
	if !i.visible[src.ID] || !src.Overlay.IsValid() {
		return nil
	}
	ranges := append([]PortRange(nil), i.hosts[src.Overlay]...)
	for prefix, spans := range i.networks {
		if prefix.Contains(src.Overlay) {
			ranges = append(ranges, spans...)
		}
	}
	return ranges
}

func diffACLTraffic(ctx context.Context, nodes []*Node, before, after *ACLPolicy) (*ACLTrafficDiff, error) {
	nodes = safeRealRoutes(nodes)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	out := &ACLTrafficDiff{Added: []AccessChange{}, Removed: []AccessChange{}}
	for _, dst := range nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if dst.Disabled || !dst.Approved {
			continue
		}
		oldPorts, _ := indexAccessPorts(nodes, dst, before, true)
		newPorts, err := indexAccessPorts(nodes, dst, after, false)
		if err != nil {
			return nil, err
		}
		for _, src := range nodes {
			oldRanges, newRanges := oldPorts.ranges(src), newPorts.ranges(src)
			for _, protocol := range aclTrafficProtocols {
				old := unionAccessRanges(oldRanges, protocol)
				next := unionAccessRanges(newRanges, protocol)
				appendAccessChanges(src, dst, subtractAccessRanges(next, old), &out.Added, &out.AddedCount)
				appendAccessChanges(src, dst, subtractAccessRanges(old, next), &out.Removed, &out.RemovedCount)
			}
		}
	}
	return out, nil
}

func appendAccessChanges(src, dst *Node, spans []PortRange, changes *[]AccessChange, count *int) {
	*count += len(spans)
	for _, span := range spans {
		if len(*changes) == maxAccessChanges {
			break
		}
		*changes = append(*changes, AccessChange{Src: src.Name, Dst: dst.Name, PortRange: span})
	}
}

// Split ICMP from other portless protocols so a rule can change just one.
func unionAccessRanges(ranges []PortRange, protocol string) []PortRange {
	var spans []PortRange
	for _, span := range ranges {
		if protocol == "other" || protocol == meshproto.ACLICMP {
			if span == allPorts() || span.Proto == meshproto.ACLPortless ||
				(protocol == "other" && span.Proto == meshproto.ACLNonICMPPortless) ||
				(protocol == meshproto.ACLICMP && span.Proto == meshproto.ACLICMP) {
				return []PortRange{{Proto: protocol}}
			}
			continue
		}
		if span.Proto == "" || span.Proto == protocol {
			span.Proto = protocol
			span.First = max(span.First, 1)
			spans = append(spans, span)
		}
	}
	slices.SortFunc(spans, func(a, b PortRange) int { return cmp.Compare(a.First, b.First) })
	merged := spans[:0]
	for _, span := range spans {
		if n := len(merged); n > 0 && int(span.First) <= int(merged[n-1].Last)+1 {
			merged[n-1].Last = max(merged[n-1].Last, span.Last)
		} else {
			merged = append(merged, span)
		}
	}
	return merged
}

func subtractAccessRanges(allowed, excluded []PortRange) []PortRange {
	var out []PortRange
	for _, span := range allowed {
		start, end := int(span.First), int(span.Last)
		for len(excluded) > 0 && int(excluded[0].Last) < start {
			excluded = excluded[1:]
		}
		for _, cut := range excluded {
			if int(cut.First) > end {
				break
			}
			if start < int(cut.First) {
				out = append(out, PortRange{First: uint16(start), Last: cut.First - 1, Proto: span.Proto})
			}
			start = max(start, int(cut.Last)+1)
			if start > end {
				break
			}
		}
		if start <= end {
			out = append(out, PortRange{First: uint16(start), Last: span.Last, Proto: span.Proto})
		}
	}
	return out
}
