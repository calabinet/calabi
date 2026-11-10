package core

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

func isACLAction(rule ACLRule, action string) bool {
	return strings.EqualFold(strings.TrimSpace(rule.Action), action)
}

func hasACLAction(p *ACLPolicy, action string) bool {
	return p != nil && slices.ContainsFunc(p.ACLs, func(r ACLRule) bool { return isACLAction(r, action) })
}

func hasFullMeshAllow(p *ACLPolicy) bool {
	hasWildcard := func(items []string) bool {
		return slices.ContainsFunc(items, func(s string) bool { return strings.TrimSpace(s) == "*" })
	}
	return slices.ContainsFunc(p.ACLs, func(rule ACLRule) bool {
		return isACLAction(rule, "accept") && hasWildcard(rule.Src) && hasWildcard(rule.Dst) &&
			(len(rule.Ports) == 0 || hasWildcard(rule.Ports))
	})
}

type deniedPrefix struct {
	prefix netip.Prefix
	ports  []PortRange
}

// Bound expansion per receiver. Save and preview report this error. If a
// later topology change hits the limit, netmap emits an enabled empty filter.
const (
	maxDenyFilterParts = 4096
	maxDenyFilterSpans = 16384
)

func subtractDenyRules(allowed []FilterRule, self *Node, peers []*Node, doc *ACLPolicy) ([]FilterRule, error) {
	if len(allowed) == 0 || !hasACLAction(doc, "deny") {
		return allowed, nil
	}
	var denied []deniedPrefix
	visitACLRules(self, peers, doc, "deny", func(_ int, rule FilterRule) bool {
		for _, cidr := range rule.SrcCIDRs {
			if prefix, err := netip.ParsePrefix(cidr); err == nil {
				denied = append(denied, deniedPrefix{prefix.Masked(), rule.DstPorts})
				if len(denied) > maxDenyFilterParts {
					return false
				}
			}
		}
		return true
	})
	if len(denied) == 0 {
		return allowed, nil
	}
	if len(denied) > maxDenyFilterParts {
		return nil, fmt.Errorf("too many denied source ranges for device %q", self.Name)
	}
	var out []FilterRule
	parts, spans := 0, 0
	for _, rule := range allowed {
		// Many sibling prefixes share the same surviving ports. Group them
		// within this rule to keep the packet filter small.
		start := len(out)
		for _, cidr := range rule.SrcCIDRs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			ok := partitionAccess(prefix.Masked(), rule.DstPorts, denied, func(prefix netip.Prefix, ports []PortRange) bool {
				parts++
				if parts > maxDenyFilterParts {
					return false
				}
				groups := out[start:]
				for i := range groups {
					if slices.Equal(groups[i].DstPorts, ports) {
						groups[i].SrcCIDRs = append(groups[i].SrcCIDRs, prefix.String())
						return true
					}
				}
				spans += len(ports)
				if spans > maxDenyFilterSpans {
					return false
				}
				out = append(out, FilterRule{SrcCIDRs: []string{prefix.String()}, DstPorts: ports})
				return true
			})
			if !ok {
				return nil, fmt.Errorf("access rules expand to too many address or port ranges for device %q", self.Name)
			}
		}
	}
	return out, nil
}

// Recurse only into address prefixes that contain a narrower denial. A denial
// that covers the current prefix applies to both of its children.
func partitionAccess(prefix netip.Prefix, ports []PortRange, denied []deniedPrefix, emit func(netip.Prefix, []PortRange) bool) bool {
	var nested []deniedPrefix
	var excluded []PortRange
	for _, deny := range denied {
		if !prefix.Overlaps(deny.prefix) {
			continue
		}
		if deny.prefix.Bits() <= prefix.Bits() {
			excluded = append(excluded, deny.ports...)
		} else {
			nested = append(nested, deny)
		}
	}
	if len(excluded) > 0 {
		ports = subtractPortPermissions(ports, excluded)
	}
	if len(ports) == 0 {
		return true
	}
	if len(nested) == 0 {
		return emit(prefix, ports)
	}
	bit := prefix.Bits()
	low := netip.PrefixFrom(prefix.Addr(), bit+1)
	bytes := prefix.Addr().AsSlice()
	bytes[bit/8] |= 0x80 >> (bit % 8)
	addr, _ := netip.AddrFromSlice(bytes)
	high := netip.PrefixFrom(addr, bit+1)
	return partitionAccess(low, ports, nested, emit) && partitionAccess(high, ports, nested, emit)
}

func subtractPortPermissions(allowed, denied []PortRange) []PortRange {
	var out []PortRange
	changed := false
	var icmp, other bool
	for _, protocol := range aclTrafficProtocols {
		before := unionAccessRanges(allowed, protocol)
		after := subtractAccessRanges(before, unionAccessRanges(denied, protocol))
		changed = changed || !slices.Equal(before, after)
		switch protocol {
		case meshproto.ACLICMP:
			icmp = len(after) > 0
		case "other":
			other = len(after) > 0
		default:
			out = append(out, after...)
		}
	}
	if !changed {
		return allowed
	}
	switch {
	case icmp && other:
		out = append(out, PortRange{Proto: meshproto.ACLPortless})
	case icmp:
		out = append(out, PortRange{Proto: meshproto.ACLICMP})
	case other:
		out = append(out, PortRange{Proto: meshproto.ACLNonICMPPortless})
	}
	return out
}

func supportsACLRange(dst *Node, span PortRange) bool {
	switch span.Proto {
	case meshproto.ACLPortless:
		return dst.ACLPortless != nil && *dst.ACLPortless
	case meshproto.ACLICMP, meshproto.ACLNonICMPPortless:
		return dst.ACLICMP != nil && *dst.ACLICMP
	default:
		return true
	}
}

func hasICMPRule(doc *ACLPolicy) bool {
	return doc != nil && slices.ContainsFunc(doc.ACLs, func(rule ACLRule) bool {
		return slices.ContainsFunc(rule.Ports, func(spec string) bool {
			return strings.EqualFold(strings.TrimSpace(spec), meshproto.ACLICMP)
		})
	})
}

func incompatibleACLDevices(ctx context.Context, nodes []*Node, doc *ACLPolicy) ([]string, error) {
	nodes = safeRealRoutes(nodes)
	var incompatible []string
	for _, dst := range nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if dst.Disabled || !dst.Approved {
			continue
		}
		peers := accessPeers(nodes, dst, doc)
		filter, err := compileEffectiveFilter(dst, peers, doc)
		if err != nil {
			return nil, err
		}
		blocked := slices.ContainsFunc(filter, func(rule FilterRule) bool {
			return slices.ContainsFunc(rule.DstPorts, func(span PortRange) bool { return !supportsACLRange(dst, span) })
		})
		if !blocked && !supportsACLRange(dst, PortRange{Proto: meshproto.ACLICMP}) {
			// Older flow trackers can mistake a new echo request for a reply.
			visitACLRules(dst, peers, doc, "deny", func(_ int, rule FilterRule) bool {
				blocked = slices.ContainsFunc(rule.DstPorts, func(span PortRange) bool { return span.Proto == meshproto.ACLICMP })
				return !blocked
			})
		}
		if blocked {
			incompatible = append(incompatible, dst.Name)
		}
	}
	slices.Sort(incompatible)
	return incompatible, nil
}
