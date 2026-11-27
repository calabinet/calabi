package core

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"strings"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// RemoteLoginGrant is directional for the recipient of a netmap.
type RemoteLoginGrant struct {
	ToPeer, FromPeer []uint32
}

func remoteLoginFor(self *Node, peers []*Node, doc *ACLPolicy) map[int64]RemoteLoginGrant {
	if doc == nil {
		return nil
	}
	var grants map[int64]RemoteLoginGrant
	for _, peer := range peers {
		to, from := remoteLoginPorts(self, peer, doc), remoteLoginPorts(peer, self, doc)
		if len(to)+len(from) == 0 {
			continue
		}
		if grants == nil {
			grants = make(map[int64]RemoteLoginGrant)
		}
		grants[peer.ID] = RemoteLoginGrant{ToPeer: to, FromPeer: from}
	}
	return grants
}

func remoteLoginPorts(src, dst *Node, doc *ACLPolicy) []uint32 {
	service, standard := meshproto.RemoteLoginService(dst.OS)
	if doc == nil || standard == 0 || src.OwnerUserID <= 0 || sameOwner(src, dst) || src.SignedOut || dst.SignedOut ||
		!src.Approved || !dst.Approved || src.Disabled || dst.Disabled ||
		(dst.BlockIncoming != nil && *dst.BlockIncoming) {
		return nil
	}
	account := userPrefix + strconv.FormatInt(src.OwnerUserID, 10)
	var ports []uint32
	for _, rule := range doc.ACLs {
		// A login grant names the source account and receiving device.
		if !strings.EqualFold(rule.Action, "accept") ||
			!slices.ContainsFunc(rule.Dst, func(sel string) bool { return strings.TrimSpace(sel) == deviceSelector(dst) }) ||
			!matchesRemoteLoginAccount(account, rule.Src, doc.Groups) {
			continue
		}
		for _, spec := range rule.Ports {
			parsed, ok := parsePortSpec(spec)
			if !ok || (parsed.service != "" && parsed.service != service) {
				continue
			}
			for _, span := range portsForSpec(spec, dst) {
				if span.First == 0 || span.First != span.Last || (span.Proto != "" && span.Proto != "tcp") {
					continue
				}
				port := uint32(span.First)
				if span.First != standard && !slices.ContainsFunc(dst.Services, func(s Service) bool {
					return s.Name == service && s.Proto == "tcp" && uint32(s.Port) == port
				}) {
					continue
				}
				if !remoteLoginDenied(src, dst, doc, span.First) {
					ports = append(ports, port)
				}
			}
		}
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}

// Preview the same directional grants placed on the netmap. A broad ACL can
// already allow the TCP port while an edit changes only the login grant.
func diffRemoteLogin(ctx context.Context, nodes []*Node, before, after *ACLPolicy) (*ACLTrafficDiff, error) {
	ordered := slices.Clone(nodes)
	slices.SortFunc(ordered, func(a, b *Node) int { return cmp.Compare(a.ID, b.ID) })
	out := &ACLTrafficDiff{Added: []AccessChange{}, Removed: []AccessChange{}}
	for _, dst := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, standard := meshproto.RemoteLoginService(dst.OS); standard == 0 {
			continue
		}
		for _, src := range ordered {
			if src.ID == dst.ID {
				continue
			}
			old := remoteLoginPorts(src, dst, before)
			next := remoteLoginPorts(src, dst, after)
			appendRemoteLoginChanges(src, dst, next, old, &out.Added, &out.AddedCount)
			appendRemoteLoginChanges(src, dst, old, next, &out.Removed, &out.RemovedCount)
		}
	}
	return out, nil
}

func appendRemoteLoginChanges(src, dst *Node, allowed, previous []uint32, changes *[]AccessChange, count *int) {
	for _, port := range allowed {
		if _, exists := slices.BinarySearch(previous, port); !exists {
			appendAccessChanges(src, dst, []PortRange{{Proto: "tcp", First: uint16(port), Last: uint16(port)}}, changes, count)
		}
	}
}

func matchesRemoteLoginAccount(account string, sources []string, groups map[string][]string) bool {
	match := func(sel string) bool { return strings.TrimSpace(sel) == account }
	return slices.ContainsFunc(sources, func(sel string) bool {
		sel = strings.TrimSpace(sel)
		return match(sel) || strings.HasPrefix(sel, "group:") && slices.ContainsFunc(groups[sel], match)
	})
}

func remoteLoginDenied(src, dst *Node, doc *ACLPolicy, port uint16) bool {
	target := AccessTransport{Protocol: "tcp", Port: port}
	for _, rule := range doc.ACLs {
		if strings.EqualFold(rule.Action, "deny") && matchAny(rule.Src, src, doc.Groups) &&
			matchDst(rule.Dst, src, dst, doc.Groups) &&
			slices.ContainsFunc(resolvePorts(rule.Ports, dst), func(span PortRange) bool {
				return matchesTransport(span, &target)
			}) {
			return true
		}
	}
	return false
}
