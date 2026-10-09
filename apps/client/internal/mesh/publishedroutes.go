package mesh

import (
	"net/netip"
	"sort"
	"strings"
)

// selfPublishedRoutes is what the coordinator currently routes to THIS node,
// named by the prefixes the node itself advertised: its own netmap entry's
// allowed-ips, minus its overlay address, with every stand-in prefix turned back
// into the route it stands in for.
//
// It is the only way a node learns that a route it advertised is actually live.
// Advertising is a claim; the coordinator publishes it once it is approved, and
// on the platform that means an admin. Until then the node's configuration says
// "192.168.1.0/24" exactly as it will afterwards, and nobody can reach it —
// which is the state this exists to make visible on the machine that asked.
//
// The answer was on the wire all along. A coordinator builds the self entry with
// the same function as a peer entry, so its allowed-ips have carried the approved
// routes since routes needed approving; nothing new has to be sent, and it holds
// for every coordinator a current client can talk to.
//
// An alias is mapped back through SubnetAliases because that is the form this
// node's operator knows the route by: they typed the real CIDR, and "is it
// published" is a question about the thing they typed.
func selfPublishedRoutes(nm NetMap) []netip.Prefix {
	realOf := make(map[netip.Prefix]netip.Prefix, len(nm.SubnetAliases))
	for _, a := range nm.SubnetAliases {
		realOf[a.Alias.Masked()] = a.Real.Masked()
	}
	seen := make(map[netip.Prefix]bool, len(nm.Self.AllowedIPs))
	var out []netip.Prefix
	for _, aip := range nm.Self.AllowedIPs {
		p := aip.Masked()
		if p.IsSingleIP() && p.Addr() == nm.Self.Overlay {
			continue // the node's own address, not a route it offers
		}
		if real, ok := realOf[p]; ok {
			p = real
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// unpublishedRoutes is what this node advertises and the coordinator does not
// route to it: advertised minus published.
func unpublishedRoutes(advertised, published []netip.Prefix) []netip.Prefix {
	live := make(map[netip.Prefix]bool, len(published))
	for _, p := range published {
		live[p.Masked()] = true
	}
	var out []netip.Prefix
	for _, r := range advertised {
		if !live[r.Masked()] {
			out = append(out, r.Masked())
		}
	}
	return out
}

// routesFingerprint identifies a set of prefixes, so the netmap callback logs
// the waiting routes when the set CHANGES rather than on every re-push.
func routesFingerprint(rs []netip.Prefix) string {
	if len(rs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		parts = append(parts, r.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
