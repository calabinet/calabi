package mesh

import (
	"fmt"
	"net/netip"
)

// The subnet-router / exit-node NAT rule builders live here (no build tag) so
// they can be unit-tested on any OS; the Linux backend (subnetrouter_linux.go)
// executes them via iptables or nft. Both MASQUERADE overlay-sourced traffic
// (meshOverlayCIDR) heading to an advertised CIDR — or, for a 0.0.0.0/0 exit
// node, to anywhere outside the overlay — so LAN / internet replies return via
// this node without the far side needing a route back to the overlay.

// iptablesMasqueradeRules returns the `iptables` arg lists (one per IPv4 route).
func iptablesMasqueradeRules(routes []netip.Prefix) [][]string {
	var rules [][]string
	for _, r := range routes {
		if !r.Addr().Is4() {
			continue // v0: IPv4 subnet routes only
		}
		if r.Bits() == 0 { // exit node (default route)
			rules = append(rules, []string{"-t", "nat", "-A", "POSTROUTING", "-s", meshOverlayCIDR, "!", "-d", meshOverlayCIDR, "-j", "MASQUERADE"})
		} else {
			rules = append(rules, []string{"-t", "nat", "-A", "POSTROUTING", "-s", meshOverlayCIDR, "-d", r.String(), "-j", "MASQUERADE"})
		}
	}
	return rules
}

// nftMasqueradeRules returns the nft rule bodies (the text after
// `add rule ip <table> postrouting`) for each IPv4 route.
func nftMasqueradeRules(routes []netip.Prefix) []string {
	var rules []string
	for _, r := range routes {
		if !r.Addr().Is4() {
			continue
		}
		if r.Bits() == 0 { // exit node
			rules = append(rules, fmt.Sprintf("ip saddr %s ip daddr != %s masquerade", meshOverlayCIDR, meshOverlayCIDR))
		} else {
			rules = append(rules, fmt.Sprintf("ip saddr %s ip daddr %s masquerade", meshOverlayCIDR, r.String()))
		}
	}
	return rules
}

// iptablesAliasRules returns the `iptables` arg lists that rewrite each alias
// prefix to its real one on the way IN — the other half of what makes an aliased
// subnet reachable, the MASQUERADE rules above being the way back out.
//
//	iptables -t nat -A PREROUTING -d 100.96.5.0/24 -j NETMAP --to 192.168.1.0/24
//
// NETMAP is a 1:1 block rewrite: it maps the network part and leaves the host
// part alone, which is exactly the alias contract (alias.222 is real.222) and
// is why no state or lookup table is involved. The reply direction needs no rule
// of its own — conntrack reverses this automatically, so the consumer sees the
// answer coming from the alias it dialled.
//
// Ordering with the MASQUERADE rules matters and is free: PREROUTING runs before
// the routing decision, so by the time POSTROUTING sees the packet its
// destination is already the real LAN address and the existing
// `-s 100.64/10 -d <real cidr>` rule matches unchanged.
func iptablesAliasRules(aliases []SubnetAlias) [][]string {
	var rules [][]string
	for _, a := range aliases {
		if !a.Alias.Addr().Is4() || !a.Real.Addr().Is4() || a.Alias.Bits() != a.Real.Bits() {
			continue // v0: IPv4, same size — anything else is not a 1:1 rewrite
		}
		rules = append(rules, []string{
			"-t", "nat", "-A", "PREROUTING",
			"-d", a.Alias.Masked().String(),
			"-j", "NETMAP", "--to", a.Real.Masked().String(),
		})
	}
	return rules
}
