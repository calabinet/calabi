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
