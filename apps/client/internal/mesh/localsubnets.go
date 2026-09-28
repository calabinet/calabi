package mesh

import (
	"fmt"
	"net/netip"

	"github.com/calabinet/calabi/apps/client/internal/hostnet"
)

// privateV4Blocks are the IPv4 ranges an exit-node client keeps on the physical
// link instead of sending through the exit peer, so local-network access
// survives full-tunnelling (the consumer side of MESH.7b "allow LAN access").
// They cover RFC1918 private space; together with each interface's own, more
// specific, directly-connected on-link route (which wins by longest prefix on
// its own) this keeps every private destination — directly attached OR one
// router hop away via the physical gateway — off the exit tunnel.
//
// A subnet-router that advertises a MORE specific private prefix under its real
// range (e.g. a remote office's 10.99.0.0/24) still beats these /8–/16 carves by
// longest-prefix match, so mesh-reachable remote subnets keep working through
// the tun. The mesh overlay (100.64.0.0/10) is deliberately absent — it must
// flow INTO the tun. That includes the subnet-alias pool (100.96.0.0/11), so an
// aliased subnet never meets these carves at all.
// Link-local (169.254/16) is absent too: it is on-link only, never routed, so
// it never reaches the exit peer regardless.
var privateV4Blocks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// localDirectSubnets returns the directly-connected IP subnets of this host's
// physical interfaces — each interface address masked to its on-link prefix
// (e.g. 192.168.1.37/24 -> 192.168.1.0/24). The tun named excludeIfname, plus
// loopback/down interfaces and loopback/link-local addresses, are skipped, so
// the result is exactly "the LANs this machine is physically on".
//
// Used to decide which mesh-advertised subnets overlap a local network: on a
// collision the local network wins (the advertised subnet is NOT routed into the
// mesh), because the destination IP is ambiguous and hijacking the machine's own
// LAN is the worse failure. See selectSubnetRoutes (MESH.7).
func localDirectSubnets(excludeIfname string) ([]netip.Prefix, error) {
	ifaces, err := hostnet.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("mesh: list interfaces: %w", err)
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, iface := range ifaces {
		if iface.Name == excludeIfname {
			continue // never treat our own tun as a "local network"
		}
		if !iface.Up || iface.Loopback {
			continue
		}
		for _, a := range iface.Addrs {
			addr := a.Addr.Unmap()
			if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
				continue
			}
			ones := a.Bits
			if ones <= 0 {
				continue // no mask, or a /0 one: not a "local subnet"
			}
			p := netip.PrefixFrom(addr, ones).Masked()
			if !p.IsValid() || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// localSubnetWins reports whether pfx names address space this machine is
// ALREADY directly attached to — equal to a local on-link subnet, or contained
// in one. Such a route is refused: local wins.
//
// The containment half was learned the hard way. This rule used to flag only an
// EXACT same-subnet collision, on the reasoning that a more-specific
// advertisement (192.168.1.222/32 while this box is on 192.168.1.0/24) is
// resolved safely by longest-prefix match — it diverts one address and leaves
// the rest of the LAN on the wire. True about the routing table, and beside the
// point: that argument silently assumes .222 is somewhere else. In the ordinary
// home setup it is not. A subnet router sits on the same LAN and advertises the
// NAS beside it, and every machine on that LAN installs a /32 that sends
// wire-adjacent traffic into WireGuard instead. Measured 2026-09-06: the path
// out was a NAT hairpin through the ISP, so a gigabit LAN ran at 0.3 MB/s and
// the machine had even routed its OWN address (192.168.1.22/32) into the tun.
//
// What this costs, stated plainly rather than waved at. The rule cannot tell an
// address that is LIVE on our wire (the NAS above) from one that merely falls
// inside our subnet while nothing local answers for it — it refuses both, and
// the second kind has real users:
//
//   - A remote site numbered like us (the same RFC1918 /24), published whole or
//     as host routes for addresses we happen not to use.
//   - Links with client isolation (guest Wi-Fi, some APs), where two hosts share
//     a subnet and genuinely cannot reach each other, so the mesh route was the
//     only path.
//
// Subnet aliases cover both cases
// since 1.8.0, for any route that gets one. A subnet router asks for an alias on
// every route it publishes unless SubnetAliasSupport says it cannot install the
// NETMAP rewrite, and an aliased route reaches consumers ONLY as its stand-in,
// a same-size prefix from 100.96.0.0/11 that keeps the host bits: with
// 192.168.1.0/24 aliased to 100.96.5.0/24, 192.168.1.222 is dialled as
// 100.96.5.222. Stand-ins lie inside meshOverlayCIDR, which the tun's overlay
// route already carries and selectSubnetRoutes skips before asking this rule,
// so this rule never sees an alias (TestAliasPrefixesNeedNoConsumerSideChange).
//
// What remains is confined to routes that arrive under their REAL range and
// land inside a LAN we are on. A route arrives that way when:
//
//   - its router never asked for an alias: it cannot install the rewrite (not
//     Linux; no `iptables` with a working NETMAP target, e.g. nft-only hosts or
//     kernels without xt_NETMAP), it predates 1.8.0, or it is a foreground
//     `calabi mesh up` from 1.8.0 through 2.0.0, which asked for none;
//   - the coordinator had none to give: the meshnet is at its alias budget (256
//     addresses by default, which one site's /24 uses up), the pool is
//     exhausted, or the route is IPv6 (the pool is IPv4-only). The router's
//     status lists these as UnaliasedRoutes.
//
// Those fail LOUDLY here — a Warn naming the local subnet that won — rather than
// silently at a thousandth of the speed. The fix for them is not a weaker
// default, which would reopen the silent case above, but getting the route an
// alias (upgrade the router, give it iptables with NETMAP, raise the meshnet's
// alias budget) or an explicit consumer-side include list (the mirror of
// RoutePolicy.Excludes) that takes a real-range route anyway. That list does not
// exist yet; until it does, this is a capability the rule removes, and saying so
// is part of shipping it.
//
// pfx is masked first, so an unmasked advertisement (192.168.1.5/24) still
// matches the local 192.168.1.0/24. A BROADER advertisement (192.168.0.0/16
// against a local /24) is still kept: it is not covered by the local subnet, and
// longest-prefix match means it never wins for local addresses anyway.
func localSubnetWins(pfx netip.Prefix, locals []netip.Prefix) (netip.Prefix, bool) {
	m := pfx.Masked()
	for _, l := range locals {
		// l covers m: same family, no longer than m, and holding its base address.
		if l.Bits() <= m.Bits() && l.Contains(m.Addr()) {
			return l, true
		}
	}
	return netip.Prefix{}, false
}
