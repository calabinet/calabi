package mesh

import (
	"fmt"
	"net"
	"net/netip"
)

// privateV4Blocks are the IPv4 ranges an exit-node client keeps on the physical
// link instead of sending through the exit peer, so local-network access
// survives full-tunnelling (the consumer side of MESH.7b "allow LAN access").
// They cover RFC1918 private space; together with each interface's own, more
// specific, directly-connected on-link route (which wins by longest prefix on
// its own) this keeps every private destination — directly attached OR one
// router hop away via the physical gateway — off the exit tunnel.
//
// A subnet-router that advertises a MORE specific private prefix (e.g. a remote
// office 10.99.0.0/16) still beats these /8–/16 carves by longest-prefix match,
// so mesh-reachable remote subnets keep working through the tun. The mesh
// overlay (100.64.0.0/10) is deliberately absent — it must flow INTO the tun.
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
// LAN is the worse failure. See selectSubnetRoutes and (MESH.7).
func localDirectSubnets(excludeIfname string) ([]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("mesh: list interfaces: %w", err)
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, iface := range ifaces {
		if iface.Name == excludeIfname {
			continue // never treat our own tun as a "local network"
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
				continue
			}
			ones, _ := ipn.Mask.Size()
			if ones == 0 {
				continue // a /0 address mask is not a "local subnet"
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

// exactLocalCollision reports whether pfx is the SAME subnet as one of the local
// networks (identical base and length) — the ONLY overlap that would hijack the
// whole local network if routed into the mesh, and the only one that is
// genuinely ambiguous (a routing-metric tie between two equal-length prefixes).
//
// It deliberately does NOT flag more-specific or broader overlaps: those are
// resolved safely by longest-prefix match. A more-specific advertised route (a
// remote host 192.168.1.222/32 while this box is on 192.168.1.0/24) only diverts
// that exact sub-range into the mesh and leaves the rest of the local subnet on
// the physical link — that is a deliberate, approved host advertisement and must
// keep working. A broader advertised route (192.168.0.0/16) never wins over the
// local /24 for local addresses at all. pfx is masked first so an unmasked
// advertisement (192.168.1.5/24) still matches the local 192.168.1.0/24.
func exactLocalCollision(pfx netip.Prefix, locals []netip.Prefix) (netip.Prefix, bool) {
	m := pfx.Masked()
	for _, l := range locals {
		if m == l {
			return l, true
		}
	}
	return netip.Prefix{}, false
}
