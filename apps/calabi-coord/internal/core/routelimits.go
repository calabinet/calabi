package core

import "net/netip"

// How wide a subnet route a node may publish.
//
// Deliberately a second, independent copy of the rule the client enforces in
// apps/client/internal/mesh/routespec.go. The client's copy exists so the person
// typing a route gets told immediately and precisely; THIS one exists because
// the alias pool is a resource shared across every meshnet on the platform, and
// a limit that only lives in the client is a limit any client can decline to
// have. Keep the two in step: the constant below and AdvertiseMinBitsV4.

// advertiseMinBitsV4 is the widest IPv4 route accepted: a /24 (256 addresses,
// exactly the default per-meshnet alias budget). A /16 would need 65,536 — it
// could never be granted an alias, so before this rule it was accepted and then
// silently published under its real CIDR, i.e. back into the collision aliases
// exist to prevent.
//
// IPv6 is not limited: the alias pool is IPv4-only and no v6 route is aliased.
const advertiseMinBitsV4 = 24

// routeTooBroad reports whether p may not be published for being wider than a
// /24.
func routeTooBroad(p netip.Prefix) bool {
	return p.Addr().Is4() && p.Bits() < advertiseMinBitsV4
}

// splitAdvertised divides what a node claims into what it may publish and what
// is refused for being too broad.
//
// Refusing the ROUTE and not the registration is the whole point: a node with
// one over-wide route is still a node, and dropping it off the mesh entirely
// (its overlay address, its peer-to-peer traffic, its other routes) to punish a
// netmask would be a far worse trade than declining the one route. The caller
// logs what it refused; the client's own copy of this rule is what tells the
// operator, at the moment they type it.
func splitAdvertised(routes []netip.Prefix) (keep, refused []netip.Prefix) {
	for _, p := range routes {
		m := p.Masked()
		if routeTooBroad(m) {
			refused = append(refused, m)
			continue
		}
		keep = append(keep, m)
	}
	return keep, refused
}
