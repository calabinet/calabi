package core

import (
	"log/slog"
	"net/netip"
)

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

// routeInOverlaySpace reports whether p lands inside the mesh's OWN address
// space (100.64.0.0/10 — node overlays and the subnet-alias pool alike).
//
// Nothing legitimate advertises these: they are addresses the coordinator
// hands out, not a network anyone's router serves. Left unchecked they were an
// interception primitive (audit finding MESH-1): a member could advertise a
// colleague's overlay /32 as a "subnet route" — narrow enough to pass the
// width limit, auto-approved because the node had never been reviewed — and
// every peer's netmap then carried that prefix under TWO peers. WireGuard
// allowed-ips are exclusive and the client writes peers in public-key order,
// so an attacker who grinds a key sorting after the victim's takes ownership
// of the victim's address on every consumer: their traffic arrives at the
// attacker, who can also answer as the victim.
//
// Refused rather than merely left unapproved, because there is no case where
// an admin should be able to approve it either.
func routeInOverlaySpace(p netip.Prefix) bool {
	return carrierGradeNAT.Overlaps(p)
}

// autoApprovable narrows a never-reviewed node's own claims to the ones that
// may be honoured without an admin looking: everything except a CIDR that
// overlaps one a PEER already publishes.
//
// Auto-approval exists so subnet routers keep working without ceremony, and on
// its own it is fine — a node vouching for its own LAN. It became half of an
// interception primitive only in combination with overlap (audit finding
// MESH-1): claim the CIDR a colleague's router already serves and every
// consumer's netmap carries that prefix under two peers. WireGuard allowed-ips
// are exclusive, so the peer written last simply takes the traffic. Nobody can
// tell from the coordinator's side which of two claimants is honest — which is
// exactly the definition of a decision that belongs to a human.
//
// The unclaimed routes are still recorded in AdvertisedRoutes, so the console
// shows them as awaiting approval rather than losing them.
func autoApprovable(claims []netip.Prefix, peers []*Node, selfID int64, logger *slog.Logger, t MeshnetID) []netip.Prefix {
	if len(claims) == 0 || len(peers) == 0 {
		return claims
	}
	type publishedRoute struct {
		prefix netip.Prefix
		nodeID int64
	}
	var published []publishedRoute
	for _, p := range peers {
		if p == nil || (selfID != 0 && p.ID == selfID) {
			continue
		}
		// Both what peers are TOLD to route here (aliases substituted) and the
		// underlying approvals: an alias is what collides on the wire, the real
		// CIDR is what collides in intent, and either is contested.
		for _, r := range PublishedRoutes(p) {
			published = append(published, publishedRoute{r, p.ID})
		}
		for _, r := range p.ApprovedRoutes {
			published = append(published, publishedRoute{r, p.ID})
		}
	}
	out := make([]netip.Prefix, 0, len(claims))
	for _, r := range claims {
		contested := false
		for _, pub := range published {
			if r.Overlaps(pub.prefix) {
				if logger != nil {
					logger.Warn("not auto-approving a subnet route a peer already publishes; an admin must decide",
						"meshnet", t, "route", r, "overlaps", pub.prefix, "published_by_node", pub.nodeID)
				}
				contested = true
				break
			}
		}
		if !contested {
			out = append(out, r)
		}
	}
	return out
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
		if routeTooBroad(m) || routeInOverlaySpace(m) {
			refused = append(refused, m)
			continue
		}
		keep = append(keep, m)
	}
	return keep, refused
}
