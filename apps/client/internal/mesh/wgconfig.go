package mesh

import (
	"net/netip"
	"strings"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// meshKeepalive keeps NAT bindings warm on relayed/direct peer links.
const meshKeepalive = 25 * time.Second

// WGPeer is the desired WireGuard configuration for one peer.
type WGPeer struct {
	PublicKey meshproto.NodeKey
	// DiscoKey is the peer's hole-punching identity (MESH.4). The datapath needs
	// it to map WireGuard's node key onto the disco key the DISCO prober files
	// validated direct paths under. Zero for a peer that advertises none — such a
	// peer stays relay-only.
	DiscoKey   meshproto.DiscoKey
	AllowedIPs []netip.Prefix
	// Endpoint is the direct UDP address to reach the peer. ZERO in DERP-only
	// mode (MESH.2): traffic goes via the relay keyed by PublicKey until hole
	// punching (MESH.4) discovers a direct path and fills this in.
	Endpoint            netip.AddrPort
	DERPHome            string
	PersistentKeepalive time.Duration
}

// WGConfig is the full desired tun/WireGuard state derived from a NetMap. The
// datapath owns the private key; only the public identity travels here.
type WGConfig struct {
	NodeKey     meshproto.NodeKey
	OverlayAddr netip.Addr
	Peers       []WGPeer
	// ExitNode, when non-zero, is the peer this node routes its DEFAULT traffic
	// through (full-tunnel, MESH.7b). It's a LOCAL choice (never from the
	// coordinator): the consumer opts in to one advertised exit node. Zero = no
	// exit node — advertised 0.0.0.0/0 routes are then ignored, never auto-used.
	ExitNode meshproto.NodeKey
	// RelayByRegion resolves a DERP region code to the relay address serving it
	// (MESH.4 B2b). The datapath needs it twice: to reach a peer via THAT peer's
	// home relay, and to keep its own home link on the relay its own region
	// resolves to. Empty for a deployment whose map carries no usable relay.
	RelayByRegion map[string]string
	// Filter / FilterEnabled are the node's INBOUND packet filter (MESH.5b),
	// straight from the netmap. FilterEnabled false = the coordinator doesn't
	// compile filters, so nothing is filtered.
	Filter        []FilterRule
	FilterEnabled bool
	// SelfRelay is the address of this node's own home relay (RelayByRegion of the
	// node's home region) — where peers relay to reach it, so it must be the link
	// this node listens on. Empty leaves the bootstrap relay in place.
	SelfRelay string
	// RelayGrant is the coordinator's relay authorization, straight from the
	// netmap (R0'). It rides on the config for the same reason the filter does:
	// SetConfig receives the FULL desired state on every netmap update, which is
	// exactly the cadence a grant needs to be refreshed at.
	RelayGrant []byte
}

// BuildWGConfig maps a NetMap onto the desired WG state. Pure + deterministic so
// the datapath can diff-and-apply. In DERP-only mode peer Endpoints stay zero;
// once endpoints are present (MESH.4) the first is taken as the direct-path hint.
func BuildWGConfig(nm NetMap) WGConfig {
	cfg := WGConfig{NodeKey: nm.Self.NodeKey, OverlayAddr: nm.Self.Overlay}
	cfg.Filter, cfg.FilterEnabled = nm.Filter, nm.FilterEnabled
	cfg.RelayGrant = nm.RelayGrant
	cfg.RelayByRegion = relayAddrsByRegion(nm.DERP)
	cfg.SelfRelay = cfg.RelayByRegion[nm.Self.DERPHome]
	for _, p := range nm.Peers {
		wp := WGPeer{
			PublicKey:           p.NodeKey,
			DiscoKey:            p.DiscoKey,
			AllowedIPs:          p.AllowedIPs,
			DERPHome:            p.DERPHome,
			PersistentKeepalive: meshKeepalive,
		}
		if len(p.Endpoints) > 0 {
			wp.Endpoint = p.Endpoints[0]
		}
		cfg.Peers = append(cfg.Peers, wp)
	}
	return cfg
}

// ResolveExitNode maps a local exit-node selection (a peer name or an overlay
// IP, e.g. "office" or "100.64.0.2") to that peer's node key, so the datapath
// can single out which peer carries the default route. Empty selection, or one
// that matches no peer, yields the zero key (no exit node). Never matches self.
func ResolveExitNode(nm NetMap, sel string) meshproto.NodeKey {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return meshproto.NodeKey{}
	}
	byIP, _ := netip.ParseAddr(sel) // ok if it fails; then we match by name only
	for _, p := range nm.Peers {
		if p.Name == sel || (byIP.IsValid() && p.Overlay == byIP) {
			return p.NodeKey
		}
	}
	return meshproto.NodeKey{}
}

// droppedRoute records an advertised subnet that selectSubnetRoutes declined to
// route into the mesh because it is IDENTICAL to a local network — surfaced as a
// WARN so the operator can see WHY a peer's subnet isn't reachable (local wins).
type droppedRoute struct {
	Advertised netip.Prefix
	Local      netip.Prefix
	Peer       meshproto.NodeKey
}

// RoutePolicy is this node's CONSUMER-side stance on the subnet routes its peers
// advertise. Advertising is the publisher's decision and approval is the org
// admin's; this is the third party neither of them speaks for — the machine whose
// kernel routing table the route actually lands in.
//
// It exists because accepting a route is not free: a prefix covering a host that
// also TALKS to this node hijacks the return path for those connections (the
// reply goes into the tun, the far side's cryptokey routing drops it, and the
// connection times out silently). Whether that trade is worth it is a question
// only the receiving machine can answer.
type RoutePolicy struct {
	// Accept installs peers' advertised subnet routes. Off means this node joins
	// the mesh for peer-to-peer traffic only — the overlay always works.
	Accept bool
	// Excludes are prefixes to refuse even when Accept is on: the surgical case,
	// where one advertised prefix collides with this machine's traffic and the
	// rest are wanted. A route is refused if it is EQUAL TO or CONTAINED IN an
	// exclude, so excluding 192.168.1.0/24 also refuses a 192.168.1.22/32 inside
	// it — the operator named a region of address space, not a literal string.
	Excludes []netip.Prefix
}

// RefusedRoute is one advertised prefix this node declined, for logging.
type RefusedRoute struct {
	Prefix netip.Prefix
	Peer   meshproto.NodeKey
	Reason string
}

// refuses reports whether the policy declines prefix p, and why.
func (rp RoutePolicy) refuses(p netip.Prefix) (string, bool) {
	if !rp.Accept {
		return "this node is not accepting subnet routes", true
	}
	for _, ex := range rp.Excludes {
		// Contains-or-equal: an exclude names a region of address space. Comparing
		// only for equality would let a /32 inside an excluded /24 slip through,
		// which is exactly the shape that caused trouble in the first place.
		if ex.Overlaps(p) && ex.Bits() <= p.Bits() {
			return "excluded by this node's route policy (" + ex.String() + ")", true
		}
	}
	return "", false
}

// applyRoutePolicy strips peers' advertised SUBNET routes from cfg according to
// rp, returning the filtered config and what it refused.
//
// Two kinds of allowed-ip are NEVER filtered, whatever the policy says:
//
//   - overlay addresses — that is how a peer is reached at all, and refusing them
//     would silently leave the node in a mesh it cannot talk on.
//   - the default route (0.0.0.0/0) — that is the EXIT NODE mechanism, and using
//     an exit node is already this node's own explicit opt-in (ExitNode). A
//     consumer-side switch about OTHER people's subnets has no business
//     overriding a choice this machine made for itself.
//
// Filtering here rather than at the OS-route layer is deliberate: a refused
// prefix is then absent from WireGuard's allowed-ips, so this node will neither
// send to it nor accept packets from it. Half-refusing (no OS route but still in
// allowed-ips) would leave a peer able to source traffic from that range.
func applyRoutePolicy(cfg WGConfig, rp RoutePolicy) (WGConfig, []RefusedRoute) {
	if rp.Accept && len(rp.Excludes) == 0 {
		return cfg, nil // nothing to do — the common case, no allocation
	}
	overlay := netip.MustParsePrefix(meshOverlayCIDR)
	var refused []RefusedRoute
	peers := make([]WGPeer, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		kept := make([]netip.Prefix, 0, len(p.AllowedIPs))
		for _, aip := range p.AllowedIPs {
			if overlay.Contains(aip.Addr()) || isDefaultRoute(aip) {
				kept = append(kept, aip)
				continue
			}
			if why, no := rp.refuses(aip); no {
				refused = append(refused, RefusedRoute{Prefix: aip, Peer: p.PublicKey, Reason: why})
				continue
			}
			kept = append(kept, aip)
		}
		p.AllowedIPs = kept
		peers = append(peers, p)
	}
	cfg.Peers = peers
	return cfg, refused
}

// selectSubnetRoutes decides which of the peers' advertised allowed-ips get an OS
// route at the tun (MESH.7a). It drops three kinds: overlay /32s (already covered
// by the meshOverlayCIDR route), default routes (0.0.0.0/0 — handled by the exit
// step, never a plain tun route), and — the local-wins rule — an advertised
// subnet that is IDENTICAL to a directly-connected local network.
//
// The last case is narrow ON PURPOSE. Only an exact same-subnet collision (this
// box and a remote subnet-router both literally on 192.168.1.0/24) is ambiguous:
// routing it into the tun would hijack the machine's OWN LAN, and two equal-length
// prefixes tie under longest-prefix so a routing-metric accident would otherwise
// decide it — drop it, local wins (reach the remote copy via address translation).
//
// A MORE-SPECIFIC advertisement (a remote host 192.168.1.222/32 while this box is
// on 192.168.1.0/24) or a BROADER one (192.168.0.0/16) is NOT dropped: RFC1918
// address space collides constantly, and longest-prefix match already resolves
// these safely — the /32 diverts only that one address into the mesh and leaves
// the rest of the local /24 on the physical link; the /16 never beats the local
// /24 for local addresses. These are exactly the approved host/subnet routes that
// must keep working. Pure + deterministic so it can be unit-tested.
func selectSubnetRoutes(peers []WGPeer, overlay netip.Prefix, locals []netip.Prefix) (keep []netip.Prefix, dropped []droppedRoute) {
	seen := map[netip.Prefix]bool{}
	for _, p := range peers {
		for _, aip := range p.AllowedIPs {
			if overlay.Contains(aip.Addr()) || isDefaultRoute(aip) || seen[aip] {
				continue
			}
			if l, ok := exactLocalCollision(aip, locals); ok {
				dropped = append(dropped, droppedRoute{Advertised: aip, Local: l, Peer: p.PublicKey})
				continue
			}
			seen[aip] = true
			keep = append(keep, aip)
		}
	}
	return keep, dropped
}

// diffSubnetRoutes reports the OS route changes that move the table from the set
// this datapath installed last time (have) to the one the current netmap selects
// (want): add is want minus have, del is have minus want.
//
// The del half is the point. When a peer stops advertising a CIDR — unpublished,
// or an admin revoked the approval — the peer write has already dropped it from
// WireGuard's allowed-ips. A route left pointing at the tun then BLACKHOLES that
// subnet: packets enter the device and no peer claims them, rather than falling
// back to the physical link. Before this diff existed the route survived until
// the tun went down, so only a client restart cleared it.
//
// Only prefixes WE installed are ever removed — that is the whole reason for
// carrying `have`. Scanning the OS table for routes that merely LOOK like mesh
// routes would delete the operator's own static ones. It also means a prefix
// selectSubnetRoutes DROPPED (identical to a local network) can never be deleted
// here: it never entered `have`, so this can't withdraw the machine's own LAN out
// from under it. Pure + deterministic so it can be unit-tested.
func diffSubnetRoutes(have, want []netip.Prefix) (add, del []netip.Prefix) {
	inWant := make(map[netip.Prefix]bool, len(want))
	for _, p := range want {
		inWant[p] = true
	}
	inHave := make(map[netip.Prefix]bool, len(have))
	for _, p := range have {
		inHave[p] = true
	}
	for _, p := range want {
		if !inHave[p] {
			inHave[p] = true // also dedupes a prefix repeated within want
			add = append(add, p)
		}
	}
	for _, p := range have {
		if !inWant[p] {
			del = append(del, p)
		}
	}
	return add, del
}

// nextSubnetState returns the set to record as installed after an apply, given
// what the netmap wants and whether each OS batch actually succeeded.
//
// It has to be pessimistic in BOTH directions, or one transient OS failure
// becomes permanent: the next apply diffs against this value, and a state that
// lies about what happened produces an empty diff and never retries.
//
//   - a failed DELETE keeps its prefixes in the state, so the next netmap tries
//     the withdrawal again (deleting an already-gone route is tolerated per-OS);
//   - a failed ADD drops its prefixes from the state, so the next netmap tries
//     the install again (adding an existing route is likewise tolerated).
//
// A partially-applied batch is fine under both rules, since every per-OS call is
// idempotent in the direction it is retried.
func nextSubnetState(want, add, del []netip.Prefix, addOK, delOK bool) []netip.Prefix {
	skip := make(map[netip.Prefix]bool, len(add))
	if !addOK {
		for _, p := range add {
			skip[p] = true
		}
	}
	out := make([]netip.Prefix, 0, len(want)+len(del))
	for _, p := range want {
		if !skip[p] {
			out = append(out, p)
		}
	}
	if !delOK {
		// del is have-minus-want, so these cannot duplicate anything above.
		out = append(out, del...)
	}
	return out
}

// refusedFingerprint collapses a refusal set into a comparable string, so the
// controller logs a policy decision when it CHANGES rather than on every netmap
// re-push. Order is the peer iteration order, which is stable for an unchanged
// netmap — a reorder costs one extra log line, never a missed one.
func refusedFingerprint(rs []RefusedRoute) string {
	if len(rs) == 0 {
		return ""
	}
	var b strings.Builder
	for _, r := range rs {
		b.WriteString(r.Peer.String())
		b.WriteByte('|')
		b.WriteString(r.Prefix.String())
		b.WriteByte(';')
	}
	return b.String()
}
