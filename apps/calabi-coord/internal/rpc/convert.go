package rpc

import (
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/protobuf/proto"
	"net/netip"
)

// toProtoNetMap maps a core.NetMap onto the wire type. Peers already come
// ACL-filtered from the coordinator (v0 = full mesh minus self).
func toProtoNetMap(nm *core.NetMap) *meshpb.NetMap {
	return toProtoNetMapWithPeers(nm, toProtoPeer)
}

func toProtoNetMapWithPeers(nm *core.NetMap, peer func(*core.Node) *meshpb.Peer) *meshpb.NetMap {
	return toProtoNetMapWithRDP(nm, peer, false)
}

func toProtoNetMapWithRDP(nm *core.NetMap, peer func(*core.Node) *meshpb.Peer, selfHosted bool) *meshpb.NetMap {
	out := &meshpb.NetMap{
		Self:    toProtoPeer(&nm.Self),
		DerpMap: toProtoDERPMap(nm.DERP),
		// This coordinator always compiles a filter, so the flag is unconditionally
		// true: an empty list from HERE means "nothing may reach this node", while
		// an older coordinator leaves the flag false and its nodes don't filter.
		FilterEnabled: true,
		RelayGrant:    nm.RelayGrant,
	}
	if len(nm.Peers) > 0 {
		out.Peers = make([]*meshpb.Peer, 0, len(nm.Peers))
	}
	for i := range nm.Peers {
		out.Peers = append(out.Peers, peerForRDP(&nm.Self, &nm.Peers[i], peer(&nm.Peers[i]), selfHosted))
	}
	for _, r := range nm.PacketFilter {
		fr := &meshpb.FilterRule{SrcCidrs: r.SrcCIDRs}
		for _, pr := range r.DstPorts {
			fr.DstPorts = append(fr.DstPorts, &meshpb.PortRange{
				First: uint32(pr.First), Last: uint32(pr.Last), Proto: pr.Proto,
			})
		}
		out.PacketFilter = append(out.PacketFilter, fr)
	}
	// The node's own registered services, so it can self-check them. Self
	// already carries them — NetMapFor swaps in the enriched copy so an "svc:"
	// rule about self matches like it does for peers — they simply never rode
	// the wire before, which left every console-authored service permanently
	// unobserved. See the field comment in coord.proto for why sending them
	// grants nothing.
	for _, s := range nm.Self.Services {
		out.SelfServices = append(out.SelfServices, &meshpb.DeclaredService{
			Name: s.Name, Proto: s.Proto, Port: uint32(s.Port), Note: s.Note, Target: s.Target,
		})
	}
	// The node's OWN alias mapping, sent only to itself. Peers see the alias in
	// this node's allowed_ips and nothing else; the node needs both halves to
	// install the 1:1 rewrite between them.
	approved := make(map[netip.Prefix]bool, len(nm.Self.ApprovedRoutes))
	for _, route := range nm.Self.ApprovedRoutes {
		approved[route.Masked()] = true
	}
	for _, ra := range nm.Self.RouteAliases {
		// A partial route withdrawal can leave an orphaned alias row. Never
		// instruct the router to keep rewriting a route no longer approved.
		if !approved[ra.Real.Masked()] {
			continue
		}
		out.SubnetAliases = append(out.SubnetAliases, &meshpb.SubnetAlias{
			Alias: ra.Alias.String(), Real: ra.Real.String(),
		})
	}
	for _, r := range nm.UnaliasedRoutes {
		out.UnaliasedRoutes = append(out.UnaliasedRoutes, r.String())
	}
	out.AliasBudgetAddrs = uint32(nm.AliasBudgetAddrs)
	out.RelayBandwidthKbps = nm.RelayBandwidthKbps
	out.RelayBandwidthBurstKbps = nm.RelayBandwidthBurstKbps
	out.AliasUsedAddrs = uint32(nm.AliasUsedAddrs)
	return out
}

// The base wire peer may be shared by different recipients of one snapshot.
func peerForOwner(owner int64, node *core.Node, base *meshpb.Peer) *meshpb.Peer {
	if owner <= 0 || owner != node.OwnerUserID {
		return base
	}
	result := proto.Clone(base).(*meshpb.Peer)
	result.SameOwner = true
	return result
}

// Preserve SameOwner as an identity assertion. A self-hosted operator separately
// authorizes approved, unattributed members of the same mesh for RDP access.
func peerForRDP(self, node *core.Node, base *meshpb.Peer, selfHosted bool) *meshpb.Peer {
	peer := peerForOwner(self.OwnerUserID, node, base)
	active := func(n *core.Node) bool { return n.Approved && !n.Disabled && !n.SignedOut }
	allowed := self.Meshnet > 0 && self.ID != node.ID && self.Meshnet == node.Meshnet && active(self) && active(node) &&
		(peer.SameOwner || selfHosted && self.OwnerUserID == 0 && node.OwnerUserID == 0)
	if !allowed {
		return peer
	}
	peer = proto.Clone(peer).(*meshpb.Peer)
	peer.RdpAccessAllowed = true
	return peer
}

func toProtoPeer(n *core.Node) *meshpb.Peer {
	p := &meshpb.Peer{
		NodeId:      n.ID,
		NodeKey:     n.NodeKey.String(),
		DiscoKey:    n.DiscoKey.String(),
		OverlayAddr: n.Overlay.String(),
		DerpHome:    n.DERPHome,
		Name:        n.Name,
		Os:          n.OS,
	}
	// A peer's traffic is routed to it by its overlay /32 plus any approved subnet
	// routes it advertises — the mesh routes those CIDRs to this node.
	if n.Overlay.IsValid() {
		p.AllowedIps = append(p.AllowedIps, n.Overlay.String()+"/32")
	}
	// Only APPROVED routes are routed to this node: an unapproved claim must not
	// pull anyone's traffic here (admin approval).
	//
	// PublishedRoutes, not ApprovedRoutes: a route with a subnet alias rides under
	// the ALIAS and never its real CIDR. Peers must not learn the real one — it is
	// the address that collides with their own LAN, which is the entire reason the
	// alias exists. It also has to be this list specifically, because allowed_ips
	// is cryptokey routing: whatever is not here cannot be sent OR received.
	for _, r := range core.PublishedRoutes(n) {
		p.AllowedIps = append(p.AllowedIps, r.String())
	}
	for _, ep := range n.Endpoints {
		p.Endpoints = append(p.Endpoints, ep.String())
	}
	// What this machine is FOR. n.Services is already confirmed-only by the time
	// a netmap is assembled (nodesWithServices drops unapproved rows so an
	// "svc:" rule cannot match a claim), so there is no second filter here — and
	// deliberately no second SOURCE either: the day approval semantics change,
	// the ACL and this list must change together.
	//
	// Name, proto and port only. Target is what the node itself dials to reach
	// the app — internal topology a peer cannot use — and the note is the
	// admin's. See PeerService in coord.proto.
	for _, sv := range n.Services {
		p.Services = append(p.Services, &meshpb.PeerService{
			Name: sv.Name, Proto: sv.Proto, Port: uint32(sv.Port),
		})
	}
	return p
}

func toProtoDERPMap(m core.DERPMap) *meshpb.DERPMap {
	out := &meshpb.DERPMap{}
	for _, r := range m.Regions {
		pr := &meshpb.DERPRegion{Code: r.Code}
		for _, node := range r.Nodes {
			pn := &meshpb.DERPNode{
				HostName: node.HostName,
				DerpPort: int32(node.DERPPort),
				StunPort: int32(node.STUNPort),
			}
			if node.TLS.Enabled() {
				pn.Tls = &meshpb.DERPNodeTLS{Trust: node.TLS.Trust, Pins: append([]string(nil), node.TLS.Pins...)}
			}
			pr.Nodes = append(pr.Nodes, pn)
		}
		out.Regions = append(out.Regions, pr)
	}
	return out
}
