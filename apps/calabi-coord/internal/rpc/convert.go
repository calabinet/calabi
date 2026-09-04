package rpc

import (
	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// toProtoNetMap maps a core.NetMap onto the wire type. Peers already come
// ACL-filtered from the coordinator (v0 = full mesh minus self).
func toProtoNetMap(nm *core.NetMap) *meshpb.NetMap {
	out := &meshpb.NetMap{
		Self:    toProtoPeer(&nm.Self),
		DerpMap: toProtoDERPMap(nm.DERP),
		// This coordinator always compiles a filter, so the flag is unconditionally
		// true: an empty list from HERE means "nothing may reach this node", while
		// an older coordinator leaves the flag false and its nodes don't filter.
		FilterEnabled: true,
		RelayGrant:    nm.RelayGrant,
	}
	for i := range nm.Peers {
		out.Peers = append(out.Peers, toProtoPeer(&nm.Peers[i]))
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
	// The node's own registered services, so it can self-check them (F3b). Self
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
	return out
}

func toProtoPeer(n *core.Node) *meshpb.Peer {
	p := &meshpb.Peer{
		NodeId:      n.ID,
		NodeKey:     n.NodeKey.String(),
		DiscoKey:    n.DiscoKey.String(),
		OverlayAddr: n.Overlay.String(),
		DerpHome:    n.DERPHome,
		Name:        n.Name,
	}
	// A peer's traffic is routed to it by its overlay /32 plus any approved subnet
	// routes it advertises (MESH.7) — the mesh routes those CIDRs to this node.
	if n.Overlay.IsValid() {
		p.AllowedIps = append(p.AllowedIps, n.Overlay.String()+"/32")
	}
	// Only APPROVED routes are routed to this node: an unapproved claim must not
	// pull anyone's traffic here (MESH.7 + admin approval).
	for _, r := range n.ApprovedRoutes {
		p.AllowedIps = append(p.AllowedIps, r.String())
	}
	for _, ep := range n.Endpoints {
		p.Endpoints = append(p.Endpoints, ep.String())
	}
	return p
}

func toProtoDERPMap(m core.DERPMap) *meshpb.DERPMap {
	out := &meshpb.DERPMap{}
	for _, r := range m.Regions {
		pr := &meshpb.DERPRegion{Code: r.Code}
		for _, node := range r.Nodes {
			pr.Nodes = append(pr.Nodes, &meshpb.DERPNode{
				HostName: node.HostName,
				DerpPort: int32(node.DERPPort),
				StunPort: int32(node.STUNPort),
			})
		}
		out.Regions = append(out.Regions, pr)
	}
	return out
}
