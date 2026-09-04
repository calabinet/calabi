// Package mesh is the calabi client's Connect (WireGuard mesh) subsystem. It
// speaks ONLY pkg/mesh-proto (the intentionally-public coordination + relay
// contract) — never pkg/api — so it links cleanly into the self-hosted client
// (enforced by scripts/export-public.sh).
//
// MESH.2 scope in this slice: the control-plane plumbing — the netmap model
// (this file) and the coordinator client (coord.go). The DERP relay client and
// the WireGuard tun datapath (which need a real tun device / privileges, not
// exercisable in CI) land behind the Datapath seam in follow-up slices.
package mesh

import (
	"fmt"
	"net/netip"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// Peer is one node the local node may reach, as resolved from a NetMap.
type Peer struct {
	NodeID     int64
	Name       string // MagicDNS label
	NodeKey    meshproto.NodeKey
	DiscoKey   meshproto.DiscoKey
	Overlay    netip.Addr
	AllowedIPs []netip.Prefix
	Endpoints  []netip.AddrPort
	DERPHome   string
}

// NetMap is the client-side view of the meshnet: self + the ACL-filtered peers
// + the relay directory. Built from a meshpb.NetMap via FromNetMap.
type NetMap struct {
	Self  Peer
	Peers []Peer
	DERP  DERPMap
	// Filter is what THIS node enforces on inbound traffic (MESH.5b), meaningful
	// only when FilterEnabled — see below.
	Filter []FilterRule
	// FilterEnabled says the coordinator compiled Filter authoritatively. When
	// false (an older coordinator that doesn't send one) the node must not filter
	// at all; when true, an EMPTY Filter means "nothing may reach me". The two
	// cases are indistinguishable from the list alone, and guessing either way is
	// an outage for the other.
	FilterEnabled bool
	// RelayGrant is the coordinator's signed authorization for this node to use
	// relays (R0'). Opaque: the node hands the bytes to a relay, which verifies
	// them offline against the coordinator's public key. Empty from a coordinator
	// that doesn't issue grants — relays must then not require them.
	RelayGrant []byte
	// SelfServices is the coordinator's registry of the services registered on
	// THIS node, used only for the self-check (F3b). It exists because the
	// registry is not only what this node declared: a manager can enter a
	// service in the console, and nothing else pushes that back down, so
	// without it such a service could never be observed at all.
	//
	// It grants nothing and configures nothing — see the field comment in
	// coord.proto. Empty from a coordinator that predates the field, in which
	// case the node checks its own declarations exactly as before.
	SelfServices []DeclaredService
}

// FilterRule allows traffic from any of SrcCIDRs to any of DstPorts on THIS
// node (MESH.5b). The coordinator compiles the meshnet's ACL into these per
// node; the node enforces them on inbound traffic — the receiver's own copy of
// the rules is the one a compromised sender cannot argue with.
type FilterRule struct {
	SrcCIDRs []netip.Prefix
	DstPorts []PortRange
}

// PortRange is an inclusive span for one protocol ("tcp", "udp", or "" = any).
type PortRange struct {
	First uint16
	Last  uint16
	Proto string
}

// filterFromProto converts the wire filter, SKIPPING malformed entries the same
// way peers are skipped. A rule we can't parse must not silently widen access,
// so a rule with no usable source or no usable port is dropped entirely rather
// than kept as a partial (and therefore broader) rule.
func filterFromProto(in []*meshpb.FilterRule) []FilterRule {
	out := make([]FilterRule, 0, len(in))
	for _, r := range in {
		var fr FilterRule
		for _, c := range r.GetSrcCidrs() {
			pfx, err := netip.ParsePrefix(c)
			if err != nil {
				continue
			}
			fr.SrcCIDRs = append(fr.SrcCIDRs, pfx)
		}
		for _, p := range r.GetDstPorts() {
			if p.GetFirst() > 65535 || p.GetLast() > 65535 || p.GetLast() < p.GetFirst() {
				continue
			}
			fr.DstPorts = append(fr.DstPorts, PortRange{
				First: uint16(p.GetFirst()), Last: uint16(p.GetLast()), Proto: p.GetProto(),
			})
		}
		if len(fr.SrcCIDRs) == 0 || len(fr.DstPorts) == 0 {
			continue
		}
		out = append(out, fr)
	}
	return out
}

// DERPMap is the relay directory (region -> relay nodes).
type DERPMap struct {
	Regions []DERPRegion
}

// DERPRegion groups relays by geography.
type DERPRegion struct {
	Code  string
	Nodes []DERPNode
}

// DERPNode is one relay endpoint.
type DERPNode struct {
	HostName string
	DERPPort int
	STUNPort int
}

// FromNetMap converts the wire NetMap into the client model. It fails only if
// self is unusable (missing, or an unparseable node key / overlay); individual
// malformed peer entries are SKIPPED (best-effort) rather than dropping the
// whole map, so one bad row can't sever the mesh.
func FromNetMap(pb *meshpb.NetMap) (NetMap, error) {
	if pb == nil || pb.GetSelf() == nil {
		return NetMap{}, fmt.Errorf("mesh: netmap has no self")
	}
	self, err := peerFromProto(pb.GetSelf())
	if err != nil {
		return NetMap{}, fmt.Errorf("mesh: self: %w", err)
	}
	nm := NetMap{
		Self:          self,
		DERP:          derpFromProto(pb.GetDerpMap()),
		Filter:        filterFromProto(pb.GetPacketFilter()),
		FilterEnabled: pb.GetFilterEnabled(),
		RelayGrant:    pb.GetRelayGrant(),
	}
	for _, ps := range pb.GetSelfServices() {
		if ps.GetName() == "" {
			continue // a nameless entry can't be reported against; drop it
		}
		nm.SelfServices = append(nm.SelfServices, DeclaredService{
			Name:   ps.GetName(),
			Proto:  ps.GetProto(),
			Port:   int(ps.GetPort()),
			Target: ps.GetTarget(),
			Note:   ps.GetNote(),
		})
	}
	for _, pp := range pb.GetPeers() {
		p, err := peerFromProto(pp)
		if err != nil {
			continue // skip malformed peer, keep the rest
		}
		nm.Peers = append(nm.Peers, p)
	}
	return nm, nil
}

func peerFromProto(pp *meshpb.Peer) (Peer, error) {
	nk, err := meshproto.ParseNodeKey(pp.GetNodeKey())
	if err != nil {
		return Peer{}, fmt.Errorf("node_key: %w", err)
	}
	p := Peer{NodeID: pp.GetNodeId(), Name: pp.GetName(), NodeKey: nk, DERPHome: pp.GetDerpHome()}

	// disco_key is optional (empty until MESH.4).
	if dk := pp.GetDiscoKey(); dk != "" {
		if k, err := meshproto.ParseDiscoKey(dk); err == nil {
			p.DiscoKey = k
		}
	}
	if oa := pp.GetOverlayAddr(); oa != "" {
		addr, err := netip.ParseAddr(oa)
		if err != nil {
			return Peer{}, fmt.Errorf("overlay_addr %q: %w", oa, err)
		}
		p.Overlay = addr
	}
	for _, cidr := range pp.GetAllowedIps() {
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil {
			return Peer{}, fmt.Errorf("allowed_ip %q: %w", cidr, err)
		}
		p.AllowedIPs = append(p.AllowedIPs, pfx)
	}
	for _, ep := range pp.GetEndpoints() {
		ap, err := netip.ParseAddrPort(ep)
		if err != nil {
			continue // endpoints are hints; skip unparseable ones
		}
		p.Endpoints = append(p.Endpoints, ap)
	}
	return p, nil
}

func derpFromProto(pb *meshpb.DERPMap) DERPMap {
	var out DERPMap
	if pb == nil {
		return out
	}
	for _, r := range pb.GetRegions() {
		reg := DERPRegion{Code: r.GetCode()}
		for _, n := range r.GetNodes() {
			reg.Nodes = append(reg.Nodes, DERPNode{
				HostName: n.GetHostName(),
				DERPPort: int(n.GetDerpPort()),
				STUNPort: int(n.GetStunPort()),
			})
		}
		out.Regions = append(out.Regions, reg)
	}
	return out
}
