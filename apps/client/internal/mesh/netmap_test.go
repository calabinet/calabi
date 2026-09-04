package mesh

import (
	"testing"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

func keyB64(b byte) string {
	var k meshproto.NodeKey
	for i := range k {
		k[i] = b
	}
	return k.String()
}

func TestFromNetMap(t *testing.T) {
	pb := &meshpb.NetMap{
		Self: &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1", AllowedIps: []string{"100.64.0.1/32"}},
		Peers: []*meshpb.Peer{
			{NodeId: 2, NodeKey: keyB64(2), OverlayAddr: "100.64.0.2", AllowedIps: []string{"100.64.0.2/32"}, DerpHome: "lax", Endpoints: []string{"203.0.113.5:41641"}},
			{NodeId: 3, NodeKey: "not-base64!!"}, // malformed → skipped
		},
		DerpMap: &meshpb.DERPMap{Regions: []*meshpb.DERPRegion{{Code: "lax", Nodes: []*meshpb.DERPNode{{HostName: "derp-lax.calabi.net", DerpPort: 443, StunPort: 3478}}}}},
	}

	nm, err := FromNetMap(pb)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if nm.Self.NodeID != 1 || nm.Self.Overlay.String() != "100.64.0.1" {
		t.Fatalf("self = %+v", nm.Self)
	}
	if len(nm.Peers) != 1 {
		t.Fatalf("peers = %d, want 1 (bad peer skipped)", len(nm.Peers))
	}
	p := nm.Peers[0]
	if p.NodeID != 2 || p.Overlay.String() != "100.64.0.2" || p.DERPHome != "lax" {
		t.Fatalf("peer = %+v", p)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != "100.64.0.2/32" {
		t.Fatalf("allowed_ips = %v", p.AllowedIPs)
	}
	if len(p.Endpoints) != 1 || p.Endpoints[0].String() != "203.0.113.5:41641" {
		t.Fatalf("endpoints = %v", p.Endpoints)
	}
	if len(nm.DERP.Regions) != 1 || nm.DERP.Regions[0].Nodes[0].DERPPort != 443 {
		t.Fatalf("derp = %+v", nm.DERP)
	}
}

func TestFromNetMapNoSelf(t *testing.T) {
	if _, err := FromNetMap(&meshpb.NetMap{}); err == nil {
		t.Fatal("expected error when self is missing")
	}
}

// The packet filter round-trips off the wire, and the two meanings of an empty
// filter stay distinguishable: an older coordinator (no flag) must leave the
// node unfiltered, while this coordinator's empty list means "nothing may reach
// me". Getting these backwards is an outage either way.
func TestFromNetMapPacketFilter(t *testing.T) {
	pb := &meshpb.NetMap{
		Self:          &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"},
		FilterEnabled: true,
		PacketFilter: []*meshpb.FilterRule{
			{
				SrcCidrs: []string{"100.64.0.2/32", "192.168.1.0/24", "not-a-cidr"},
				DstPorts: []*meshpb.PortRange{{First: 443, Last: 443, Proto: "tcp"}},
			},
			// Unusable rules are dropped whole: a partially-parsed rule would be a
			// BROADER rule than intended.
			{SrcCidrs: []string{"bad"}, DstPorts: []*meshpb.PortRange{{First: 1, Last: 2}}},
			{SrcCidrs: []string{"100.64.0.3/32"}, DstPorts: []*meshpb.PortRange{{First: 9, Last: 1}}},
		},
	}
	nm, err := FromNetMap(pb)
	if err != nil {
		t.Fatalf("FromNetMap: %v", err)
	}
	if !nm.FilterEnabled {
		t.Fatal("filter_enabled did not survive")
	}
	if len(nm.Filter) != 1 {
		t.Fatalf("filter = %+v, want only the usable rule", nm.Filter)
	}
	if len(nm.Filter[0].SrcCIDRs) != 2 {
		t.Fatalf("srcs = %v, want the two parseable CIDRs", nm.Filter[0].SrcCIDRs)
	}
	if nm.Filter[0].DstPorts[0] != (PortRange{First: 443, Last: 443, Proto: "tcp"}) {
		t.Fatalf("ports = %+v", nm.Filter[0].DstPorts)
	}

	// An older coordinator: no flag, no filter → the node must not filter.
	old, err := FromNetMap(&meshpb.NetMap{Self: pb.Self})
	if err != nil {
		t.Fatalf("FromNetMap: %v", err)
	}
	if old.FilterEnabled || len(old.Filter) != 0 {
		t.Fatalf("legacy netmap = %+v, want unfiltered", old)
	}
}
