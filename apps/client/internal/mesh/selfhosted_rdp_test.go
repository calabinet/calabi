package mesh

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

func TestSelfHostedRDPAuthorizationDecodeAndInbound(t *testing.T) {
	pin := bytes.Repeat([]byte{4}, 32)
	peer := &meshpb.Peer{NodeId: 2, NodeKey: keyB64(2), OverlayAddr: "100.64.0.11", AllowedIps: []string{"100.64.0.11/32"}, Os: "windows", RdpAccessAllowed: true, RdpCertificateSha256: pin}
	p, err := peerFromProto(peer)
	if err != nil || p.SameOwner || !p.RDPAccessAllowed || p.RDPPin != hex.EncodeToString(pin) {
		t.Fatalf("permission decode: %+v %v", p, err)
	}
	local := netip.MustParseAddr("100.64.0.12")
	cfg := BuildWGConfig(NetMap{Self: Peer{Overlay: local}, Peers: []Peer{p}})
	if len(cfg.RDPOwners) != 1 || cfg.RDPOwners[0] != p.Overlay {
		t.Fatalf("missing inbound grant: %+v", cfg.RDPOwners)
	}
	tun := &filteredTUN{filter: &PacketFilter{}, flows: newFlowTable()}
	tun.rdp.Store(&rdpOwnerFilter{local, map[netip.Addr]bool{p.Overlay: true}})
	packet := ipv4(p.Overlay.String(), protoTCP, 3389, 0)
	copy(packet[16:20], local.AsSlice())
	if !tun.allowInbound(packet) {
		t.Fatal("authorized self-hosted RDP blocked")
	}
	tun.filter.SetRules(true, nil)
	if tun.allowInbound(packet) {
		t.Fatal("RDP grant bypassed access rules")
	}
	tun.filter.SetRules(false, nil)
	peer.RdpAccessAllowed = false
	revoked, err := peerFromProto(peer)
	if err != nil || revoked.RDPPin != "" || len(BuildWGConfig(NetMap{Peers: []Peer{revoked}}).RDPOwners) != 0 {
		t.Fatalf("untrusted pin survived revocation: %+v %v", revoked, err)
	}
	tun.rdp.Store(&rdpOwnerFilter{local, map[netip.Addr]bool{}})
	if tun.allowInbound(packet) {
		t.Fatal("revoked peer still reaches 3389")
	}
	peer.SameOwner = true
	legacy, err := peerFromProto(peer)
	if err != nil || legacy.RDPPin != hex.EncodeToString(pin) {
		t.Fatal("legacy same-owner coordinator lost compatibility", err)
	}
}
