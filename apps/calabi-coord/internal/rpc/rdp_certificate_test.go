package rpc

import (
	"bytes"
	"context"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"testing"
)

func TestRDPListenerPinPublication(t *testing.T) {
	ctx := context.Background()
	co := &core.Coordinator{Nodes: core.NewMemNodeStore(), Presence: core.NewPresence()}
	s := New(co, nil, core.NewNotifier(), nil)
	n := &core.Node{ID: 1, Meshnet: 7, OS: "windows", OwnerUserID: 9, NodeKey: meshproto.NodeKey{1}, Approved: true}
	if _, err := co.Nodes.Upsert(ctx, n); err != nil {
		t.Fatal(err)
	}
	token, err := s.sessions.start(n)
	if err != nil {
		t.Fatal(err)
	}
	leave := co.Presence.Connected(1)
	defer leave()
	post := func(token string, p []byte) error {
		_, err := s.ReportRdpCertificate(ctx, &meshpb.ReportRdpCertificateRequest{SessionToken: token, Sha256: p})
		return err
	}
	get := func(owned bool, key string) []byte {
		p := &meshpb.Peer{NodeId: 1, NodeKey: key, Os: "windows", SameOwner: owned}
		out := &meshpb.NetMap{Peers: []*meshpb.Peer{p}}
		s.addFileTransfers(out)
		if len(p.RdpCertificateSha256) > 0 {
			t.Fatal("mutated shared peer")
		}
		return out.Peers[0].RdpCertificateSha256
	}
	pin := bytes.Repeat([]byte{1}, 32)
	key := n.NodeKey.String()
	if post("wrong", pin) == nil || post(token, pin[:7]) == nil {
		t.Fatal("invalid publication accepted")
	}
	if err := post(token, pin); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(get(true, key), pin) || len(get(false, key)) != 0 || len(get(true, meshproto.NodeKey{2}.String())) != 0 {
		t.Fatal("wrong pin distribution")
	}
	pin[0] = 2
	if err := post(token, pin); err != nil || !bytes.Equal(get(true, key), pin) {
		t.Fatal("rotation failed", err)
	}
	if err := post(token, nil); err != nil || len(get(true, key)) != 0 {
		t.Fatal("withdrawal failed", err)
	}
	if err := post(token, pin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.sessions.start(n); err != nil {
		t.Fatal(err)
	}
	if len(get(true, key)) != 0 || post(token, pin) == nil {
		t.Fatal("stale registration pin survived")
	}
}
