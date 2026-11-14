package rpc

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

func TestSelfHostedRDPActualInvitationEnrollment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store := core.NewMemNodeStore()
	keys := core.NewMemAuthKeyStore()
	auth := &core.KeyAuth{Keys: keys}
	notif := core.NewNotifier()
	coordinator := &core.Coordinator{Nodes: store, Presence: core.NewPresence(), Policy: core.AllowAllPolicy{}, IPAM: core.NewMemIPAM(), DERP: core.StaticDERP{}}
	server := New(coordinator, auth, notif, slog.New(slog.NewTextHandler(io.Discard, nil)))
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	meshpb.RegisterCoordinatorServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()
	defer listener.Close()
	conn, err := grpc.NewClient("passthrough:///self-hosted-rdp", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := meshpb.NewCoordinatorClient(conn)
	join := func(meshnet core.MeshnetID, name, os string) testNode {
		secret, k, e := core.NewAuthKey(meshnet)
		if e != nil {
			t.Fatal(e)
		}
		k.MaxUses = 1
		if _, e = keys.CreateAuthKey(ctx, k); e != nil {
			t.Fatal(e)
		}
		key, priv := newKeyPair(t)
		response, e := enrollAs(ctx, client, secret, name, key, priv, func(r *meshpb.RegisterNodeRequest) {
			r.Os = os
			r.Capabilities = []string{string(meshproto.CapFileTransfer)}
		})
		if e != nil {
			t.Fatal(e)
		}
		n, e := store.Get(ctx, response.NodeId)
		if e != nil || n.OwnerUserID != 0 || !n.Approved {
			t.Fatalf("default enrollment: %+v %v", n, e)
		}
		return testNode{id: response.NodeId, key: key, priv: priv, token: response.SessionToken, overlay: response.OverlayAddr}
	}
	windows := join(1, "windows", "windows")
	controller := join(1, "mac", "darwin")
	other := join(2, "other-mesh", "darwin")
	targetStream, err := client.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: windows.id, SessionToken: windows.token})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = targetStream.Recv(); err != nil {
		t.Fatal(err)
	}
	pin := bytes.Repeat([]byte{8}, 32)
	if _, err = client.ReportRdpCertificate(ctx, &meshpb.ReportRdpCertificateRequest{SessionToken: windows.token, Sha256: pin}); err != nil {
		t.Fatal(err)
	}
	read := func(node testNode) *meshpb.NetMap {
		readCtx, stop := context.WithCancel(ctx)
		defer stop()
		nm, e := pullFirst(readCtx, client, &meshpb.PullNetMapRequest{NodeId: node.id, SessionToken: node.token})
		if e != nil {
			t.Fatal(e)
		}
		return nm
	}
	first := read(controller)
	found := false
	for _, p := range first.Peers {
		if p.NodeId == windows.id {
			found = true
			if p.SameOwner || !p.RdpAccessAllowed || !bytes.Equal(p.RdpCertificateSha256, pin) {
				t.Fatalf("missing authenticated RDP grant: %v", p)
			}
		}
	}
	if !found {
		t.Fatal("approved Windows peer missing")
	}
	if len(read(other).Peers) != 0 {
		t.Fatal("RDP authorization crossed mesh boundary")
	}
	if err = store.SetApproved(ctx, windows.id, false); err != nil {
		t.Fatal(err)
	}
	notif.Bump(1)
	for _, p := range read(controller).Peers {
		if p.NodeId == windows.id {
			t.Fatal("unapproved target remains reachable")
		}
	}
	if _, err = client.ReportRdpCertificate(ctx, &meshpb.ReportRdpCertificateRequest{SessionToken: windows.token, Sha256: pin}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unapproved session published pin: %v", err)
	}
}

func TestSelfHostedRDPPermissionBoundaries(t *testing.T) {
	viewer := core.Node{ID: 1, Meshnet: 7, Approved: true}
	target := core.Node{ID: 2, Meshnet: 7, Approved: true, OS: "windows"}
	tests := []struct {
		name   string
		hosted bool
		change func(*core.Node, *core.Node)
		want   bool
	}{
		{"approved self-hosted", true, func(*core.Node, *core.Node) {}, true},
		{"unattributed platform", false, func(*core.Node, *core.Node) {}, false},
		{"different mesh", true, func(_, n *core.Node) { n.Meshnet = 8 }, false},
		{"invalid mesh", true, func(s, n *core.Node) { s.Meshnet = 0; n.Meshnet = 0 }, false},
		{"self", true, func(s, n *core.Node) { n.ID = s.ID }, false},
		{"unapproved target", true, func(_, n *core.Node) { n.Approved = false }, false},
		{"unapproved viewer", true, func(s, _ *core.Node) { s.Approved = false }, false},
		{"disabled target", true, func(_, n *core.Node) { n.Disabled = true }, false},
		{"disabled viewer", true, func(s, _ *core.Node) { s.Disabled = true }, false},
		{"signed out target", true, func(_, n *core.Node) { n.SignedOut = true }, false},
		{"signed out viewer", true, func(s, _ *core.Node) { s.SignedOut = true }, false},
		{"attributed target", true, func(_, n *core.Node) { n.OwnerUserID = 9 }, false},
		{"attributed viewer", true, func(s, _ *core.Node) { s.OwnerUserID = 9 }, false},
		{"same attributed platform owner", false, func(s, n *core.Node) { s.OwnerUserID = 9; n.OwnerUserID = 9 }, true},
		{"different attributed platform owner", false, func(s, n *core.Node) { s.OwnerUserID = 8; n.OwnerUserID = 9 }, false},
	}
	base := &meshpb.Peer{NodeId: 2, Os: "windows"}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, n := viewer, target
			tc.change(&s, &n)
			p := peerForRDP(&s, &n, base, tc.hosted)
			if p.RdpAccessAllowed != tc.want {
				t.Fatalf("RDP allowed=%v, want %v", p.RdpAccessAllowed, tc.want)
			}
			if (s.OwnerUserID == 0 || n.OwnerUserID == 0) && p.SameOwner {
				t.Fatal("unattributed identity became same-owner")
			}
			if base.RdpAccessAllowed || base.SameOwner {
				t.Fatal("shared wire peer mutated")
			}
		})
	}
}

func TestSelfHostedRDPRequiresConfiguredKeyAuthenticator(t *testing.T) {
	var missing *core.KeyAuth
	for _, auth := range []core.Authenticator{nil, missing, core.StaticAuth{}} {
		if (&Server{auth: auth}).selfHostedRDP() {
			t.Fatal("missing or unrelated authenticator enabled self-hosted RDP")
		}
	}
	if !(&Server{auth: &core.KeyAuth{Keys: core.NewMemAuthKeyStore()}}).selfHostedRDP() {
		t.Fatal("configured self-hosted auth rejected")
	}
}

func TestSelfHostedRDPDefaultInvitesAndBothMapPaths(t *testing.T) {
	ctx := context.Background()
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "shared snapshot", true: "legacy full map"}[legacy], func(t *testing.T) {
			s, store, nodes, e := sharedMapFixture(t)
			s.coord.Presence = core.NewPresence()
			keys := core.NewMemAuthKeyStore()
			secret, k, err := core.NewAuthKey(1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = keys.CreateAuthKey(ctx, k); err != nil {
				t.Fatal(err)
			}
			auth := &core.KeyAuth{Keys: keys}
			identity, err := auth.Resolve(ctx, secret)
			if err != nil || identity.UserID != 0 || identity.Meshnet != 1 {
				t.Fatalf("default invite identity: %+v %v", identity, err)
			}
			s.auth = auth
			s.legacyMaps = legacy
			windows := *nodes[1]
			windows.OS = "windows"
			windows.OwnerUserID = identity.UserID
			if _, err = store.Upsert(ctx, &windows); err != nil {
				t.Fatal(err)
			}
			token, err := s.sessions.start(&windows)
			if err != nil {
				t.Fatal(err)
			}
			leave := s.coord.Presence.Connected(windows.ID)
			defer leave()
			pin := bytes.Repeat([]byte{0x65}, 32)
			if _, err = s.ReportRdpCertificate(ctx, &meshpb.ReportRdpCertificateRequest{SessionToken: token, Sha256: pin}); err != nil {
				t.Fatal(err)
			}
			stream := &snapshotStream{ctx: ctx}
			if err = s.sendNetMap(stream, nodes[0], e, false); err != nil {
				t.Fatal(err)
			}
			var target *meshpb.Peer
			for _, p := range stream.sent.Peers {
				if p.NodeId == windows.ID {
					target = p
				}
			}
			if target == nil || !target.RdpAccessAllowed || target.SameOwner || !bytes.Equal(target.RdpCertificateSha256, pin) {
				t.Fatalf("self-hosted RDP target: %v", target)
			}
			// The permission is per recipient. A platform view over the very same
			// shared topology must not reuse the self-hosted authorization.
			s.auth = nil
			denied := &snapshotStream{ctx: ctx}
			if err = s.sendNetMap(denied, nodes[0], e, false); err != nil {
				t.Fatal(err)
			}
			for _, p := range denied.sent.Peers {
				if p.RdpAccessAllowed || len(p.RdpCertificateSha256) > 0 {
					t.Fatal("platform inherited cached self-hosted authority")
				}
			}
			if _, err = s.ReportRdpCertificate(ctx, &meshpb.ReportRdpCertificateRequest{SessionToken: token, Sha256: pin}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("unowned platform publication: %v", err)
			}
			s.auth = auth
			if _, err = s.ReportRdpCertificate(ctx, &meshpb.ReportRdpCertificateRequest{SessionToken: token}); err != nil {
				t.Fatal(err)
			}
			withdrawn := &snapshotStream{ctx: ctx}
			if err = s.sendNetMap(withdrawn, nodes[0], e, false); err != nil {
				t.Fatal(err)
			}
			for _, p := range withdrawn.sent.Peers {
				if p.NodeId == windows.ID && len(p.RdpCertificateSha256) > 0 {
					t.Fatal("withdrawn pin remained")
				}
			}
			windows.Approved = false
			if _, err = store.Upsert(ctx, &windows); err != nil {
				t.Fatal(err)
			}
			if _, err = s.ReportRdpCertificate(ctx, &meshpb.ReportRdpCertificateRequest{SessionToken: token, Sha256: pin}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("unapproved publication: %v", err)
			}
		})
	}
}

func TestSelfHostedRDPGrantRevocationTravelsInDelta(t *testing.T) {
	enc := meshproto.NetMapEncoder{}
	cache := &meshproto.PeerFingerprintCache{}
	first := &meshpb.NetMap{Self: &meshpb.Peer{NodeId: 1}, Peers: []*meshpb.Peer{{NodeId: 2, RdpAccessAllowed: true, RdpCertificateSha256: bytes.Repeat([]byte{1}, 32)}}}
	for id := int64(3); id < 12; id++ {
		first.Peers = append(first.Peers, &meshpb.Peer{NodeId: id, Name: strings.Repeat("unchanged-peer", 30)})
	}
	full, next, err := enc.NextWithPeerCache(first, cache)
	if err != nil {
		t.Fatal(err)
	}
	decoder := meshproto.NetMapDecoder{}
	if _, _, err = decoder.Apply(full); err != nil {
		t.Fatal(err)
	}
	revoked := proto.Clone(first).(*meshpb.NetMap)
	revoked.Peers[0].RdpAccessAllowed = false
	revoked.Peers[0].RdpCertificateSha256 = nil
	delta, _, err := next.NextWithPeerCache(revoked, cache)
	if err != nil || !delta.Delta || len(delta.Peers) != 1 {
		t.Fatalf("missing authorization delta: %v %v", delta, err)
	}
	result, _, err := decoder.Apply(delta)
	if err != nil || result.Peers[0].RdpAccessAllowed || len(result.Peers[0].RdpCertificateSha256) > 0 {
		t.Fatalf("revocation lost: %v %v", result, err)
	}
}
