package rpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFileTransferSessionScopeAndWithdrawal(t *testing.T) {
	ctx := context.Background()
	coord := &core.Coordinator{Nodes: core.NewMemNodeStore(), Presence: core.NewPresence()}
	s := New(coord, nil, core.NewNotifier(), nil)
	node := &core.Node{ID: 1, Meshnet: 7, NodeKey: meshproto.NodeKey{1}, Approved: true}
	if _, err := coord.Nodes.Upsert(ctx, node); err != nil {
		t.Fatal(err)
	}
	tok, err := s.sessions.start(node)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	info := &meshpb.FileTransferInfo{Version: 1, Port: 17401, Receiving: true, Certificate: der, ExpiresUnix: now.Add(meshproto.FileTransferLease).Unix()}
	if err := meshproto.SignFileTransfer(node.NodeKey, info, key); err != nil {
		t.Fatal(err)
	}
	update := func(token string, i *meshpb.FileTransferInfo) error {
		_, err := s.UpdateFileTransfer(ctx, &meshpb.UpdateFileTransferRequest{SessionToken: token, Info: i})
		return err
	}
	if err := update("invalid", info); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauth: %v", err)
	}
	if err := update(tok, info); err != nil {
		t.Fatal(err)
	}
	mapFor := func() *meshpb.NetMap {
		out := &meshpb.NetMap{Self: &meshpb.Peer{NodeId: 1, NodeKey: node.NodeKey.String()}}
		s.addFileTransfers(out)
		return out
	}
	if !mapFor().FileTransferSupported || mapFor().Self.FileTransfer != nil {
		t.Fatal("offline listener advertised")
	}
	release := coord.Presence.Connected(1)
	if mapFor().Self.FileTransfer == nil {
		t.Fatal("online listener absent")
	}
	release()
	if mapFor().Self.FileTransfer != nil {
		t.Fatal("offline listener retained")
	}
	defer coord.Presence.Connected(1)()
	if err := update(tok, nil); err != nil {
		t.Fatal(err)
	}
	if mapFor().Self.FileTransfer != nil {
		t.Fatal("withdrawn listener retained")
	}
	if err := update(tok, info); err != nil {
		t.Fatal(err)
	}
	newToken, err := s.sessions.start(node)
	if err != nil {
		t.Fatal(err)
	}
	if mapFor().Self.FileTransfer != nil {
		t.Fatal("new session inherited old listener")
	}
	if err := update(tok, info); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("old session: %v", err)
	}
	other := meshproto.NodeKey{2}
	if err := meshproto.SignFileTransfer(other, info, key); err != nil {
		t.Fatal(err)
	}
	if err := update(newToken, info); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("other device proof: %v", err)
	}
	node.Disabled = true
	if _, err := coord.Nodes.Upsert(ctx, node); err != nil {
		t.Fatal(err)
	}
	if err := update(newToken, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("disabled: %v", err)
	}
}
