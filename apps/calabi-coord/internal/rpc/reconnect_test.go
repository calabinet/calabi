package rpc

import (
	"context"
	"log/slog"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUnchangedReauthenticationStillRevokesSession(t *testing.T) {
	ctx := context.Background()
	c := &core.Coordinator{Nodes: core.NewMemNodeStore(), IPAM: core.NewMemIPAM(), Services: core.NewMemServiceStore()}
	auth := &principalAuth{keys: map[string]core.Identity{devKey: {Meshnet: 1, Principal: "owner"}}, revoked: map[string]bool{}}
	notif := core.NewNotifier()
	_, unsubscribe := notif.Subscribe(1, 0)
	defer unsubscribe()
	s := New(c, auth, notif, slog.Default())
	key, private := newKeyPair(t)
	var id int64
	register := func(name string, mutate func(*meshpb.RegisterNodeRequest)) (*meshpb.RegisterNodeResponse, error) {
		chReq := &meshpb.GetRegisterChallengeRequest{AuthKey: devKey}
		if id != 0 {
			chReq = &meshpb.GetRegisterChallengeRequest{NodeId: id, NodeKey: key.String()}
		}
		ch, err := s.GetRegisterChallenge(ctx, chReq)
		if err != nil {
			return nil, err
		}
		parsed, err := meshproto.ParseRegisterChallenge(ch.Challenge)
		if err != nil {
			t.Fatal(err)
		}
		req := &meshpb.RegisterNodeRequest{AuthKey: chReq.AuthKey, NodeId: id, NodeKey: key.String(), Name: name, ProtocolVersion: meshproto.ProtocolVersion, ChallengeId: ch.ChallengeId, RegisterProof: meshproto.SealRegisterProof(parsed, key, private)}
		// A superseded subscription keeps its live discovery transport while
		// repeating proof, membership checks and token replacement.
		req.DiscoKey = key.String()
		if mutate != nil {
			mutate(req)
		}
		return s.RegisterNode(ctx, req)
	}
	first, err := register("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	id = first.NodeId
	v, _ := notif.Version(1)
	oldCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	release, err := s.admissions.acquireSession(1, id, first.SessionToken, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	second, err := register("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if v2, _ := notif.Version(1); v2 != v {
		t.Fatal("unchanged registration broadcast")
	}
	if oldCtx.Err() == nil {
		t.Fatal("old subscription not canceled")
	}
	if _, ok := s.sessions.lookup(first.SessionToken); ok {
		t.Fatal("old token still valid")
	}
	if _, err := s.authorizeNode(ctx, first.SessionToken, id); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("old token authorization: %v", err)
	}
	// A session-scoped declaration disappears even when persistent data is equal.
	s.sessions.mu.Lock()
	old := s.sessions.byToken[second.SessionToken]
	old.fileTransfer = &meshpb.FileTransferInfo{}
	s.sessions.byToken[second.SessionToken] = old
	s.sessions.mu.Unlock()
	if _, err := register("laptop", nil); err != nil {
		t.Fatal(err)
	}
	if v2, _ := notif.Version(1); v2 == v {
		t.Fatal("file-transfer withdrawal not broadcast")
	} else {
		v = v2
	}
	if s.hasFileTransfer(id) {
		t.Fatal("new session retained old declaration")
	}
	if _, err := register("laptop", func(r *meshpb.RegisterNodeRequest) {
		r.DeclaredServices = []*meshpb.DeclaredService{{Name: "db", Proto: "tcp", Port: 5432}}
	}); err != nil {
		t.Fatal(err)
	}
	if v2, _ := notif.Version(1); v2 == v {
		t.Fatal("service change not broadcast")
	} else {
		v = v2
	}
	if _, err := register("laptop", nil); err != nil {
		t.Fatal(err)
	}
	if v2, _ := notif.Version(1); v2 == v {
		t.Fatal("service withdrawal not broadcast")
	}
	auth.revoked["owner"] = true
	if _, err := register("laptop", nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked principal: %v", err)
	}
	delete(auth.revoked, "owner")
	auth.down = true
	if _, err := register("laptop", nil); status.Code(err) != codes.Unavailable {
		t.Fatalf("unavailable identity: %v", err)
	}
	auth.down = false
	if _, err := register("laptop", func(r *meshpb.RegisterNodeRequest) { r.RegisterProof = []byte("invalid") }); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("bad proof: %v", err)
	}
}
