package rpc

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

// principalAuth is an Authenticator whose keys name principals, the way the
// platform's identity service does, and whose answer to Reauthorize the test
// controls.
type principalAuth struct {
	keys map[string]core.Identity

	mu      sync.Mutex
	revoked map[string]bool // principal -> no longer admits
	down    bool            // the identity service cannot be reached
	asked   []string
}

func (a *principalAuth) Resolve(_ context.Context, key string) (core.Identity, error) {
	if id, ok := a.keys[key]; ok {
		return id, nil
	}
	return core.Identity{}, core.ErrAuthDenied
}

func (a *principalAuth) Spend(context.Context, string) (func(), error) { return func() {}, nil }

func (a *principalAuth) Reauthorize(_ context.Context, _ core.MeshnetID, principal string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, principal)
	switch {
	case a.down:
		return errors.New("identity service unreachable")
	case a.revoked[principal]:
		return core.ErrAuthDenied
	}
	return nil
}

type reauthRig struct {
	c     meshpb.CoordinatorClient
	nodes core.NodeStore
	auth  *principalAuth
}

func startReauthServer(t *testing.T) reauthRig {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	nodes := core.NewMemNodeStore()
	coord := &core.Coordinator{
		Nodes:  nodes,
		Policy: core.AllowAllPolicy{},
		IPAM:   core.NewMemIPAM(),
		DERP:   core.StaticDERP{Map: core.DERPMap{Regions: []core.DERPRegion{{Code: "lax"}}}},
	}
	auth := &principalAuth{
		keys: map[string]core.Identity{
			"alice-token": {Meshnet: 1, UserID: 11, Principal: "user:11", Tags: []string{"tag:laptop"}},
			"bob-token":   {Meshnet: 1, UserID: 12, Principal: "user:12"},
		},
		revoked: map[string]bool{},
	}
	gs := grpc.NewServer()
	meshpb.RegisterCoordinatorServer(gs, New(coord, auth, core.NewNotifier(), slog.Default()))
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		gs.Stop()
		_ = lis.Close()
	})
	return reauthRig{c: meshpb.NewCoordinatorClient(conn), nodes: nodes, auth: auth}
}

// reauth re-registers n by proof alone: no auth key, its node id and key.
func reauth(ctx context.Context, c meshpb.CoordinatorClient, n testNode, name string) (*meshpb.RegisterNodeResponse, error) {
	chr, err := c.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{NodeId: n.id, NodeKey: n.key.String()})
	if err != nil {
		return nil, err
	}
	ch, err := meshproto.ParseRegisterChallenge(chr.GetChallenge())
	if err != nil {
		return nil, err
	}
	return c.RegisterNode(ctx, &meshpb.RegisterNodeRequest{
		NodeId: n.id, NodeKey: n.key.String(), Name: name, ProtocolVersion: meshproto.ProtocolVersion,
		ChallengeId: chr.GetChallengeId(), RegisterProof: meshproto.SealRegisterProof(ch, n.key, n.priv),
	})
}

// enrollWithCaps is enroll, asking for capabilities, and returns the response.
func enrollWithCaps(t *testing.T, c meshpb.CoordinatorClient, authKey, name string, caps ...string) (testNode, *meshpb.RegisterNodeResponse) {
	t.Helper()
	key, priv := newKeyPair(t)
	resp, err := enrollAs(context.Background(), c, authKey, name, key, priv, func(r *meshpb.RegisterNodeRequest) {
		r.Capabilities = caps
	})
	if err != nil {
		t.Fatalf("enroll %s: %v", name, err)
	}
	return testNode{id: resp.GetNodeId(), overlay: resp.GetOverlayAddr(), key: key, priv: priv, token: resp.GetSessionToken()}, resp
}

// The capability is offered only to a node that asks for it.
func TestNodeReauthIsNegotiated(t *testing.T) {
	r := startReauthServer(t)
	_, resp := enrollWithCaps(t, r.c, "alice-token", "laptop", string(meshproto.CapNodeReauth), "some-future-thing")
	if got := resp.GetCapabilities(); len(got) != 1 || got[0] != string(meshproto.CapNodeReauth) {
		t.Fatalf("capabilities = %v, want just node_reauth", got)
	}
	_, resp = enrollWithCaps(t, r.c, "bob-token", "phone")
	if len(resp.GetCapabilities()) != 0 {
		t.Fatalf("a node that asked for nothing was offered %v", resp.GetCapabilities())
	}
}

// Enrolled once with a credential, a node comes back on proof of its node key
// alone: same id, same address, same tags and owner, a working session — and
// the identity service is asked about the principal it enrolled as.
func TestReauthKeepsTheNodeAndAsksAboutItsPrincipal(t *testing.T) {
	r := startReauthServer(t)
	ctx := context.Background()
	n, _ := enrollWithCaps(t, r.c, "alice-token", "laptop", string(meshproto.CapNodeReauth))

	resp, err := reauth(ctx, r.c, n, "laptop")
	if err != nil {
		t.Fatalf("reauth: %v", err)
	}
	if resp.GetNodeId() != n.id || resp.GetOverlayAddr() != n.overlay {
		t.Fatalf("reauth gave node %d %s, want %d %s", resp.GetNodeId(), resp.GetOverlayAddr(), n.id, n.overlay)
	}
	if _, err := pullFirst(ctx, r.c, &meshpb.PullNetMapRequest{NodeId: n.id, SessionToken: resp.GetSessionToken()}); err != nil {
		t.Fatalf("the new session does not work: %v", err)
	}
	stored, _ := r.nodes.Get(ctx, n.id)
	if stored.OwnerUserID != 11 || stored.EnrolledBy != "user:11" || len(stored.Tags) != 1 || stored.Tags[0] != "tag:laptop" {
		t.Fatalf("reauth changed who the node is: owner=%d enrolled_by=%q tags=%v", stored.OwnerUserID, stored.EnrolledBy, stored.Tags)
	}
	r.auth.mu.Lock()
	asked := append([]string(nil), r.auth.asked...)
	r.auth.mu.Unlock()
	if len(asked) != 1 || asked[0] != "user:11" {
		t.Fatalf("Reauthorize asked about %v, want [user:11]", asked)
	}
}

// Every way a node must NOT come back by proof alone, and the code that tells
// the device what to do instead.
func TestReauthRefusals(t *testing.T) {
	ctx := context.Background()

	t.Run("revoked principal", func(t *testing.T) {
		r := startReauthServer(t)
		n, _ := enrollWithCaps(t, r.c, "alice-token", "laptop")
		r.auth.revoked["user:11"] = true
		if _, err := reauth(ctx, r.c, n, "laptop"); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("err = %v, want Unauthenticated", err)
		}
	})

	t.Run("identity service down", func(t *testing.T) {
		r := startReauthServer(t)
		n, _ := enrollWithCaps(t, r.c, "alice-token", "laptop")
		r.auth.down = true
		if _, err := reauth(ctx, r.c, n, "laptop"); status.Code(err) != codes.Unavailable {
			t.Fatalf("err = %v, want Unavailable (refused, and retryable)", err)
		}
	})

	t.Run("signed out, until it enrolls with a key again", func(t *testing.T) {
		r := startReauthServer(t)
		n, _ := enrollWithCaps(t, r.c, "alice-token", "laptop")
		if _, err := r.c.SignOut(ctx, &meshpb.SignOutRequest{SessionToken: n.token}); err != nil {
			t.Fatalf("sign out: %v", err)
		}
		if _, err := reauth(ctx, r.c, n, "laptop"); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("after sign-out: err = %v, want FailedPrecondition", err)
		}
		// The sign-out also ended the session it was made on.
		if _, err := pullFirst(ctx, r.c, &meshpb.PullNetMapRequest{NodeId: n.id, SessionToken: n.token}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("the signed-out session still works: %v", err)
		}
		// Enrolling with the credential again is the same device, and clears it.
		again, err := enrollAs(ctx, r.c, "alice-token", "laptop", n.key, n.priv, nil)
		if err != nil || again.GetNodeId() != n.id {
			t.Fatalf("re-enroll after sign-out: %v, node %d (want %d)", err, again.GetNodeId(), n.id)
		}
		if _, err := reauth(ctx, r.c, n, "laptop"); err != nil {
			t.Fatalf("reauth after re-enrolling: %v", err)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		r := startReauthServer(t)
		n, _ := enrollWithCaps(t, r.c, "alice-token", "laptop")
		_ = r.nodes.SetDisabled(ctx, n.id, true)
		if _, err := reauth(ctx, r.c, n, "laptop"); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("err = %v, want PermissionDenied", err)
		}
	})

	t.Run("deleted", func(t *testing.T) {
		r := startReauthServer(t)
		n, _ := enrollWithCaps(t, r.c, "alice-token", "laptop")
		if err := r.nodes.Delete(ctx, n.id); err != nil {
			t.Fatal(err)
		}
		if _, err := reauth(ctx, r.c, n, "laptop"); status.Code(err) != codes.NotFound {
			t.Fatalf("err = %v, want NotFound", err)
		}
		if list, _ := r.nodes.ListMeshnet(ctx, 1); len(list) != 0 {
			t.Fatalf("a deleted node came back without a key: %d nodes", len(list))
		}
	})

	t.Run("another node's id", func(t *testing.T) {
		r := startReauthServer(t)
		alice, _ := enrollWithCaps(t, r.c, "alice-token", "laptop")
		bob, _ := enrollWithCaps(t, r.c, "bob-token", "phone")
		// Bob knows Alice's node id and public key - every peer does - but not
		// her private key.
		impostor := testNode{id: alice.id, key: alice.key, priv: bob.priv}
		if _, err := reauth(ctx, r.c, impostor, "laptop"); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("proof with the wrong private key: err = %v, want Unauthenticated", err)
		}
		// And his own key under her id is refused before a challenge is issued.
		_, err := r.c.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{NodeId: alice.id, NodeKey: bob.key.String()})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("a mismatched key got a challenge: err = %v", err)
		}
	})
}

// A challenge issued for re-registering one node cannot be spent enrolling with
// a key, or re-registering another.
func TestReauthChallengeIsBoundToItsNode(t *testing.T) {
	r := startReauthServer(t)
	ctx := context.Background()
	alice, _ := enrollWithCaps(t, r.c, "alice-token", "laptop")
	bob, _ := enrollWithCaps(t, r.c, "bob-token", "phone")

	chr, err := r.c.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{NodeId: alice.id, NodeKey: alice.key.String()})
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := meshproto.ParseRegisterChallenge(chr.GetChallenge())
	_, err = r.c.RegisterNode(ctx, &meshpb.RegisterNodeRequest{
		NodeId: bob.id, NodeKey: bob.key.String(), Name: "phone", ProtocolVersion: meshproto.ProtocolVersion,
		ChallengeId: chr.GetChallengeId(), RegisterProof: meshproto.SealRegisterProof(ch, bob.key, bob.priv),
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("alice's challenge re-registered bob: err = %v", err)
	}

	chr, err = r.c.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{NodeId: alice.id, NodeKey: alice.key.String()})
	if err != nil {
		t.Fatal(err)
	}
	ch, _ = meshproto.ParseRegisterChallenge(chr.GetChallenge())
	_, err = r.c.RegisterNode(ctx, &meshpb.RegisterNodeRequest{
		AuthKey: "alice-token", NodeKey: alice.key.String(), Name: "laptop", ProtocolVersion: meshproto.ProtocolVersion,
		ChallengeId: chr.GetChallengeId(), RegisterProof: meshproto.SealRegisterProof(ch, alice.key, alice.priv),
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a re-registration challenge was spent on an enrollment: err = %v", err)
	}
}
