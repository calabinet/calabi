package mesh

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

// reauthCoord is a coordinator stand-in that knows the two ways in: with an
// auth key, and back by proof alone. It records each registration's shape.
type reauthCoord struct {
	meshpb.UnimplementedCoordinatorServer
	offer     bool  // agree to node_reauth when asked
	reauthErr error // refuse proof-alone re-registrations with this

	mu        sync.Mutex
	pending   map[string]fakeChallenge
	seq       int
	calls     []string // "key" or "reauth:<node id>" per RegisterNode that got through
	challenge []*meshpb.GetRegisterChallengeRequest
	signedOut string
}

func (f *reauthCoord) GetRegisterChallenge(_ context.Context, req *meshpb.GetRegisterChallengeRequest) (*meshpb.GetRegisterChallengeResponse, error) {
	ch, ephPriv, err := meshproto.NewRegisterChallenge()
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.challenge = append(f.challenge, req)
	if f.pending == nil {
		f.pending = map[string]fakeChallenge{}
	}
	f.seq++
	id := fmt.Sprintf("ch-%d", f.seq)
	f.pending[id] = fakeChallenge{ch: ch, ephPriv: ephPriv}
	return &meshpb.GetRegisterChallengeResponse{ChallengeId: id, Challenge: ch.Encode()}, nil
}

func (f *reauthCoord) RegisterNode(_ context.Context, req *meshpb.RegisterNodeRequest) (*meshpb.RegisterNodeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pending[req.GetChallengeId()]
	delete(f.pending, req.GetChallengeId())
	key, err := meshproto.ParseNodeKey(req.GetNodeKey())
	if !ok || err != nil || meshproto.OpenRegisterProof(p.ch, p.ephPriv, key, req.GetRegisterProof()) != nil {
		return nil, status.Error(codes.Unauthenticated, "fake: proof rejected")
	}
	reauth := req.GetAuthKey() == "" && req.GetNodeId() != 0
	if reauth && f.reauthErr != nil {
		return nil, f.reauthErr
	}
	if !reauth && req.GetAuthKey() == "" {
		return nil, status.Error(codes.Unauthenticated, "fake: no auth key")
	}
	if reauth {
		f.calls = append(f.calls, fmt.Sprintf("reauth:%d", req.GetNodeId()))
	} else {
		f.calls = append(f.calls, "key")
	}
	resp := &meshpb.RegisterNodeResponse{NodeId: 42, OverlayAddr: "100.64.0.42", SessionToken: "tok"}
	for _, c := range req.GetCapabilities() {
		if f.offer && c == string(meshproto.CapNodeReauth) {
			resp.Capabilities = append(resp.Capabilities, c)
		}
	}
	return resp, nil
}

func (f *reauthCoord) SignOut(_ context.Context, req *meshpb.SignOutRequest) (*meshpb.SignOutResponse, error) {
	f.mu.Lock()
	f.signedOut = req.GetSessionToken()
	f.mu.Unlock()
	return &meshpb.SignOutResponse{}, nil
}

func (f *reauthCoord) registrations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func dialReauthCoord(t *testing.T, f *reauthCoord) *CoordClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	meshpb.RegisterCoordinatorServer(gs, f)
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(); gs.Stop(); _ = lis.Close() })
	return NewCoordClient(conn)
}

func reauthParams(authKey string) RegisterParams {
	return RegisterParams{AuthKey: authKey, NodeKey: testKey(1).Public(), NodePrivate: testKey(1), Name: "phone"}
}

// The first registration uses the key and learns the coordinator's offer; the
// next one comes back by proof alone, naming the node, with no key on the wire.
func TestReauthStateCarriesTheOfferToTheNextSession(t *testing.T) {
	f := &reauthCoord{offer: true}
	c := dialReauthCoord(t, f)
	ctx := context.Background()
	var saved []string
	st := NewReauthState(0, false, func(id int64, offered bool) { saved = append(saved, fmt.Sprintf("%d/%v", id, offered)) })

	for i := 0; i < 2; i++ {
		p := reauthParams("my-key")
		st.apply(&p)
		reg, err := c.Register(ctx, p)
		if err != nil {
			t.Fatalf("registration %d: %v", i+1, err)
		}
		st.record(reg)
	}
	if got := f.registrations(); len(got) != 2 || got[0] != "key" || got[1] != "reauth:42" {
		t.Fatalf("registrations = %v, want [key reauth:42]", got)
	}
	f.mu.Lock()
	last := f.challenge[len(f.challenge)-1]
	f.mu.Unlock()
	if last.GetAuthKey() != "" || last.GetNodeId() != 42 || last.GetNodeKey() != testKey(1).Public().String() {
		t.Fatalf("the proof-alone challenge request carried %v", last)
	}
	if !st.Offered() || len(saved) != 1 || saved[0] != "42/true" {
		t.Fatalf("Offered=%v, persisted %v; want true and one change 42/true", st.Offered(), saved)
	}
}

// A coordinator that did not offer node_reauth keeps getting the key.
func TestNoReauthWithoutTheOffer(t *testing.T) {
	f := &reauthCoord{offer: false}
	c := dialReauthCoord(t, f)
	st := NewReauthState(0, false, nil)
	for i := 0; i < 2; i++ {
		p := reauthParams("my-key")
		st.apply(&p)
		reg, err := c.Register(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		st.record(reg)
	}
	if got := f.registrations(); len(got) != 2 || got[0] != "key" || got[1] != "key" {
		t.Fatalf("registrations = %v, want the key both times", got)
	}
	if st.Offered() {
		t.Fatal("Offered without an offer")
	}
}

// A refused proof-alone re-registration falls back to the key — except when the
// node is disabled, or there is no key to fall back on; then the refusal itself
// comes back, so the caller can tell "enroll again" from "disabled".
func TestReauthFallback(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		refusal  error
		authKey  string
		wantCode codes.Code // codes.OK = succeeds
		wantRegs []string
	}{
		{"deleted, key in hand", status.Error(codes.NotFound, "gone"), "my-key", codes.OK, []string{"key"}},
		{"signed out, key in hand", status.Error(codes.FailedPrecondition, "signed out"), "my-key", codes.OK, []string{"key"}},
		{"credential no longer valid, key in hand", status.Error(codes.Unauthenticated, "revoked"), "my-key", codes.OK, []string{"key"}},
		{"disabled", status.Error(codes.PermissionDenied, "disabled"), "my-key", codes.PermissionDenied, nil},
		{"deleted, no key", status.Error(codes.NotFound, "gone"), "", codes.NotFound, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &reauthCoord{offer: true, reauthErr: tc.refusal}
			c := dialReauthCoord(t, f)
			p := reauthParams(tc.authKey)
			p.NodeID, p.Reauth = 42, true
			_, err := c.Register(ctx, p)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("err = %v, want %v", err, tc.wantCode)
			}
			if got := f.registrations(); fmt.Sprint(got) != fmt.Sprint(tc.wantRegs) {
				t.Fatalf("registrations = %v, want %v", got, tc.wantRegs)
			}
		})
	}
}

func TestSignOutSendsTheSession(t *testing.T) {
	f := &reauthCoord{}
	c := dialReauthCoord(t, f)
	if err := c.SignOut(context.Background()); err == nil {
		t.Fatal("signed out before registering")
	}
	if _, err := c.Register(context.Background(), reauthParams("my-key")); err != nil {
		t.Fatal(err)
	}
	if err := c.SignOut(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.signedOut != "tok" {
		t.Fatalf("SignOut carried session %q", f.signedOut)
	}
}
