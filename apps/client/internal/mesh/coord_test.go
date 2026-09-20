package mesh

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

// fakeCoord is a minimal in-test CoordinatorServer. The REAL server is covered
// by calabi-coord's own tests; here we only verify the client's use of the
// generated stub + its conversion logic against the shared meshpb contract.
type fakeCoord struct {
	meshpb.UnimplementedCoordinatorServer
	reg     *meshpb.RegisterNodeResponse
	netmaps []*meshpb.NetMap
	// endWatch returns from PullNetMap once the netmaps are sent, instead of
	// holding the stream open. That ends the session the way a dropped
	// connection does, which is what the runner retries on.
	endWatch bool

	mu           sync.Mutex
	lastReg      *meshpb.RegisterNodeRequest
	reportedEps  [][]string
	reportedHome []string      // home_region carried by each report
	reportedCh   chan []string // optional: signalled on each ReportEndpoints
	creds        []string      // "<call> <session_token>" per node-scoped call
	legacy       bool          // answer GetRegisterChallenge Unimplemented, like a pre-v2 coordinator
	pending      map[string]fakeChallenge
	seq          int
	proved       bool // a RegisterNode carried a proof that opened
}

func (f *fakeCoord) RegisterNode(_ context.Context, req *meshpb.RegisterNodeRequest) (*meshpb.RegisterNodeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastReg = req
	// A proof, when one is sent, is checked the way the real coordinator checks
	// it, so a client that seals with the wrong key fails here too.
	if id := req.GetChallengeId(); id != "" {
		p, ok := f.pending[id]
		delete(f.pending, id)
		key, err := meshproto.ParseNodeKey(req.GetNodeKey())
		if !ok || err != nil || meshproto.OpenRegisterProof(p.ch, p.ephPriv, key, req.GetRegisterProof()) != nil {
			return nil, status.Error(codes.Unauthenticated, "fake: registration proof rejected")
		}
		f.proved = true
	}
	return f.reg, nil
}

func (f *fakeCoord) ReportEndpoints(_ context.Context, req *meshpb.ReportEndpointsRequest) (*meshpb.ReportEndpointsResponse, error) {
	f.mu.Lock()
	f.reportedEps = append(f.reportedEps, req.GetEndpoints())
	f.reportedHome = append(f.reportedHome, req.GetHomeRegion())
	f.creds = append(f.creds, "endpoints "+req.GetSessionToken())
	ch := f.reportedCh
	f.mu.Unlock()
	if ch != nil {
		select {
		case ch <- req.GetEndpoints():
		default:
		}
	}
	return &meshpb.ReportEndpointsResponse{}, nil
}

// reports is how many endpoint reports have landed so far.
func (f *fakeCoord) reports() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reportedEps)
}

func (f *fakeCoord) PullNetMap(req *meshpb.PullNetMapRequest, stream meshpb.Coordinator_PullNetMapServer) error {
	f.mu.Lock()
	f.creds = append(f.creds, "netmap "+req.GetSessionToken())
	f.mu.Unlock()
	for _, nm := range f.netmaps {
		if err := stream.Send(nm); err != nil {
			return err
		}
	}
	if f.endWatch {
		return nil // the stream ends; Controller.Run returns
	}
	<-stream.Context().Done() // hold the stream open like the real server
	return stream.Context().Err()
}

func dialFake(t *testing.T, f *fakeCoord) *CoordClient {
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

func TestCoordRegister(t *testing.T) {
	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 7, OverlayAddr: "100.64.0.7"}}
	c := dialFake(t, f)
	reg, err := c.Register(context.Background(), RegisterParams{AuthKey: "tk_x", NodeKey: testKey(1).Public(), NodePrivate: testKey(1), Name: "laptop"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if reg.NodeID != 7 || reg.Overlay.String() != "100.64.0.7" {
		t.Fatalf("reg = %+v", reg)
	}
	f.mu.Lock()
	proved := f.proved
	f.mu.Unlock()
	if !proved {
		t.Fatal("the registration carried no proof of possession the coordinator could open")
	}
}

func TestCoordWatch(t *testing.T) {
	f := &fakeCoord{netmaps: []*meshpb.NetMap{
		{Self: &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"}},
		{Self: &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"},
			Peers: []*meshpb.Peer{{NodeId: 2, NodeKey: keyB64(2), OverlayAddr: "100.64.0.2"}}},
	}}
	c := dialFake(t, f)

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan NetMap, 4)
	done := make(chan error, 1)
	go func() { done <- c.Watch(ctx, 1, func(nm NetMap) { got <- nm }) }()

	// First push: no peers. Second: one peer. Then we cancel.
	nm1 := recvNetMap(t, got)
	if len(nm1.Peers) != 0 {
		t.Fatalf("nm1 peers = %d, want 0", len(nm1.Peers))
	}
	nm2 := recvNetMap(t, got)
	if len(nm2.Peers) != 1 || nm2.Peers[0].NodeID != 2 {
		t.Fatalf("nm2 peers = %+v", nm2.Peers)
	}
	cancel()
	select {
	case <-done: // Watch returned after cancel
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after cancel")
	}
}

func TestCoordReportEndpoints(t *testing.T) {
	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 5}}
	c := dialFake(t, f)
	eps := []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.10:41641"),
		netip.MustParseAddrPort("[2001:db8::1]:41641"),
	}
	if err := c.ReportEndpoints(context.Background(), 5, eps, "sgp"); err != nil {
		t.Fatalf("report: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reportedEps) != 1 || len(f.reportedEps[0]) != 2 {
		t.Fatalf("server received %v, want one report of 2 endpoints", f.reportedEps)
	}
	if f.reportedEps[0][0] != "192.168.1.10:41641" || f.reportedEps[0][1] != "[2001:db8::1]:41641" {
		t.Fatalf("endpoints round-tripped wrong: %v", f.reportedEps[0])
	}
	// The measured home region rides the same report (MESH.4 B2b).
	if len(f.reportedHome) != 1 || f.reportedHome[0] != "sgp" {
		t.Fatalf("home_region round-tripped as %v, want [sgp]", f.reportedHome)
	}
}

func recvNetMap(t *testing.T, ch <-chan NetMap) NetMap {
	t.Helper()
	select {
	case nm := <-ch:
		return nm
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for netmap")
		return NetMap{}
	}
}

func mustKey(b byte) (k meshproto.NodeKey) {
	for i := range k {
		k[i] = b
	}
	return k
}

func (f *fakeCoord) ReportServiceHealth(_ context.Context, req *meshpb.ReportServiceHealthRequest) (*meshpb.ReportServiceHealthResponse, error) {
	f.mu.Lock()
	f.creds = append(f.creds, "health "+req.GetSessionToken())
	f.mu.Unlock()
	return &meshpb.ReportServiceHealthResponse{}, nil
}

// testKey is a deterministic node private key for tests; Public() derives the
// matching node key, so a proof sealed with it opens against it.
func testKey(b byte) PrivateKey {
	var k PrivateKey
	for i := range k {
		k[i] = b
	}
	return k
}

type fakeChallenge struct {
	ch      meshproto.RegisterChallenge
	ephPriv [meshproto.KeyLen]byte
}

func (f *fakeCoord) GetRegisterChallenge(context.Context, *meshpb.GetRegisterChallengeRequest) (*meshpb.GetRegisterChallengeResponse, error) {
	if f.legacy {
		return nil, status.Error(codes.Unimplemented, "fake: coordinator predates mesh protocol v2")
	}
	ch, ephPriv, err := meshproto.NewRegisterChallenge()
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending == nil {
		f.pending = map[string]fakeChallenge{}
	}
	f.seq++
	id := fmt.Sprintf("ch-%d", f.seq)
	f.pending[id] = fakeChallenge{ch: ch, ephPriv: ephPriv}
	return &meshpb.GetRegisterChallengeResponse{ChallengeId: id, Challenge: ch.Encode()}, nil
}

func (f *fakeCoord) UpdateNodeDeclarations(_ context.Context, req *meshpb.UpdateNodeDeclarationsRequest) (*meshpb.UpdateNodeDeclarationsResponse, error) {
	f.mu.Lock()
	f.creds = append(f.creds, "declarations "+req.GetSessionToken())
	f.mu.Unlock()
	return &meshpb.UpdateNodeDeclarationsResponse{NodeId: 7}, nil
}

// Mesh protocol v2: every node-scoped call after Register carries the session
// token the coordinator returned. The coordinator refuses a call without one, so
// a call site that dropped it would take the node off the mesh; this pins all
// four, and the protocol version registration announces.
func TestCoordNodeScopedCallsCarryTheSessionToken(t *testing.T) {
	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 7, SessionToken: "tok-7"}, endWatch: true}
	c := dialFake(t, f)
	ctx := context.Background()
	p := RegisterParams{AuthKey: "tk_live", NodeKey: testKey(3).Public(), NodePrivate: testKey(3), Name: "nas"}
	if _, err := c.Register(ctx, p); err != nil {
		t.Fatalf("register: %v", err)
	}
	f.mu.Lock()
	ver := f.lastReg.GetProtocolVersion()
	f.mu.Unlock()
	if ver != meshproto.ProtocolVersion || ver < 2 {
		t.Fatalf("registered with protocol v%d, want the current version (at least 2)", ver)
	}
	if err := c.ReportEndpoints(ctx, 7, []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}, ""); err != nil {
		t.Fatalf("report endpoints: %v", err)
	}
	if err := c.ReportServiceHealth(ctx, 7, []ServiceHealthReport{{Name: "smb", Checked: true, TargetOK: true}}); err != nil {
		t.Fatalf("report health: %v", err)
	}
	if err := c.Watch(ctx, 7, func(NetMap) {}); err != nil && err != io.EOF {
		t.Fatalf("watch: %v", err)
	}
	if err := c.UpdateDeclarations(ctx, p); err != nil {
		t.Fatalf("update declarations: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, call := range []string{"endpoints", "health", "netmap", "declarations"} {
		found := false
		for _, got := range f.creds {
			if got == call+" tok-7" {
				found = true
			}
		}
		if !found {
			t.Fatalf("the %s call did not carry the session token; saw %v", call, f.creds)
		}
	}
}

// A coordinator that predates mesh protocol v2 has no challenge to answer. The
// client must still enroll with it - that is what lets the client ship before the
// coordinator - and must not send a proof it was never asked for.
func TestCoordRegisterWithAPreV2Coordinator(t *testing.T) {
	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 7}, legacy: true}
	c := dialFake(t, f)
	p := RegisterParams{AuthKey: "tk_x", NodeKey: testKey(1).Public(), NodePrivate: testKey(1), Name: "laptop"}
	if _, err := c.Register(context.Background(), p); err != nil {
		t.Fatalf("register against a pre-v2 coordinator: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lastReg.GetChallengeId() != "" || len(f.lastReg.GetRegisterProof()) != 0 {
		t.Fatalf("sent a proof nobody asked for: %+v", f.lastReg)
	}
}

// NodePrivate must be the private half of NodeKey. Anything else cannot prove
// possession, so it is refused before a round trip rather than by the
// coordinator after one.
func TestCoordRegisterRefusesAMissingOrMismatchedPrivateKey(t *testing.T) {
	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 7}}
	c := dialFake(t, f)
	for _, p := range []RegisterParams{
		{AuthKey: "tk_x", NodeKey: testKey(1).Public(), Name: "no-private"},
		{AuthKey: "tk_x", NodeKey: testKey(1).Public(), NodePrivate: testKey(2), Name: "wrong-private"},
	} {
		if _, err := c.Register(context.Background(), p); err == nil {
			t.Fatalf("%s: registered", p.Name)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lastReg != nil {
		t.Fatal("a registration went out without a usable private key")
	}
}

// The private key must never print: RegisterParams is exactly the kind of struct
// that ends up in a %+v while someone is debugging.
func TestPrivateKeyDoesNotPrint(t *testing.T) {
	k := testKey(9)
	for _, s := range []string{
		fmt.Sprint(k),
		fmt.Sprintf("%v", RegisterParams{NodePrivate: k}),
		fmt.Sprintf("%+v", RegisterParams{NodePrivate: k}),
	} {
		if strings.Contains(s, k.Hex()) || strings.Contains(s, "9 9 9") {
			t.Fatalf("the private key printed: %s", s)
		}
	}
}
