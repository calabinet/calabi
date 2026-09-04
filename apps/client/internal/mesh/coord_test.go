package mesh

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
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
}

func (f *fakeCoord) RegisterNode(_ context.Context, req *meshpb.RegisterNodeRequest) (*meshpb.RegisterNodeResponse, error) {
	f.mu.Lock()
	f.lastReg = req
	f.mu.Unlock()
	return f.reg, nil
}

func (f *fakeCoord) ReportEndpoints(_ context.Context, req *meshpb.ReportEndpointsRequest) (*meshpb.ReportEndpointsResponse, error) {
	f.mu.Lock()
	f.reportedEps = append(f.reportedEps, req.GetEndpoints())
	f.reportedHome = append(f.reportedHome, req.GetHomeRegion())
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

func (f *fakeCoord) PullNetMap(_ *meshpb.PullNetMapRequest, stream meshpb.Coordinator_PullNetMapServer) error {
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
	c := dialFake(t, &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 7, OverlayAddr: "100.64.0.7"}})
	reg, err := c.Register(context.Background(), RegisterParams{AuthKey: "tk_x", NodeKey: mustKey(1), Name: "laptop"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if reg.NodeID != 7 || reg.Overlay.String() != "100.64.0.7" {
		t.Fatalf("reg = %+v", reg)
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
