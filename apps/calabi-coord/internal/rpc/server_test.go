package rpc

import (
	"context"
	"log/slog"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

const devKey = "k1"

func nodeKeyB64(b byte) string {
	var k meshproto.NodeKey
	for i := range k {
		k[i] = b
	}
	return k.String()
}

func startTestServer(t *testing.T) meshpb.CoordinatorClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	coord := &core.Coordinator{
		Nodes:  core.NewMemNodeStore(),
		Policy: core.AllowAllPolicy{},
		IPAM:   core.NewMemIPAM(),
		DERP:   core.StaticDERP{Map: core.DERPMap{Regions: []core.DERPRegion{{Code: "lax"}}}},
	}
	auth := core.StaticAuth{Keys: map[string]core.Identity{devKey: {Meshnet: 1}}}
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
	return meshpb.NewCoordinatorClient(conn)
}

func register(t *testing.T, c meshpb.CoordinatorClient, keyByte byte, name string) *meshpb.RegisterNodeResponse {
	t.Helper()
	resp, err := c.RegisterNode(context.Background(), &meshpb.RegisterNodeRequest{
		AuthKey: devKey, NodeKey: nodeKeyB64(keyByte), Name: name,
	})
	if err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
	return resp
}

func peerKeys(nm *meshpb.NetMap) map[string]string {
	m := map[string]string{} // node_key -> overlay_addr
	for _, p := range nm.GetPeers() {
		m[p.GetNodeKey()] = p.GetOverlayAddr()
	}
	return m
}

func TestRegisterAndNetMapPush(t *testing.T) {
	c := startTestServer(t)
	ctx := context.Background()

	a := register(t, c, 1, "a")
	b := register(t, c, 2, "b")
	if a.GetOverlayAddr() != "100.64.0.1" {
		t.Fatalf("a overlay = %s, want 100.64.0.1", a.GetOverlayAddr())
	}

	// A opens its netmap stream; initial snapshot must show peer B with B's
	// node_key + overlay.
	stream, err := c.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: a.GetNodeId()})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	nm1, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv initial: %v", err)
	}
	if nm1.GetSelf().GetNodeId() != a.GetNodeId() {
		t.Fatalf("self = %d, want %d", nm1.GetSelf().GetNodeId(), a.GetNodeId())
	}
	pk := peerKeys(nm1)
	if got := pk[nodeKeyB64(2)]; got != b.GetOverlayAddr() {
		t.Fatalf("initial netmap: peer B overlay = %q, want %q (peers=%v)", got, b.GetOverlayAddr(), pk)
	}
	if len(pk) != 1 {
		t.Fatalf("initial peers = %d, want 1", len(pk))
	}

	// Registering C must PUSH a fresh netmap to A's already-open stream.
	cc := register(t, c, 3, "c")
	nm2, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv push: %v", err)
	}
	pk2 := peerKeys(nm2)
	if _, ok := pk2[nodeKeyB64(3)]; !ok {
		t.Fatalf("pushed netmap missing C (peers=%v)", pk2)
	}
	if pk2[nodeKeyB64(3)] != cc.GetOverlayAddr() {
		t.Fatalf("C overlay = %q, want %q", pk2[nodeKeyB64(3)], cc.GetOverlayAddr())
	}
	if len(pk2) != 2 {
		t.Fatalf("pushed peers = %d, want 2 (b,c)", len(pk2))
	}
}

func TestRegisterAuthDenied(t *testing.T) {
	c := startTestServer(t)
	_, err := c.RegisterNode(context.Background(), &meshpb.RegisterNodeRequest{
		AuthKey: "wrong", NodeKey: nodeKeyB64(9), Name: "x",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestPullNetMapUnknownNode(t *testing.T) {
	c := startTestServer(t)
	stream, err := c.PullNetMap(context.Background(), &meshpb.PullNetMapRequest{NodeId: 999})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

// A node reports the relay region it measured as closest along with its
// endpoints (MESH.4 B2b); the coordinator records it and peers see it as that
// node's derp_home — which is where they will relay traffic to it.
func TestReportEndpointsSetsMeasuredHome(t *testing.T) {
	c := startTestServer(t)
	ctx := context.Background()
	a := register(t, c, 1, "a")
	b := register(t, c, 2, "b")

	if _, err := c.ReportEndpoints(ctx, &meshpb.ReportEndpointsRequest{
		NodeId:     a.GetNodeId(),
		Endpoints:  []string{"203.0.113.7:41641"},
		HomeRegion: "lax",
	}); err != nil {
		t.Fatalf("report: %v", err)
	}

	stream, err := c.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: b.GetNodeId()})
	if err != nil {
		t.Fatalf("pull netmap: %v", err)
	}
	nm, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv netmap: %v", err)
	}
	var seen string
	for _, p := range nm.GetPeers() {
		if p.GetNodeKey() == nodeKeyB64(1) {
			seen = p.GetDerpHome()
		}
	}
	if seen != "lax" {
		t.Fatalf("peer a's derp_home = %q, want the region it reported (lax)", seen)
	}
}

// The coordinator publishes the relay map, so it also decides what a valid home
// is: a region it never published is refused rather than handed to peers.
func TestReportEndpointsRejectsUnknownHomeRegion(t *testing.T) {
	c := startTestServer(t)
	a := register(t, c, 1, "a")

	_, err := c.ReportEndpoints(context.Background(), &meshpb.ReportEndpointsRequest{
		NodeId:     a.GetNodeId(),
		Endpoints:  []string{"203.0.113.7:41641"},
		HomeRegion: "atlantis",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v (code %s), want InvalidArgument", err, status.Code(err))
	}
}
