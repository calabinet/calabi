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
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// startServerWithStore is startTestServer, also handing back the node store so
// a test can do what the admin API does to a node.
func startServerWithStore(t *testing.T) (meshpb.CoordinatorClient, core.NodeStore) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	nodes := core.NewMemNodeStore()
	coord := &core.Coordinator{
		Nodes:  nodes,
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
	return meshpb.NewCoordinatorClient(conn), nodes
}

// A disabled node's session stops working for every call, not only the netmap
// stream: before, a disabled device kept reporting endpoints and connections on
// the session it had earned while enabled.
func TestDisabledNodeLosesItsWholeSession(t *testing.T) {
	c, nodes := startServerWithStore(t)
	ctx := context.Background()
	n := register(t, c, "laptop")

	report := func() error {
		_, err := c.ReportEndpoints(ctx, &meshpb.ReportEndpointsRequest{
			NodeId: n.id, SessionToken: n.token, Endpoints: []string{"192.0.2.1:41641"},
		})
		return err
	}
	if err := report(); err != nil {
		t.Fatalf("control: an enabled node's report was refused: %v", err)
	}
	if err := nodes.SetDisabled(ctx, n.id, true); err != nil {
		t.Fatal(err)
	}
	if err := report(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("disabled node's report: err = %v, want PermissionDenied", err)
	}
	_, err := c.ReportConnections(ctx, &meshpb.ReportConnectionsRequest{SessionToken: n.token, NodeKey: n.key.String()})
	if status.Code(err) == codes.OK {
		t.Fatal("disabled node's connection report was accepted")
	}
}
