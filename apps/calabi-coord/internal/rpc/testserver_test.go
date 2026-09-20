package rpc

// Shared test harness. It lives in its own file (not in a repro_*_test.go)
// because scripts/export-public.sh drops every security-audit repro from the
// public tree, and server_test.go must still compile there.

import (
	"context"
	"log/slog"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

// startTwoOrgServer runs a coordinator with two orgs: org-a-key -> meshnet 1,
// org-b-key -> meshnet 2.
func startTwoOrgServer(t *testing.T) meshpb.CoordinatorClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	coord := &core.Coordinator{
		Nodes:  core.NewMemNodeStore(),
		Policy: core.AllowAllPolicy{},
		IPAM:   core.NewMemIPAM(),
		DERP:   core.StaticDERP{Map: core.DERPMap{Regions: []core.DERPRegion{{Code: "lax"}, {Code: "sgp"}}}},
	}
	auth := core.StaticAuth{Keys: map[string]core.Identity{
		"org-a-key": {Meshnet: 1},
		"org-b-key": {Meshnet: 2},
	}}
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
