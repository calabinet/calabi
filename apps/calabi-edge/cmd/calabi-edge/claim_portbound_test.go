// claim_portbound_test.go — what the edge DOES when a claim is refused for a
// port collision, as opposed to what it logs.
//
// tunnelstore has a test that the refusal is typed (portbound_test.go). This
// one is about the three things the adapter must then do, none of which that
// test can see:
//
//	reserve the number      — it came out of this process's pool, so the pool
//	                          is what is wrong; the next attempt must not get
//	                          the same one back
//	say so on the ROW       — otherwise the console shows 待接入 about a
//	                          client that is running and did try, forever,
//	                          because nothing retries a refused claim
//	do NOT fall through     — Persist would adopt the row that holds the port
//	                          and soft-delete the one the user just created
//
// RUN: go test./apps/calabi-edge/cmd/calabi-edge/ -run TestClaimPortBound -v
package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabi/calabi/apps/calabi-edge/internal/platform/tunnelstore"
	"github.com/calabi/calabi/apps/calabi-edge/internal/router"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
	pb "github.com/calabi/calabi/pkg/edge-proto/edgepb"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// portBoundRPC is tunnel-svc with (1000400000, 20000) already bound to some
// other live row — the state that produced the user's log line.
type portBoundRPC struct {
	creates  int
	statuses []reportedStatus
}

type reportedStatus struct {
	id     int64
	status string
	reason string
}

func (f *portBoundRPC) ClaimTunnel(context.Context, *pb.ClaimTunnelRequest, ...grpc.CallOption) (*pb.Tunnel, error) {
	return nil, status.Error(codes.AlreadyExists,
		"store: already exists: edge=1000400000 port=20000 already bound")
}

func (f *portBoundRPC) CreateTunnel(context.Context, *pb.CreateTunnelRequest, ...grpc.CallOption) (*pb.Tunnel, error) {
	f.creates++
	return &pb.Tunnel{Meta: &pb.ResourceMeta{Id: 999}}, nil
}

func (f *portBoundRPC) ReportStatus(_ context.Context, in *pb.ReportStatusRequest, _ ...grpc.CallOption) (*pb.ReportStatusResponse, error) {
	f.statuses = append(f.statuses, reportedStatus{
		id: in.GetTunnelId(), status: in.GetStatus(), reason: in.GetReason(),
	})
	return &pb.ReportStatusResponse{}, nil
}

func (f *portBoundRPC) GetTunnelOAuthSecret(context.Context, *pb.GetTunnelOAuthSecretRequest, ...grpc.CallOption) (*pb.GetTunnelOAuthSecretResponse, error) {
	return &pb.GetTunnelOAuthSecretResponse{}, nil
}
func (f *portBoundRPC) ListTunnels(context.Context, *pb.ListTunnelsRequest, ...grpc.CallOption) (*pb.ListTunnelsResponse, error) {
	return &pb.ListTunnelsResponse{}, nil
}
func (f *portBoundRPC) ListEdgeClaimedPorts(context.Context, *pb.ListEdgeClaimedPortsRequest, ...grpc.CallOption) (*pb.ListEdgeClaimedPortsResponse, error) {
	return &pb.ListEdgeClaimedPortsResponse{}, nil
}
func (f *portBoundRPC) DeleteTunnel(context.Context, *pb.DeleteTunnelRequest, ...grpc.CallOption) (*pb.DeleteTunnelResponse, error) {
	return &pb.DeleteTunnelResponse{}, nil
}
func (f *portBoundRPC) Resolve(context.Context, *pb.ResolveRequest, ...grpc.CallOption) (*pb.ResolveResponse, error) {
	return &pb.ResolveResponse{}, nil
}

func TestClaimPortBoundReservesReportsAndRefuses(t *testing.T) {
	rpc := &portBoundRPC{}
	pool := router.NewPortPool(20000, 20999)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := &tunnelPersisterAdapter{
		tc:        tunnelstore.Wrap(log, rpc, testEdgeID, "edge-a", "cn-a.calabi.net"),
		logger:    log,
		edgeLabel: "edge-a",
		index:     &tunnelIDIndex{},
		ports:     pool,
	}

	sess := &session.Session{TenantID: "4", DeviceID: 7}
	p := &session.Proxy{
		ID: "px-1", Type: proto.ProxyKindUDP, Name: "test-udp01",
		LocalAddr: "192.168.1.222:5001", RemotePort: 20000, ClaimTunnelID: 28,
	}

	id, err := a.OnProxyOpened(sess, p)
	if err == nil {
		t.Fatal("a port collision must fail the NEW_PROXY, not be swallowed")
	}
	if id != 0 {
		t.Fatalf("tunnel id = %d, want 0 — nothing was claimed", id)
	}
	// The fallback is what deleted a user's tunnel once (see portbound_test.go).
	if rpc.creates != 0 {
		t.Fatalf("Persist ran %d time(s) after a port collision; it must not — it "+
			"adopts the row holding the port and soft-deletes this one", rpc.creates)
	}

	// The number is out of circulation, so the next tunnel gets a free one.
	if got, ok := pool.Allocate(); !ok || got == 20000 {
		t.Fatalf("Allocate = %d (ok=%v); the colliding port must not be handed out again",
			got, ok)
	}

	// And the row says why, instead of sitting at 待接入.
	var said *reportedStatus
	for i := range rpc.statuses {
		if rpc.statuses[i].id == 28 {
			said = &rpc.statuses[i]
		}
	}
	if said == nil {
		t.Fatal("nothing was reported on the row; the console still shows this " +
			"tunnel as waiting for a client that is running and already tried")
	}
	if said.status != "error" {
		t.Fatalf("reported status = %q, want \"error\" — effectiveState checks "+
			"status before it checks edge_node_id, and that is what stops the "+
			"list from saying pending", said.status)
	}
	if !strings.HasPrefix(said.reason, "port_in_use:") || !strings.HasSuffix(said.reason, "20000") {
		t.Fatalf("reason = %q, want a port_in_use code naming 20000", said.reason)
	}
}
