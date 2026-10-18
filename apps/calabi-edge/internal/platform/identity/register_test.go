package identity

import (
	"context"
	"log/slog"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/calabinet/calabi/pkg/edge-proto/edgepb"
)

// recordingRPC keeps the RegisterEdgeNode request it was sent.
type recordingRPC struct {
	RPC
	got *pb.RegisterEdgeNodeRequest
}

func (r *recordingRPC) RegisterEdgeNode(_ context.Context, in *pb.RegisterEdgeNodeRequest, _ ...grpc.CallOption) (*pb.RegisterEdgeNodeResponse, error) {
	r.got = in
	return &pb.RegisterEdgeNodeResponse{}, nil
}

// RegisterEdgeNode copies EdgeRegistration into the request field by field, so
// a field the heartbeat carries and this drops never reaches the directory —
// for tls_passthrough that reads as "no node takes TLS endpoints".
func TestRegisterEdgeNode_SendsTLSPassthrough(t *testing.T) {
	for _, want := range []bool{true, false} {
		rpc := &recordingRPC{}
		v := Wrap(slog.Default(), rpc)
		if err := v.RegisterEdgeNode(context.Background(), EdgeRegistration{
			EdgeNodeID: 1, NodeLabel: "node-1", TLSPassthrough: want,
		}); err != nil {
			t.Fatalf("RegisterEdgeNode: %v", err)
		}
		if rpc.got == nil {
			t.Fatal("no request sent")
		}
		if got := rpc.got.GetTlsPassthrough(); got != want {
			t.Fatalf("tls_passthrough sent = %v, want %v", got, want)
		}
	}
}
