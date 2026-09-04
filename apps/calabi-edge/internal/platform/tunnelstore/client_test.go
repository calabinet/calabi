package tunnelstore_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabi/calabi/apps/calabi-edge/internal/platform/tunnelstore"
	pb "github.com/calabi/calabi/pkg/edge-proto/edgepb"
)

// fakeRPC embeds the RPC interface so unimplemented methods are present
// (they panic if called, which the tests below never do). Only the two
// methods exercised by are overridden.
type fakeRPC struct {
	tunnelstore.RPC
	claimErr error
	listResp *pb.ListTunnelsResponse
}

func (f *fakeRPC) ClaimTunnel(ctx context.Context, in *pb.ClaimTunnelRequest, opts ...grpc.CallOption) (*pb.Tunnel, error) {
	if f.claimErr != nil {
		return nil, f.claimErr
	}
	return &pb.Tunnel{Meta: &pb.ResourceMeta{Id: in.GetId()}}, nil
}

func (f *fakeRPC) ListTunnels(ctx context.Context, in *pb.ListTunnelsRequest, opts ...grpc.CallOption) (*pb.ListTunnelsResponse, error) {
	return f.listResp, nil
}

func testClient(t *testing.T, rpc tunnelstore.RPC) *tunnelstore.Client {
	t.Helper()
	return tunnelstore.Wrap(slog.New(slog.NewTextHandler(io.Discard, nil)), rpc, 7, "edge1", "")
}

// a PermissionDenied from ClaimTunnel (admin-disabled) must surface
// as the typed ErrTunnelDisabled so OnProxyOpened hard-fails instead of
// falling back to Persist (which would resurrect the tunnel).
func TestClaim_DisabledMapsToSentinel(t *testing.T) {
	c := testClient(t, &fakeRPC{claimErr: status.Error(codes.PermissionDenied, "tunnel disabled by admin")})
	_, err := c.Claim(context.Background(), tunnelstore.ClaimInput{TunnelID: 5, OrgID: 1})
	if !errors.Is(err, tunnelstore.ErrTunnelDisabled) {
		t.Fatalf("want ErrTunnelDisabled, got %v", err)
	}
}

// a FailedPrecondition ("already claimed by another edge" — a genuine
// ownership conflict) maps to the typed ErrClaimConflict so OnProxyOpened
// hard-fails instead of falling back to Persist+orphan-delete (which used to
// mint duplicate TCP rows). It must NOT be confused with the admin-disabled
// sentinel. tunnel-svc now re-homes legitimate same-client/same-region claims
// in place, so a FailedPrecondition here is a real conflict, not churn.
func TestClaim_FailedPrecondMapsToConflict(t *testing.T) {
	c := testClient(t, &fakeRPC{claimErr: status.Error(codes.FailedPrecondition, "already claimed")})
	_, err := c.Claim(context.Background(), tunnelstore.ClaimInput{TunnelID: 5, OrgID: 1})
	if !errors.Is(err, tunnelstore.ErrClaimConflict) {
		t.Fatalf("want ErrClaimConflict, got %v", err)
	}
	if errors.Is(err, tunnelstore.ErrTunnelDisabled) {
		t.Fatalf("FailedPrecondition must not map to ErrTunnelDisabled: %v", err)
	}
}

// NotFound (the "pending row was deleted between push and claim" case) must
// keep the old behavior: a raw error that is NEITHER sentinel, so OnProxyOpened
// still falls back to Persist and re-creates the row.
func TestClaim_NotFoundFallsThrough(t *testing.T) {
	c := testClient(t, &fakeRPC{claimErr: status.Error(codes.NotFound, "row gone")})
	_, err := c.Claim(context.Background(), tunnelstore.ClaimInput{TunnelID: 5, OrgID: 1})
	if err == nil {
		t.Fatalf("expected an error")
	}
	if errors.Is(err, tunnelstore.ErrClaimConflict) || errors.Is(err, tunnelstore.ErrTunnelDisabled) {
		t.Fatalf("NotFound must stay a raw error (Persist fallback path), got sentinel: %v", err)
	}
}

// the Phase-C catch-up must drop admin-disabled rows so the daemon
// never attempts a NEW_PROXY for them.
func TestListByClient_SkipsAdminDisabled(t *testing.T) {
	c := testClient(t, &fakeRPC{listResp: &pb.ListTunnelsResponse{Items: []*pb.Tunnel{
		{Meta: &pb.ResourceMeta{Id: 1}, ClientId: 42, DisabledByAdmin: false},
		{Meta: &pb.ResourceMeta{Id: 2}, ClientId: 42, DisabledByAdmin: true},
		{Meta: &pb.ResourceMeta{Id: 3}, ClientId: 99, DisabledByAdmin: false}, // other client
	}}})
	out, err := c.ListByClient(context.Background(), 1, 42)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out) != 1 || out[0].GetMeta().GetId() != 1 {
		ids := make([]int64, len(out))
		for i, o := range out {
			ids[i] = o.GetMeta().GetId()
		}
		t.Fatalf("want only enabled row id=1, got ids=%v", ids)
	}
}
