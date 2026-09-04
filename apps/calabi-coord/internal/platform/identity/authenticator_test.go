package identity

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"google.golang.org/grpc"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	pb "github.com/calabi/calabi/pkg/hooks-proto/hookspb"
)

type fakeRPC struct {
	resp *pb.ValidateTokenResponse
	err  error
}

func (f fakeRPC) ValidateToken(context.Context, *pb.ValidateTokenRequest, ...grpc.CallOption) (*pb.ValidateTokenResponse, error) {
	return f.resp, f.err
}

func newAuth(f fakeRPC) *Authenticator { return Wrap(slog.Default(), f) }

func TestResolveValidToken(t *testing.T) {
	a := newAuth(fakeRPC{resp: &pb.ValidateTokenResponse{
		Valid: true, UserId: 7, Roles: []string{"org:42 ws:7 scopes:tunnel.read"},
	}})
	got, err := a.Resolve(context.Background(), "tk_whatever")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Meshnet != core.MeshnetID(42) {
		t.Fatalf("meshnet = %d, want 42", got.Meshnet)
	}
}

func TestResolveInvalidToken(t *testing.T) {
	a := newAuth(fakeRPC{resp: &pb.ValidateTokenResponse{Valid: false}})
	if _, err := a.Resolve(context.Background(), "tk_bad"); !errors.Is(err, core.ErrAuthDenied) {
		t.Fatalf("err = %v, want ErrAuthDenied", err)
	}
}

func TestResolveValidButNoOrg(t *testing.T) {
	a := newAuth(fakeRPC{resp: &pb.ValidateTokenResponse{Valid: true, Roles: []string{"ws:7 scopes:x"}}})
	if _, err := a.Resolve(context.Background(), "tk_x"); !errors.Is(err, core.ErrAuthDenied) {
		t.Fatalf("err = %v, want ErrAuthDenied", err)
	}
}

func TestResolveRPCErrorFailsClosed(t *testing.T) {
	a := newAuth(fakeRPC{err: errors.New("identity-svc down")})
	if _, err := a.Resolve(context.Background(), "tk_x"); err == nil {
		t.Fatal("expected error (fail closed) when identity-svc errors")
	}
}
