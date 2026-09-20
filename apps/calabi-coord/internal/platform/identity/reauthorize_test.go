package identity

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"google.golang.org/grpc"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	pb "github.com/calabinet/calabi/pkg/hooks-proto/hookspb"
)

// checkingRPC answers CheckEnrollment as well, and records what it was asked.
type checkingRPC struct {
	fakeRPC
	valid bool
	err   error
	got   *pb.CheckEnrollmentRequest
}

func (c *checkingRPC) CheckEnrollment(_ context.Context, in *pb.CheckEnrollmentRequest, _ ...grpc.CallOption) (*pb.CheckEnrollmentResponse, error) {
	c.got = in
	if c.err != nil {
		return nil, c.err
	}
	return &pb.CheckEnrollmentResponse{Valid: c.valid, Reason: "test"}, nil
}

// What a credential enrolls AS: the person for a login token, the key itself for
// an API key (identity-svc's "apikey:<id>" role), never the key's minter.
func TestResolveNamesThePrincipal(t *testing.T) {
	for name, tc := range map[string]struct {
		resp *pb.ValidateTokenResponse
		want string
	}{
		"login token":                        {&pb.ValidateTokenResponse{Valid: true, UserId: 7, Roles: []string{"org:42 ws:1 scopes:org.role.developer"}}, "user:7"},
		"api key":                            {&pb.ValidateTokenResponse{Valid: true, Roles: []string{"org:42 ws:1 scopes:tunnel.write", "actor:7", "apikey:99"}}, "apikey:99"},
		"api key from an older identity-svc": {&pb.ValidateTokenResponse{Valid: true, Roles: []string{"org:42 ws:1 scopes:tunnel.write", "actor:7"}}, ""},
	} {
		got, err := newAuth(fakeRPC{resp: tc.resp}).Resolve(context.Background(), "k")
		if err != nil || got.Principal != tc.want {
			t.Errorf("%s: principal %q, %v; want %q", name, got.Principal, err, tc.want)
		}
	}
}

func TestReauthorize(t *testing.T) {
	ctx := context.Background()
	rpc := &checkingRPC{valid: true}
	a := Wrap(slog.Default(), rpc)

	if err := a.Reauthorize(ctx, 42, "apikey:99"); err != nil {
		t.Fatalf("valid key: %v", err)
	}
	if rpc.got.GetOrgId() != 42 || rpc.got.GetApiKeyId() != 99 || rpc.got.GetUserId() != 0 {
		t.Fatalf("asked %v", rpc.got)
	}
	if err := a.Reauthorize(ctx, 42, "user:7"); err != nil || rpc.got.GetUserId() != 7 || rpc.got.GetApiKeyId() != 0 {
		t.Fatalf("user: %v, asked %v", err, rpc.got)
	}

	rpc.valid = false
	if err := a.Reauthorize(ctx, 42, "user:7"); !errors.Is(err, core.ErrAuthDenied) {
		t.Fatalf("no longer valid: err = %v, want ErrAuthDenied", err)
	}
	rpc.err = errors.New("unreachable")
	if err := a.Reauthorize(ctx, 42, "user:7"); err == nil || errors.Is(err, core.ErrAuthDenied) {
		t.Fatalf("identity down: err = %v, want a non-denial error (refused, retryable)", err)
	}

	// Nothing to check: refused without asking.
	rpc.err, rpc.got = nil, nil
	for _, p := range []string{"", "user:", "user:x", "robot:3", "apikey:-1"} {
		if err := a.Reauthorize(ctx, 42, p); !errors.Is(err, core.ErrAuthDenied) {
			t.Errorf("principal %q: err = %v, want ErrAuthDenied", p, err)
		}
	}
	if rpc.got != nil {
		t.Fatalf("an unusable principal still reached the identity service: %v", rpc.got)
	}

	// A client that can only validate tokens cannot vouch for anyone.
	if err := newAuth(fakeRPC{}).Reauthorize(ctx, 42, "user:7"); err == nil {
		t.Fatal("a client without CheckEnrollment let a node back in")
	}
}
