package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	proto "github.com/calabinet/calabi/pkg/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFriendlyCLIError(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{status.Error(codes.Unavailable, "dial tcp 10.0.0.1:7001: connection refused"), "temporarily unavailable"},
		{status.Error(codes.FailedPrecondition, "store: invitation expired"), "new invitation"},
		{status.Error(codes.PermissionDenied, "only org owners can renew subscriptions"), "organization owner"},
		{status.Error(codes.Internal, "sql: secret connection details"), "contact support"},
		{fmt.Errorf("register: %w", &proto.ErrorPayload{Code: proto.CodeForbidden, MessageEN: "custom domain \"shop.example.com\" is not registered; create it first"}), "shop.example.com"},
		{context.Canceled, "cancelled"},
	} {
		got := friendlyCLIError(tc.err)
		if !strings.Contains(got, tc.want) || strings.Contains(got, "rpc error") || strings.Contains(got, "code=") || strings.Contains(got, "secret") || strings.Contains(got, "10.0.0.1") {
			t.Fatalf("bad CLI message: %q", got)
		}
	}
	local := errors.New("could not open settings.yaml: permission denied")
	if friendlyCLIError(local) != local.Error() {
		t.Fatal("local configuration detail was lost")
	}
}
