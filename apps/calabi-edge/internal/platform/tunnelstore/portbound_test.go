// portbound_test.go — a Claim refused for a port collision must be TYPED.
//
// The untyped version is what made a user's tunnel disappear. Real log, real
// edge:
//
//	claim failed, falling back to Persist — orphan source row will be cleaned up
//	  claim_tunnel_id=969 err="AlreadyExists: edge=101 port=20000 already bound"
//	cleaning up orphan row left by failed Claim  orphan=969 new=928
//
// 969 was the row the console had just created. Persist adopted 928 — an
// UNRELATED older row that happened to hold (101, 20000) — and the fallback
// then soft-deleted 969. The console showed a tunnel that the list did not
// have, because it no longer existed.
//
// The sentinel is what lets OnProxyOpened hard-fail instead of falling through.
//
// RUN: go test./apps/calabi-edge/internal/platform/tunnelstore/ -run TestClaimPortBound -v
package tunnelstore_test

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/tunnelstore"
)

func TestClaimPortBoundIsTyped(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error // nil = must NOT match any hard-fail sentinel
	}{
		{
			"port already bound on this edge",
			status.Error(codes.AlreadyExists, "store: already exists: edge=101 port=20000 already bound"),
			tunnelstore.ErrPortBound,
		},
		{
			"admin disabled",
			status.Error(codes.PermissionDenied, "disabled"),
			tunnelstore.ErrTunnelDisabled,
		},
		{
			"ownership conflict",
			status.Error(codes.FailedPrecondition, "owned elsewhere"),
			tunnelstore.ErrClaimConflict,
		},
		{
			// The case the Persist fallback actually exists for: the pending row
			// went away between the push and the claim. It must STAY untyped, or
			// `calabi http 8080` against a deleted pending row stops recreating.
			"pending row vanished",
			status.Error(codes.NotFound, "no such tunnel"),
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, &fakeRPC{claimErr: tc.err})
			_, err := c.Claim(context.Background(), tunnelstore.ClaimInput{
				TunnelID: 969, OrgID: 3, ClientID: 31, RemotePort: 20000,
			})
			if err == nil {
				t.Fatal("Claim succeeded, want an error")
			}
			if tc.want == nil {
				for _, s := range []error{
					tunnelstore.ErrPortBound,
					tunnelstore.ErrTunnelDisabled,
					tunnelstore.ErrClaimConflict,
				} {
					if errors.Is(err, s) {
						t.Fatalf("err matched %v; this one must fall through to Persist", s)
					}
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want it to match %v", err, tc.want)
			}
		})
	}
}
