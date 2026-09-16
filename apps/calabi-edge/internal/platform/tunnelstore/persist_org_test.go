// persist_org_test.go — Persist must not adopt another org's tunnel row.
//
// THE BUG THIS PINS (observed 2026-09-15). An edge's subdomain sequence is
// file-backed local state. That edge ran with state.dir = /tmp inside a
// container with no volume, so a redeploy wiped the counter and it restarted at
// u000001 — a name a live row from ANOTHER org already held.
//
// CreateTunnel then answered AlreadyExists, and Persist's idempotency branch
// resolved the row BY DOMAIN — a global key with no org scoping — and handed it
// back as "the tunnel we just registered". The edge stamped
// ReportStatus(enabled) on a stranger's row, the route for that domain pointed
// at this edge, and the user who ran `calabi http` saw their tunnel in nobody's
// console while their traffic was served under somebody else's identity.
//
// Idempotency across a reconnect is the branch's purpose and still works: the
// SAME org resolving the SAME domain gets the same row back.
//
// RUN: go test./apps/calabi-edge/internal/platform/tunnelstore/ -run TestPersist -v
package tunnelstore_test

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabi/calabi/apps/calabi-edge/internal/platform/tunnelstore"
	pb "github.com/calabi/calabi/pkg/edge-proto/edgepb"
)

// collidingRPC always refuses CreateTunnel with AlreadyExists and resolves the
// domain to a row owned by resolvedOrg — the shape of a sequence collision.
type collidingRPC struct {
	tunnelstore.RPC
	resolvedOrg    int64
	resolvedID     int64
	resolveCalls   int
	createAttempts int
}

func (f *collidingRPC) CreateTunnel(ctx context.Context, in *pb.CreateTunnelRequest, opts ...grpc.CallOption) (*pb.Tunnel, error) {
	f.createAttempts++
	return nil, status.Error(codes.AlreadyExists, "domain taken")
}

func (f *collidingRPC) Resolve(ctx context.Context, in *pb.ResolveRequest, opts ...grpc.CallOption) (*pb.ResolveResponse, error) {
	f.resolveCalls++
	return &pb.ResolveResponse{
		Found: true,
		Tunnel: &pb.Tunnel{
			Meta:  &pb.ResourceMeta{Id: f.resolvedID},
			OrgId: f.resolvedOrg,
		},
	}, nil
}

func persistHTTP(t *testing.T, rpc tunnelstore.RPC, orgID int64) (tunnelstore.PersistResult, error) {
	t.Helper()
	return testClient(t, rpc).Persist(context.Background(), tunnelstore.PersistInput{
		OrgID:     orgID,
		Type:      "http",
		Domain:    "u000001.lax.calabi.online",
		LocalAddr: "127.0.0.1:8083",
	})
}

func TestPersistRefusesARowOwnedByAnotherOrg(t *testing.T) {
	rpc := &collidingRPC{resolvedOrg: 9, resolvedID: 23}
	res, err := persistHTTP(t, rpc, 6)
	if err == nil {
		t.Fatalf("Persist adopted org 9's tunnel #%d for org 6 — the edge would serve "+
			"this user's traffic on a stranger's row and the tunnel would appear in "+
			"nobody's console", res.TunnelID)
	}
	if res.TunnelID != 0 {
		t.Errorf("TunnelID = %d on refusal, want 0 (a non-zero id gets ReportStatus stamped on it)", res.TunnelID)
	}
	// The message has to name the cause: an operator reading it needs to reach
	// "this edge's subdomain state is not persistent", not "domain taken".
	if !strings.Contains(err.Error(), "another organization") {
		t.Errorf("error does not say whose it is: %v", err)
	}
}

// Idempotency — the reason the branch exists — must survive the fix.
func TestPersistStillAdoptsItsOwnRowOnReconnect(t *testing.T) {
	rpc := &collidingRPC{resolvedOrg: 6, resolvedID: 23}
	res, err := persistHTTP(t, rpc, 6)
	if err != nil {
		t.Fatalf("Persist refused the caller's OWN row: %v — an edge reconnect "+
			"re-creating the same domain must resolve to the same tunnel", err)
	}
	if res.TunnelID != 23 {
		t.Errorf("TunnelID = %d, want 23", res.TunnelID)
	}
}

// A row with no org is unknown, not foreign: refusing
// on "unknown" would break a path that had nothing to do with this bug.
func TestPersistToleratesAnUnknownOrgOnEitherSide(t *testing.T) {
	for _, tc := range []struct {
		name              string
		rowOrg, callerOrg int64
	}{
		{"row has no org", 0, 6},
		{"caller has no org", 9, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rpc := &collidingRPC{resolvedOrg: tc.rowOrg, resolvedID: 23}
			if _, err := persistHTTP(t, rpc, tc.callerOrg); err != nil {
				t.Fatalf("refused on an UNKNOWN org: %v", err)
			}
		})
	}
}
