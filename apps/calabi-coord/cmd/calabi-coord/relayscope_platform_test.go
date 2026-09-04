package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	pb "github.com/calabi/calabi/pkg/hooks-proto/hookspb"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// stubMetering answers only ListDeniedOrgs; every other method of the embedded
// interface is nil and would panic if the code under test reached for it, which
// is the point — the scope source must ask exactly one question.
type stubMetering struct {
	pb.BillingHooksClient
	orgs []int64
	err  error
}

func (s *stubMetering) ListDeniedOrgs(context.Context, *pb.ListDeniedOrgsRequest, ...grpc.CallOption) (*pb.ListDeniedOrgsResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &pb.ListDeniedOrgsResponse{OrgIds: s.orgs}, nil
}

func scopeSourceWith(cli pb.BillingHooksClient) *relayScopeSource {
	return &relayScopeSource{cli: cli, logger: slog.New(slog.DiscardHandler), denied: map[int64]bool{}}
}

func node(meshnet core.MeshnetID) *core.Node { return &core.Node{Meshnet: meshnet} }

// An org over its cap keeps the relays it runs itself and loses the platform's.
// Downgrading the scope rather than withholding the grant is what makes that
// distinction expressible at all.
func TestScopeDowngradesOnlyTheOverCapOrg(t *testing.T) {
	s := scopeSourceWith(&stubMetering{orgs: []int64{7}})
	s.refresh()

	if got := s.For(context.Background(), node(7)); got != meshproto.RelayScopeSelfHosted {
		t.Errorf("over-cap org got scope %v, want self-hosted", got)
	}
	if got := s.For(context.Background(), node(8)); got != meshproto.RelayScopeAll {
		t.Errorf("org under cap got scope %v, want all", got)
	}
}

// Called while a netmap is being built, so it must answer immediately and it
// must fail OPEN: an org wrongly losing its relay fallback is a visible outage,
// an org relaying one more cycle is a cost.
func TestScopeFailsOpenBeforeAnythingIsKnown(t *testing.T) {
	s := scopeSourceWith(&stubMetering{err: errors.New("metering is down")})

	done := make(chan meshproto.RelayScope, 1)
	go func() { done <- s.For(context.Background(), node(7)) }()
	select {
	case got := <-done:
		if got != meshproto.RelayScopeAll {
			t.Fatalf("scope = %v before any fetch, want all (fail open)", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("For blocked the netmap build")
	}
}

// A metering outage FREEZES enforcement, it does not lift it. Clearing the view
// on error would turn every outage into an amnesty.
func TestScopeKeepsThePreviousViewWhenMeteringFails(t *testing.T) {
	cli := &stubMetering{orgs: []int64{7}}
	s := scopeSourceWith(cli)
	s.refresh()
	if s.For(context.Background(), node(7)) != meshproto.RelayScopeSelfHosted {
		t.Fatal("setup: org 7 should be denied")
	}

	cli.err = errors.New("metering is down")
	s.refresh()

	if got := s.For(context.Background(), node(7)); got != meshproto.RelayScopeSelfHosted {
		t.Fatalf("scope = %v after a failed refresh, want the previous view kept", got)
	}
}

// An org that comes back under its cap gets its scope back on the next refresh.
func TestScopeLiftsWhenTheOrgIsNoLongerOverCap(t *testing.T) {
	cli := &stubMetering{orgs: []int64{7}}
	s := scopeSourceWith(cli)
	s.refresh()

	cli.orgs = nil
	s.refresh()

	if got := s.For(context.Background(), node(7)); got != meshproto.RelayScopeAll {
		t.Fatalf("scope = %v after the org came back under cap, want all", got)
	}
}

// A refresh in flight must not spawn another on every netmap build.
func TestScopeDoesNotStampede(t *testing.T) {
	s := scopeSourceWith(&stubMetering{})
	s.mu.Lock()
	s.refreshing = true
	s.mu.Unlock()

	for i := 0; i < 10; i++ {
		_ = s.For(context.Background(), node(7))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.refreshing {
		t.Fatal("an in-flight refresh was cleared by a concurrent caller")
	}
}
