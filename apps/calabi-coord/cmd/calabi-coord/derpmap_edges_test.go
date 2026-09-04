package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/grpc"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	pb "github.com/calabi/calabi/pkg/hooks-proto/hookspb"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type fakeEdgeLister struct {
	resp  *pb.ListRelayEndpointsResponse
	err   error
	calls int
}

func (f *fakeEdgeLister) ListRelayEndpoints(_ context.Context, _ *pb.ListRelayEndpointsRequest, _ ...grpc.CallOption) (*pb.ListRelayEndpointsResponse, error) {
	f.calls++
	return f.resp, f.err
}

// buildDERPFromEdges keeps only relay-running edges, groups them by region, and
// takes the relay host from public_addr (a merged node's control + relay share a
// host). This is the whole of "one source of truth = the edge configs".
func TestBuildDERPFromEdges(t *testing.T) {
	fallback := core.DERPMap{Regions: []core.DERPRegion{{Code: "static"}}}
	edges := []*pb.RelayEndpoint{
		{Region: "lax", Host: "edge01-lax.calabi.net:7443", DerpPort: 3340, StunPort: 3478},
		{Region: "lax", Host: "edge02-lax.calabi.net:7443", DerpPort: 3340, StunPort: 3478},
		{Region: "sgp", Host: "edge-sgp.calabi.net:7443", DerpPort: 3340}, // no STUN
		{Region: "fra", Host: "edge-fra.calabi.net:7443", DerpPort: 0},    // NOT a relay
		{Region: "", Host: "no-region:7443", DerpPort: 3340},              // no region → skipped
	}
	got := buildDERPFromEdges(edges, fallback)

	if len(got.Regions) != 2 {
		t.Fatalf("regions = %d, want 2 (lax, sgp); fra/no-region excluded: %+v", len(got.Regions), got.Regions)
	}
	// Sorted by code: lax first, sgp second.
	lax := got.Regions[0]
	if lax.Code != "lax" || len(lax.Nodes) != 2 {
		t.Fatalf("lax region = %+v, want 2 nodes", lax)
	}
	// Host is stripped of the control port; relay port is 3340.
	if lax.Nodes[0].HostName != "edge01-lax.calabi.net" || lax.Nodes[0].DERPPort != 3340 || lax.Nodes[0].STUNPort != 3478 {
		t.Fatalf("lax node[0] = %+v, want host edge01-lax.calabi.net:3340 stun 3478", lax.Nodes[0])
	}
	sgp := got.Regions[1]
	if sgp.Code != "sgp" || len(sgp.Nodes) != 1 || sgp.Nodes[0].STUNPort != 0 {
		t.Fatalf("sgp region = %+v, want 1 node with no STUN", sgp)
	}
}

// With no relay-running edge the deployment keeps whatever the static
// CALABI_COORD_DERP_ADDR / _MAP_FILE named — never an empty map.
func TestBuildDERPFromEdgesEmptyReturnsFallback(t *testing.T) {
	fallback := core.DERPMap{Regions: []core.DERPRegion{{Code: "static", Nodes: []core.DERPNode{{HostName: "h", DERPPort: 3340}}}}}
	got := buildDERPFromEdges([]*pb.RelayEndpoint{{Region: "lax", DerpPort: 0}}, fallback)
	if !derpMapEqual(got, fallback) {
		t.Fatalf("no relay edges must return the fallback, got %+v", got)
	}
}

// refresh reports a change only when the map actually changed, and an identity
// error must keep the previous map rather than blank the fleet's relays.
func TestRefreshChangeDetectionAndErrorKeepsPrevious(t *testing.T) {
	ctx := context.Background()
	lister := &fakeEdgeLister{resp: &pb.ListRelayEndpointsResponse{Items: []*pb.RelayEndpoint{
		{Region: "lax", Host: "h1:7443", DerpPort: 3340},
	}}}
	p := newPlatformDERPFromEdges(lister, core.DERPMap{}, quietLogger())

	if !p.refresh(ctx) {
		t.Fatal("first refresh (empty fallback → one region) should report a change")
	}
	if p.refresh(ctx) {
		t.Fatal("an identical refresh should report no change")
	}
	before := p.Current()

	lister.err = errors.New("identity down")
	if p.refresh(ctx) {
		t.Fatal("a failed refresh must report no change")
	}
	if !derpMapEqual(p.Current(), before) {
		t.Fatalf("a failed refresh must keep the previous map, got %+v", p.Current())
	}

	// Recovery with a different relay set swaps in and reports the change.
	lister.err = nil
	lister.resp = &pb.ListRelayEndpointsResponse{Items: []*pb.RelayEndpoint{
		{Region: "lax", Host: "h1:7443", DerpPort: 3340},
		{Region: "sgp", Host: "h2:7443", DerpPort: 3340},
	}}
	if !p.refresh(ctx) {
		t.Fatal("a changed edge set should report a change")
	}
	if len(p.Current().Regions) != 2 {
		t.Fatalf("recovered map should have 2 regions, got %+v", p.Current())
	}
}
