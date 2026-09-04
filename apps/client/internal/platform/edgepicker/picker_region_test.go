package edgepicker

// picker_region_test.go — an explicit region choice outranks the sticky edge.
//
// /v1/edges?region=X is deliberately over-answered: bff-console tops the list up
// with the org's own edges from EVERY region, so a daemon anchored where it owns
// nothing still lands on its own edge. With two self-hosted edges that superset
// let the sticky preference re-select the edge the user had just asked to leave.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ejr is ej with a region.
func ejr(id int64, addr, region string, owned bool, active int32) edgeJSON {
	e := ej(id, addr, owned, active)
	e.Region = region
	return e
}

func TestNarrowToRegion(t *testing.T) {
	a := ejr(1, "a:7443", "cd-vps", true, 0)
	b := ejr(2, "b:7443", "cd-vps-02", true, 0)
	lax := ejr(3, "lax:7443", "lax", false, 0)

	cases := []struct {
		name    string
		in      []edgeJSON
		region  string
		wantIDs []int64
	}{
		{"any-region query is untouched", []edgeJSON{a, b, lax}, "", []int64{1, 2, 3}},
		{"drops the other region's edges", []edgeJSON{a, b}, "cd-vps", []int64{1}},
		{"drops them the other way too", []edgeJSON{a, b}, "cd-vps-02", []int64{2}},
		// The BYOI affinity case the over-answer exists for: nothing of the org's
		// own is in the anchored region, so the out-of-region edge must stand.
		{"nothing in the region → keep everything", []edgeJSON{a, b}, "lax", []int64{1, 2}},
		{"all already in the region", []edgeJSON{a}, "cd-vps", []int64{1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ids(narrowToRegion(slog.Default(), tc.in, tc.region))
			if len(got) != len(tc.wantIDs) {
				t.Fatalf("got %v want %v", got, tc.wantIDs)
			}
			for i := range got {
				if got[i] != tc.wantIDs[i] {
					t.Fatalf("got %v want %v", got, tc.wantIDs)
				}
			}
		})
	}
}

// The reported bug, end to end: an org with two self-hosted edges, currently
// stuck on cd-vps-02, asks to go back to cd-vps. Before the fix the sticky
// preference matched cd-vps-02 in the over-answered list and reported a
// "sticky hit" on an edge in the region the user was trying to leave.
func TestPick_ExplicitRegionBeatsStickyEdgeInAnotherRegion(t *testing.T) {
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Query().Get("region")
		// What bff-console really answers: the requested region's edge PLUS the
		// org's own edges from every other region.
		_ = json.NewEncoder(w).Encode(listEdgesResponse{Items: []edgeJSON{
			ejr(1000300003, "47.109.81.93:7443", "cd-vps", true, 0),
			ejr(1000300004, "47.108.176.81:7443", "cd-vps-02", true, 0),
		}})
	}))
	defer srv.Close()

	got := Pick(context.Background(), slog.Default(), Input{
		BFFConsoleURL:    srv.URL,
		Region:           "cd-vps",
		RestrictToRegion: true,
		StickyEdgeNodeID: 1000300004, // where the daemon is right now
	})

	if asked != "cd-vps" {
		t.Fatalf("queried region %q, want cd-vps", asked)
	}
	if got.Region != "cd-vps" || got.EdgeNodeID != 1000300003 {
		t.Fatalf("switching back to cd-vps landed on region=%q edge=%d (%s); the explicit region must outrank the sticky edge",
			got.Region, got.EdgeNodeID, got.Reason)
	}
	if !got.Switched || got.PreviousEdgeNodeID != 1000300004 {
		t.Fatalf("the move off the sticky edge should be reported as a switch: switched=%v previous=%d",
			got.Switched, got.PreviousEdgeNodeID)
	}
}

// The other direction must keep working: the sticky edge IS in the requested
// region, so it wins over a less-loaded sibling (that is what sticky is for —
// per-edge wildcard DNS means silently moving breaks the user's tunnel URLs).
func TestPick_StickyStillWinsWithinTheRequestedRegion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(listEdgesResponse{Items: []edgeJSON{
			ejr(1, "busy:7443", "cd-vps", true, 99),
			ejr(2, "idle:7443", "cd-vps", true, 0),
		}})
	}))
	defer srv.Close()

	got := Pick(context.Background(), slog.Default(), Input{
		BFFConsoleURL:    srv.URL,
		Region:           "cd-vps",
		RestrictToRegion: true,
		StickyEdgeNodeID: 1,
	})
	if got.EdgeNodeID != 1 || got.Switched {
		t.Fatalf("sticky edge in the requested region should be kept, got edge=%d switched=%v (%s)",
			got.EdgeNodeID, got.Switched, got.Reason)
	}
}
