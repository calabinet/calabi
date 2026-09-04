package edgepicker

// picker_affinity_test.go — BYOI soft-affinity: a daemon whose org owns a
// self-hosted edge defaults to it, but can opt onto the platform data plane.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func ej(id int64, addr string, owned bool, active int32) edgeJSON {
	return edgeJSON{EdgeNodeID: id, PublicAddr: addr, Healthy: true, ActiveClients: active, Owned: owned}
}

func ids(es []edgeJSON) []int64 {
	out := make([]int64, len(es))
	for i, e := range es {
		out[i] = e.EdgeNodeID
	}
	return out
}

func TestNarrowByOwnership(t *testing.T) {
	owned := ej(1001, "vps:7443", true, 5)
	plat1 := ej(1, "edge1:7443", false, 2)
	plat2 := ej(2, "edge2:7443", false, 9)
	all := []edgeJSON{plat1, owned, plat2}

	cases := []struct {
		name           string
		in             []edgeJSON
		preferPlatform bool
		wantIDs        []int64
	}{
		{"default prefers own edge", all, false, []int64{1001}},
		{"default with no own edge → all platform", []edgeJSON{plat1, plat2}, false, []int64{1, 2}},
		{"prefer-platform drops own edge", all, true, []int64{1, 2}},
		{"prefer-platform with only own → not stranded", []edgeJSON{owned}, true, []int64{1001}},
		{"default with only own → own", []edgeJSON{owned}, false, []int64{1001}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ids(narrowByOwnership(slog.Default(), tc.in, tc.preferPlatform))
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

// TestPick_BYOIAffinity_EndToEnd drives the full /v1/edges decode + selection:
// a BYOI daemon lands on its own edge by default and on a platform edge when
// it opts out — even though the owned edge has MORE active_clients (which the
// load-balancer would otherwise avoid).
func TestPick_BYOIAffinity_EndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(listEdgesResponse{Items: []edgeJSON{
			ej(1, "edge1:7443", false, 0),          // platform, least loaded
			ej(1001, "vps.example:7443", true, 99), // own edge, heavily loaded
		}})
	}))
	defer srv.Close()

	// Default: own edge wins despite its high active_clients.
	got := Pick(context.Background(), slog.Default(), Input{BFFConsoleURL: srv.URL})
	if got.Addr != "vps.example:7443" || got.EdgeNodeID != 1001 {
		t.Fatalf("default affinity: want own edge, got addr=%q id=%d reason=%q", got.Addr, got.EdgeNodeID, got.Reason)
	}

	// Opt onto the platform: the load-balanced platform edge is chosen.
	got2 := Pick(context.Background(), slog.Default(), Input{BFFConsoleURL: srv.URL, PreferPlatformEdge: true})
	if got2.Addr != "edge1:7443" || got2.EdgeNodeID != 1 {
		t.Fatalf("prefer-platform: want platform edge, got addr=%q id=%d reason=%q", got2.Addr, got2.EdgeNodeID, got2.Reason)
	}
}
