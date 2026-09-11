package edgepicker

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A slow answer is still an answer.
//
// The budget used to be 3s for DNS + TCP + TLS + the request. A single
// retransmitted handshake packet eats most of that, and a path that just changed
// (a re-dialled uplink, a new egress IP) is exactly when it happens. Observed
// 2026-09-10: after the egress IP changed, every /v1/edges query hit
// `context deadline exceeded` and discovery kept failing.
func TestPickSurvivesASlowControlPlane(t *testing.T) {
	const delay = 3500 * time.Millisecond // past the old 3s budget, well inside the new one
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		_ = json.NewEncoder(w).Encode(listEdgesResponse{Items: []edgeJSON{
			{EdgeNodeID: 7, Region: "lax", PublicAddr: "edge07-lax.example.net:7443", Healthy: true},
		}})
	}))
	defer srv.Close()

	got := Pick(context.Background(), slog.New(slog.DiscardHandler), Input{
		Region:           "lax",
		RestrictToRegion: true,
		BFFConsoleURL:    srv.URL,
		AccessToken:      "t",
		DefaultAddr:      "localhost:7443",
	})
	if got.EdgeNodeID != 7 {
		t.Fatalf("a control plane answering in %v was treated as unreachable: %+v", delay, got)
	}
}
