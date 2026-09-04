package edgepicker

// picker_explicit_test.go — an explicit CALABI_SERVER address still resolves
// WHICH edge it is (by matching /v1/edges public_addr), so onOwnEdge and the
// served-by-edge / region displays work for a BYOI user who pins their own edge.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPick_ExplicitAddr_ResolvesEdgeID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(listEdgesResponse{Items: []edgeJSON{
			{EdgeNodeID: 5, NodeLabel: "plat", Region: "cn-a", PublicAddr: "edge1:7443", Healthy: true},
			{EdgeNodeID: 1000100001, NodeLabel: "my-vps", Region: "cn-b", PublicAddr: "vps.example.com:7443", Healthy: true, Owned: true},
		}})
	}))
	defer srv.Close()

	t.Run("exact host:port match fills id + region", func(t *testing.T) {
		got := Pick(context.Background(), slog.Default(), Input{
			ExplicitAddr:  "vps.example.com:7443",
			BFFConsoleURL: srv.URL,
			AccessToken:   "tk_x",
		})
		if got.Addr != "vps.example.com:7443" {
			t.Fatalf("Addr = %q, want the explicit addr unchanged", got.Addr)
		}
		if got.EdgeNodeID != 1000100001 {
			t.Fatalf("EdgeNodeID = %d, want 1000100001 (resolved from directory)", got.EdgeNodeID)
		}
		if got.Region != "cn-b" {
			t.Fatalf("Region = %q, want cn-b", got.Region)
		}
	})

	t.Run("host-only match when port differs", func(t *testing.T) {
		got := Pick(context.Background(), slog.Default(), Input{
			ExplicitAddr:  "vps.example.com:9443", // different control port
			BFFConsoleURL: srv.URL,
			AccessToken:   "tk_x",
		})
		if got.EdgeNodeID != 1000100001 {
			t.Fatalf("EdgeNodeID = %d, want 1000100001 via host-only fallback", got.EdgeNodeID)
		}
	})

	t.Run("no directory match leaves id 0 (old behavior)", func(t *testing.T) {
		got := Pick(context.Background(), slog.Default(), Input{
			ExplicitAddr:  "unknown-host:7443",
			BFFConsoleURL: srv.URL,
			AccessToken:   "tk_x",
		})
		if got.Addr != "unknown-host:7443" {
			t.Fatalf("Addr = %q, want unchanged explicit addr", got.Addr)
		}
		if got.EdgeNodeID != 0 {
			t.Fatalf("EdgeNodeID = %d, want 0 (no match → unchanged)", got.EdgeNodeID)
		}
	})

	t.Run("no bff-console url → no lookup, id 0", func(t *testing.T) {
		got := Pick(context.Background(), slog.Default(), Input{
			ExplicitAddr: "vps.example.com:7443",
		})
		if got.EdgeNodeID != 0 {
			t.Fatalf("EdgeNodeID = %d, want 0 when no directory to consult", got.EdgeNodeID)
		}
	})
}
