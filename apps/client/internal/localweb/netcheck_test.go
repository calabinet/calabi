package localweb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/mesh"
)

func TestNetCheck_StandaloneDoesNotUsePublicSTUN(t *testing.T) {
	s := New(Config{})
	mux := http.NewServeMux()
	s.Register(mux)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/netcheck", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/netcheck = %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	var rep mesh.NATReport
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode NATReport: %v", err)
	}
	if rep.NATType != mesh.NATUnknown || rep.Detail != "no_stun_servers" {
		t.Fatalf("expected unknown/no_stun_servers in standalone without mesh, got %+v", rep)
	}

	rrPost := httptest.NewRecorder()
	mux.ServeHTTP(rrPost, httptest.NewRequest(http.MethodPost, "/v1/netcheck", nil))
	if rrPost.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /v1/netcheck = %d, want 405", rrPost.Code)
	}
}
