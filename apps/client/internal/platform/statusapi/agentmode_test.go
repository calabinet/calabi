package statusapi

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// newTestServer builds a Server + its registered mux for handler-level tests.
func newTestServer(t *testing.T, agent bool) http.Handler {
	t.Helper()
	s := New(nil, Config{BFFConsoleURL: "http://127.0.0.1:0", AgentMode: agent})
	mux := http.NewServeMux()
	s.Register(mux)
	return mux
}

// In agent mode the identity/session-rebinding endpoints must be refused with
// 403 — that's what stops a browser on the loopback box from signing in as a
// different user and re-binding the pinned service to themselves. Tunnel
// management is deliberately NOT here: a management key may run those locally,
// gated by bff-console's tunnel.write scope. Reads stay open.
func TestAgentMode_BlocksIdentityEndpoints(t *testing.T) {
	h := newTestServer(t, true)

	blocked := []struct{ method, path string }{
		{"POST", "/v1/auth/login"},
		{"POST", "/v1/auth/logout"},
		{"POST", "/v1/orgs/switch"},
	}
	for _, w := range blocked {
		req := httptest.NewRequest(w.method, w.path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s %s in agent mode: got %d, want 403", w.method, w.path, rr.Code)
		}
	}
}

// Data-plane routing (edge-region / edge-affinity) is NOT identity, so an agent
// may use it. These reach the local-token gate (401 without a token) rather than
// the 403 identity gate — anything but 403 proves they're allowed through.
func TestAgentMode_AllowsDataPlaneRouting(t *testing.T) {
	h := newTestServer(t, true)
	for _, w := range []struct{ method, path string }{
		{"POST", "/v1/edge-region"},
		{"POST", "/v1/edge-affinity"},
	} {
		req := httptest.NewRequest(w.method, w.path, nil) // no X-Local-Token
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusForbidden {
			t.Errorf("%s %s in agent mode must not be 403 (identity gate); got 403", w.method, w.path)
		}
	}
}

// Tunnel-management writes must NOT be agent-blocked: they reach the local-token
// gate / upstream proxy (here failing on the missing X-Local-Token with 401, or
// a stub-dial error — anything but the 403 identity gate). bff-console is the
// real authority on whether the pinned key may write.
func TestAgentMode_AllowsTunnelManagementThroughGate(t *testing.T) {
	h := newTestServer(t, true)

	writes := []struct{ method, path string }{
		{"POST", "/v1/tunnels"},
		{"DELETE", "/v1/tunnels/7"},
		{"PUT", "/v1/tunnels/7"},
		{"POST", "/v1/tunnels/7/security"},
		{"POST", "/v1/config/import"},
	}
	for _, w := range writes {
		req := httptest.NewRequest(w.method, w.path, nil) // no X-Local-Token
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusForbidden {
			t.Errorf("%s %s in agent mode must not be 403 (identity gate); got 403",
				w.method, w.path)
		}
	}
}

// service-mode reports the pinned-agent shape so the SPA can render a
// read-only console and hide the login portal.
func TestServiceMode_Agent(t *testing.T) {
	h := newTestServer(t, true)
	req := httptest.NewRequest("GET", "/v1/service-mode", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("service-mode: got %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{`"mode":"agent"`, `"agent":true`, `"login_enabled":false`} {
		if !contains(body, want) {
			t.Errorf("service-mode body %q missing %q", body, want)
		}
	}
}

// service-mode carries the WEB console origin so the SPA's login page can link
// to registration. It is baked into the daemon (main.defaultConsoleWeb) rather
// than derived from BFFConsoleURL — in production those are different hosts
// (api.calabi.net vs console.calabi.net). The login page previously hardcoded a
// https://calabi.example.com/register placeholder that went nowhere.
func TestServiceMode_ConsoleWeb(t *testing.T) {
	s := New(nil, Config{
		BFFConsoleURL: "http://127.0.0.1:0",
		ConsoleWebURL: "https://console.example.net",
	})
	mux := http.NewServeMux()
	s.Register(mux)

	req := httptest.NewRequest("GET", "/v1/service-mode", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("service-mode: got %d, want 200", rr.Code)
	}
	if want := `"console_web":"https://console.example.net"`; !contains(rr.Body.String(), want) {
		t.Errorf("service-mode body %q missing %q", rr.Body.String(), want)
	}
}

// An unset console origin must stay empty rather than inventing one: the SPA
// keys off "" to HIDE the register link, which beats offering a dead URL.
func TestServiceMode_ConsoleWebEmptyWhenUnset(t *testing.T) {
	h := newTestServer(t, false) // Config has no ConsoleWebURL
	req := httptest.NewRequest("GET", "/v1/service-mode", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if want := `"console_web":""`; !contains(rr.Body.String(), want) {
		t.Errorf("service-mode body %q missing %q", rr.Body.String(), want)
	}
}

// Interactive mode lets login THROUGH the agent gate (it'll fail later on the
// dial to the stub bff-console, but NOT with 403) and reports the interactive
// shape so the SPA renders the login portal.
func TestInteractiveMode_AllowsLoginGate(t *testing.T) {
	h := newTestServer(t, false)

	// /v1/service-mode shape.
	req := httptest.NewRequest("GET", "/v1/service-mode", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !contains(rr.Body.String(), `"mode":"interactive"`) {
		t.Fatalf("service-mode interactive: %q", rr.Body.String())
	}

	// Login must not be agent-blocked. A bad body yields 400 (parse), proving
	// the request reached the handler rather than the 403 gate.
	req = httptest.NewRequest("POST", "/v1/auth/login", http.NoBody)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("interactive login must not be 403; got %d", rr.Code)
	}
}

// resolveBearer must fall back to the env API key when the creds file holds no
// bearer — the AGENT-mode shape (key lives in CALABI_API_KEY, creds empty).
// Without this the /me probe had no bearer, 401'd, and :7400 showed a blank
// login screen (the identity-hijack door).
func TestResolveBearer_EnvFallback(t *testing.T) {
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json")) // empty creds
	t.Setenv("CALABI_API_KEY", "tk_agent")
	t.Setenv("CALABI_TOKEN", "")
	if got := resolveBearer(false); got != "tk_agent" {
		t.Fatalf("resolveBearer env fallback: got %q, want tk_agent", got)
	}

	// Interactive mode: a saved access_token wins over the env key.
	if err := creds.Save(&creds.Config{AccessToken: "login-jwt"}); err != nil {
		t.Fatal(err)
	}
	if got := resolveBearer(false); got != "login-jwt" {
		t.Fatalf("resolveBearer login precedence: got %q, want login-jwt", got)
	}

	// AGENT mode: the API key wins even when a stale login token sits in creds —
	// the console must report the pinned key's identity, not the login user.
	if err := creds.Save(&creds.Config{AccessToken: "login-jwt", APIKey: "tk_creds"}); err != nil {
		t.Fatal(err)
	}
	if got := resolveBearer(true); got != "tk_creds" {
		t.Fatalf("agent mode must pin to the API key: got %q, want tk_creds", got)
	}
}

// injectOwnDeviceID binds a new tunnel to this daemon's device when the SPA
// sent no client_id — the agent path where the device is an org Agent absent
// from the user-scoped /v1/clients list.
func TestInjectOwnDeviceID(t *testing.T) {
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	if err := creds.Save(&creds.Config{DeviceID: 4242}); err != nil {
		t.Fatal(err)
	}
	s := New(nil, Config{BFFConsoleURL: "http://127.0.0.1:0"})

	// No client_id → injected.
	got := string(s.injectOwnDeviceID([]byte(`{"name":"t","type":"http"}`)))
	if !contains(got, `"client_id":4242`) {
		t.Errorf("expected injected device id, got %s", got)
	}
	// client_id:0 → injected (treated as unset).
	got = string(s.injectOwnDeviceID([]byte(`{"client_id":0,"name":"t"}`)))
	if !contains(got, `"client_id":4242`) {
		t.Errorf("expected zero client_id replaced, got %s", got)
	}
	// Explicit non-zero client_id → respected (unchanged).
	got = string(s.injectOwnDeviceID([]byte(`{"client_id":7,"name":"t"}`)))
	if !contains(got, `"client_id":7`) || contains(got, "4242") {
		t.Errorf("expected explicit client_id kept, got %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return len(sub) == 0
}
