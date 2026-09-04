package statusapi

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// fakeMeshSource is a settable MeshStatusSource for handler tests.
type fakeMeshSource struct {
	st       MeshStatus
	downCall int
	upCall   int
	adv      MeshAdvertise
	services []MeshServiceDecl
}

func (f *fakeMeshSource) MeshStatus() MeshStatus   { return f.st }
func (f *fakeMeshSource) MeshDown() error          { f.downCall++; return nil }
func (f *fakeMeshSource) MeshUp() error            { f.upCall++; return nil }
func (f *fakeMeshSource) Advertise() MeshAdvertise { return f.adv }
func (f *fakeMeshSource) SetAdvertise(a MeshAdvertise) error {
	f.adv = a
	return nil
}
func (f *fakeMeshSource) MeshServices() []MeshServiceDecl { return f.services }
func (f *fakeMeshSource) SetMeshServices(in []MeshServiceDecl) error {
	f.services = in
	return nil
}

func meshServer(t *testing.T, src MeshStatusSource) http.Handler {
	t.Helper()
	s := New(nil, Config{BFFConsoleURL: "http://127.0.0.1:0", Mesh: src})
	mux := http.NewServeMux()
	s.Register(mux)
	return mux
}

// No mesh source wired (the pre-MESH platform daemon, or a build without it):
// /v1/mesh 404s so the SPA shows "unavailable on this daemon".
func TestMesh_NoSource_404(t *testing.T) {
	h := meshServer(t, nil)
	req := httptest.NewRequest("GET", "/v1/mesh", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("no source: got %d, want 404", rr.Code)
	}
}

// A source that reports not-enrolled AND not-paused 404s — the platform daemon
// renders that as "unavailable", NOT the local "add a mesh: block" hint.
func TestMesh_Disabled_404(t *testing.T) {
	h := meshServer(t, &fakeMeshSource{st: MeshStatus{Enabled: false}})
	req := httptest.NewRequest("GET", "/v1/mesh", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("disabled: got %d, want 404", rr.Code)
	}
}

// A locally-PAUSED node returns 200 with paused:true (not 404) so the SPA can
// distinguish "stopped locally, offer Start" from "never enrolled".
func TestMesh_Paused_200(t *testing.T) {
	h := meshServer(t, &fakeMeshSource{st: MeshStatus{Enabled: false, Paused: true}})
	req := httptest.NewRequest("GET", "/v1/mesh", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("paused: got %d, want 200", rr.Code)
	}
	if !contains(rr.Body.String(), `"paused":true`) {
		t.Fatalf("paused body missing paused:true: %s", rr.Body.String())
	}
}

// An enrolled node returns its live status, peers normalized to a non-null array.
func TestMesh_Enabled_ReturnsStatus(t *testing.T) {
	src := &fakeMeshSource{st: MeshStatus{
		Enabled: true, Up: true, Coord: "coord:7014", Relay: "derp:3340",
		Name: "node-a", Overlay: "100.64.0.5",
	}}
	h := meshServer(t, src)
	req := httptest.NewRequest("GET", "/v1/mesh", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enabled: got %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{`"enabled":true`, `"up":true`, `"coord":"coord:7014"`,
		`"relay":"derp:3340"`, `"overlay":"100.64.0.5"`, `"peers":[]`} {
		if !contains(body, want) {
			t.Errorf("body %q missing %q", body, want)
		}
	}
}

// POST /v1/mesh/down is local-token gated (guarded write), then calls MeshDown.
func TestMeshDown_LocalTokenGate(t *testing.T) {
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	tok, err := creds.MintLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeMeshSource{st: MeshStatus{Enabled: true, Up: true}}
	h := meshServer(t, src)

	// Without the token → 401, MeshDown not called.
	req := httptest.NewRequest("POST", "/v1/mesh/down", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", rr.Code)
	}
	if src.downCall != 0 {
		t.Fatalf("MeshDown called without a valid token")
	}

	// With the token → 200 + MeshDown fired.
	req = httptest.NewRequest("POST", "/v1/mesh/down", nil)
	req.Header.Set("X-Local-Token", tok)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("with token: got %d, want 200", rr.Code)
	}
	if src.downCall != 1 {
		t.Fatalf("MeshDown call count: got %d, want 1", src.downCall)
	}
}

// GET /v1/mesh/advertise reports the node's role + forwarding_supported.
func TestMeshAdvertiseGet(t *testing.T) {
	src := &fakeMeshSource{adv: MeshAdvertise{Routes: []string{"192.168.1.0/24"}, ExitNode: true, ExitPeer: "gw"}}
	h := meshServer(t, src)
	req := httptest.NewRequest("GET", "/v1/mesh/advertise", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get advertise: %d", rr.Code)
	}
	for _, want := range []string{`"routes":["192.168.1.0/24"]`, `"advertise_exit_node":true`, `"exit_node":"gw"`, `"forwarding_supported":`} {
		if !contains(rr.Body.String(), want) {
			t.Fatalf("body %q missing %q", rr.Body.String(), want)
		}
	}
}

// POST /v1/mesh/advertise: local-token gated, validates CIDRs, persists to creds,
// and calls SetAdvertise. A bad CIDR is a 400 with no SetAdvertise.
func TestMeshAdvertiseSet(t *testing.T) {
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	tok, err := creds.MintLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeMeshSource{}
	h := meshServer(t, src)

	// No token → 401.
	req := httptest.NewRequest("POST", "/v1/mesh/advertise", strings.NewReader(`{"routes":["10.0.0.0/8"]}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401", rr.Code)
	}

	// Bad CIDR → 400, SetAdvertise not called.
	req = httptest.NewRequest("POST", "/v1/mesh/advertise", strings.NewReader(`{"routes":["not-a-cidr"]}`))
	req.Header.Set("X-Local-Token", tok)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad cidr: %d, want 400", rr.Code)
	}
	if len(src.adv.Routes) != 0 {
		t.Fatalf("SetAdvertise must not run on bad input, got %+v", src.adv)
	}

	// Valid → 200, normalized (masked), persisted to creds, SetAdvertise called.
	req = httptest.NewRequest("POST", "/v1/mesh/advertise",
		strings.NewReader(`{"routes":["192.168.1.5/24"],"advertise_exit_node":true,"exit_node":"gw"}`))
	req.Header.Set("X-Local-Token", tok)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid set: %d, body %s", rr.Code, rr.Body.String())
	}
	if len(src.adv.Routes) != 1 || src.adv.Routes[0] != "192.168.1.0/24" || !src.adv.ExitNode || src.adv.ExitPeer != "gw" {
		t.Fatalf("SetAdvertise got %+v (want masked 192.168.1.0/24, exit, gw)", src.adv)
	}
	if c, _ := creds.Load(); c == nil || len(c.MeshAdvertiseRoutes) != 1 || !c.MeshAdvertiseExitNode || c.MeshExitNode != "gw" {
		t.Fatalf("creds not persisted: %+v", c)
	}
}

// POST /v1/mesh/up is local-token gated and calls MeshUp (resume).
func TestMeshUp_LocalTokenGate(t *testing.T) {
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	tok, err := creds.MintLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeMeshSource{st: MeshStatus{Enabled: false, Paused: true}}
	h := meshServer(t, src)

	req := httptest.NewRequest("POST", "/v1/mesh/up", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || src.upCall != 0 {
		t.Fatalf("no token: got %d, upCall %d, want 401/0", rr.Code, src.upCall)
	}

	req = httptest.NewRequest("POST", "/v1/mesh/up", nil)
	req.Header.Set("X-Local-Token", tok)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || src.upCall != 1 {
		t.Fatalf("with token: got %d, upCall %d, want 200/1", rr.Code, src.upCall)
	}
}

// setServices posts a declaration list (a guarded write) and returns the
// recorder. tok comes from servicesServer below.
func setServices(t *testing.T, h http.Handler, tok, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/mesh/services", strings.NewReader(body))
	req.Header.Set("X-Local-Token", tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// servicesServer wires a handler with a minted local token for guarded writes.
func servicesServer(t *testing.T) (http.Handler, *fakeMeshSource, string) {
	t.Helper()
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	tok, err := creds.MintLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeMeshSource{}
	return meshServer(t, src), src, tok
}

// THE bug this guards: a name the coordinator cannot use is SKIPPED at
// enrollment rather than rejected, so accepting one here produced a service that
// existed on the machine and never appeared in the web console, with nothing
// anywhere saying why. A space is the easy way in — it is invisible in most of
// the places these names get typed.
func TestSetMeshServicesRejectsAnUnusableName(t *testing.T) {
	h, src, tok := servicesServer(t)

	rr := setServices(t, h, tok, `{"items":[{"name":"my svc","proto":"tcp","port":8080}]}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 — the name would be dropped at enrollment", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "a-z") {
		t.Errorf("the error does not say what is allowed: %s", rr.Body.String())
	}
	if len(src.services) != 0 {
		t.Errorf("stored %+v despite the error", src.services)
	}

	// Uppercase normalizes rather than failing — names are case-insensitive.
	if rr := setServices(t, h, tok, `{"items":[{"name":"MySvc","proto":"tcp","port":8080}]}`); rr.Code != http.StatusOK {
		t.Fatalf("uppercase name rejected: %d %s", rr.Code, rr.Body.String())
	}
	if len(src.services) != 1 || src.services[0].Name != "mysvc" {
		t.Errorf("stored %+v, want the normalized name", src.services)
	}
}

// The SPA echoes the whole list back on every edit, so a field this handler
// drops is a field that gets cleared on every unrelated add or remove.
func TestSetMeshServicesKeepsTheTarget(t *testing.T) {
	h, src, tok := servicesServer(t)
	rr := setServices(t, h, tok,
		`{"items":[{"name":"db","proto":"tcp","port":5432,"target":"192.168.1.50:5432"}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rr.Code, rr.Body.String())
	}
	if len(src.services) != 1 || src.services[0].Target != "192.168.1.50:5432" {
		t.Fatalf("stored %+v, want the target preserved", src.services)
	}

	if rr := setServices(t, h, tok, `{"items":[{"name":"db","proto":"tcp","port":5432,"target":"nope"}]}`); rr.Code != http.StatusBadRequest {
		t.Errorf("a malformed target was accepted (%d) — enrollment would drop the service", rr.Code)
	}
}

// A row registered in the WEB console is echoed back through here like any
// other. Adopting it would write a second record claiming that name, with only
// one of the two carrying the authorization.
func TestSetMeshServicesDoesNotAdoptForeignRows(t *testing.T) {
	h, src, tok := servicesServer(t)
	rr := setServices(t, h, tok, `{"items":[
		{"name":"fromconsole","proto":"tcp","port":8080,"from_console":true},
		{"name":"fromfile","proto":"tcp","port":9090,"from_config":true},
		{"name":"mine","proto":"tcp","port":7000}
	]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rr.Code, rr.Body.String())
	}
	if len(src.services) != 1 || src.services[0].Name != "mine" {
		t.Fatalf("stored %+v, want only the locally-added one", src.services)
	}
}
