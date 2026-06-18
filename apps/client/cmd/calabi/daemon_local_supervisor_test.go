package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/localweb"
	"github.com/calabi/calabi/apps/client/internal/session"
)

// Once a tunnel registers, /v1/tunnels must report the edge-ASSIGNED domain and
// the edge id (not the empty configured domain) so the console's Public + Edge
// columns aren't blank.
func TestSupervisor_TunnelsOverlaysAssignedAddr(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	planned := planTunnels(logger, []localTunnelConfig{
		{Name: "stage", Type: "http", Local: "192.168.1.5:8080"}, // no configured domain
	})
	sv := newLocalSupervisor(logger, localConfig{Server: "edge:7443", Insecure: true},
		filepath.Join(dir, "t.yaml"), planned, "edge:7443")
	id := planned[0].id

	if got := sv.Tunnels(); len(got) != 1 || got[0].Domain != "" || got[0].EdgeNodeID != 0 {
		t.Fatalf("pre-live: got %+v, want empty domain + edge id 0", got)
	}

	sv.markLive(id, session.Assigned{Domain: "u000123.edge.example.com"})
	got := sv.Tunnels()
	if got[0].Domain != "u000123.edge.example.com" {
		t.Errorf("Domain = %q, want the assigned subdomain", got[0].Domain)
	}
	if got[0].EdgeNodeID != localweb.SelfHostedEdgeID {
		t.Errorf("EdgeNodeID = %d, want %d", got[0].EdgeNodeID, localweb.SelfHostedEdgeID)
	}

	sv.markDead(id)
	if got := sv.Tunnels(); got[0].Domain != "" || got[0].EdgeNodeID != 0 {
		t.Errorf("post-dead: Domain=%q EdgeNodeID=%d, want empty/0", got[0].Domain, got[0].EdgeNodeID)
	}
}

func testSupervisor(t *testing.T) (*localSupervisor, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tunnels.yaml")
	base := localConfig{Server: "edge.example.com:7443", TokenEnv: "CALABI_TOKEN", Insecure: true}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	planned := planTunnels(logger, []localTunnelConfig{
		{Name: "web", Type: "http", Local: "8080", Domain: "web.example.com"},
	})
	return newLocalSupervisor(logger, base, path, planned, "edge.example.com:7443"), path
}

// The first edge-assigned subdomain is pinned into the plan + YAML so it stays
// stable across reconnects/restarts; a later assignment doesn't overwrite it.
func TestSupervisor_PinsAssignedDomain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunnels.yaml")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	planned := planTunnels(logger, []localTunnelConfig{
		{Name: "stage", Type: "http", Local: "192.168.1.5:8080"}, // no configured domain
	})
	sv := newLocalSupervisor(logger, localConfig{Server: "edge:7443", Insecure: true}, path, planned, "edge:7443")
	id := planned[0].id

	sv.recordAssignedAddr(id, "u000007.edge.example.com", 0)

	if got := sv.snapshot()[0].tun.Domain; got != "u000007.edge.example.com" {
		t.Errorf("in-memory tun.Domain = %q, want pinned (reconnect re-requests it)", got)
	}
	cfg, err := loadLocalConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tunnels[0].Domain != "u000007.edge.example.com" {
		t.Errorf("persisted YAML domain = %q, want pinned (restart re-requests it)", cfg.Tunnels[0].Domain)
	}

	// Idempotent: a fresh assignment must NOT override the pinned value.
	sv.recordAssignedAddr(id, "u999999.edge.example.com", 0)
	if got := sv.snapshot()[0].tun.Domain; got != "u000007.edge.example.com" {
		t.Errorf("after 2nd assign tun.Domain = %q, want unchanged", got)
	}
}

// A config that uses an inline `token:` (and no token_env / ca_file) must NOT
// gain spurious empty top-level fields when persist() rewrites the file — which
// happens on first connect, when the edge-assigned address is pinned. Regression
// for localConfig's optional fields lacking omitempty (a `token:`-only config
// used to grow a bogus `token_env: ""`).
func TestSupervisor_PersistOmitsUnsetTopLevelFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunnels.yaml")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	planned := planTunnels(logger, []localTunnelConfig{
		{Name: "web", Type: "http", Local: "8080"}, // no domain → edge assigns one
	})
	base := localConfig{Server: "edge:7443", Token: "s3cret"} // inline token, nothing else
	sv := newLocalSupervisor(logger, base, path, planned, "edge:7443")

	sv.recordAssignedAddr(planned[0].id, "u000007.edge.example.com", 0) // triggers persist()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, unwanted := range []string{"token_env", "ca_file", "insecure"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("persist injected unset field %q into the YAML:\n%s", unwanted, out)
		}
	}
	if !strings.Contains(out, "token: s3cret") {
		t.Errorf("inline token not preserved on persist:\n%s", out)
	}
}

// Create assigns a fresh id beyond the boot tunnels, appears in the list, and
// persists to YAML.
func TestSupervisor_CreatePersists(t *testing.T) {
	sv, path := testSupervisor(t)
	id, err := sv.CreateTunnel(localweb.TunnelSpec{Name: "api", Type: "tcp", LocalAddr: "127.0.0.1:22", RemotePort: 2222})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id != 2 {
		t.Errorf("new id = %d, want 2 (after the boot tunnel id 1)", id)
	}
	if got := len(sv.Tunnels()); got != 2 {
		t.Fatalf("list size = %d, want 2", got)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "name: api") || !strings.Contains(string(data), "remote_port: 2222") {
		t.Errorf("config not persisted:\n%s", data)
	}
	// token_env must be preserved (no inline token leaked).
	if !strings.Contains(string(data), "token_env: CALABI_TOKEN") {
		t.Errorf("token_env not preserved:\n%s", data)
	}
}

// UpdateSecurity stores the raw blob (security_config_json) so it round-trips,
// and a re-load of the persisted file yields the same policy.
func TestSupervisor_UpdateSecurityRoundTrips(t *testing.T) {
	sv, path := testSupervisor(t)
	blob := `{"security":{"ip":{"deny":["1.2.3.4"]}}}`
	if err := sv.UpdateSecurity(1, blob); err != nil {
		t.Fatalf("update: %v", err)
	}
	tuns := sv.Tunnels()
	if len(tuns) != 1 || tuns[0].ConfigJSON != blob {
		t.Fatalf("in-memory config_json = %q, want %q", tuns[0].ConfigJSON, blob)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "security_config_json:") {
		t.Errorf("blob not persisted as security_config_json:\n%s", data)
	}
	// Re-load the persisted file → same policy survives a restart.
	reloaded, err := loadLocalConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	tun, err := toSessionTunnel(reloaded.Tunnels[0])
	if err != nil {
		t.Fatalf("toSessionTunnel: %v", err)
	}
	if tun.SecurityConfigJSON != blob {
		t.Errorf("reloaded policy = %q, want %q", tun.SecurityConfigJSON, blob)
	}
}

// UpdateTunnel edits name + local_addr in place, normalizes a bare port, leaves
// the public endpoint alone, persists, and rejects a public upstream + blanks.
func TestSupervisor_UpdateTunnel(t *testing.T) {
	sv, path := testSupervisor(t)
	if err := sv.UpdateTunnel(1, "renamed", "3000"); err != nil {
		t.Fatalf("update: %v", err)
	}
	tuns := sv.Tunnels()
	if len(tuns) != 1 || tuns[0].Name != "renamed" {
		t.Fatalf("name = %q, want renamed", tuns[0].Name)
	}
	// Bare port normalized to loopback host:port (matches create).
	if tuns[0].LocalAddr != "127.0.0.1:3000" {
		t.Errorf("local_addr = %q, want 127.0.0.1:3000", tuns[0].LocalAddr)
	}
	// Public endpoint untouched.
	if tuns[0].Domain != "web.example.com" {
		t.Errorf("domain = %q, want web.example.com (unchanged)", tuns[0].Domain)
	}
	// Persisted to YAML (raw local form, like create; reload re-normalizes).
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "name: renamed") {
		t.Errorf("edit not persisted:\n%s", data)
	}
	reloaded, err := loadLocalConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	tun, err := toSessionTunnel(reloaded.Tunnels[0])
	if err != nil {
		t.Fatalf("toSessionTunnel: %v", err)
	}
	if tun.LocalAddr != "127.0.0.1:3000" || tun.Name != "renamed" {
		t.Errorf("reloaded edit: name=%q local=%q", tun.Name, tun.LocalAddr)
	}
	// Name-only edit leaves local untouched.
	if err := sv.UpdateTunnel(1, "again", ""); err != nil {
		t.Fatalf("name-only: %v", err)
	}
	if got := sv.Tunnels()[0]; got.Name != "again" || got.LocalAddr != "127.0.0.1:3000" {
		t.Errorf("name-only edit: name=%q local=%q", got.Name, got.LocalAddr)
	}
	// A public upstream is rejected (open-relay guard).
	if err := sv.UpdateTunnel(1, "", "8.8.8.8:80"); err == nil {
		t.Errorf("public upstream: want error, got nil")
	}
	// Unknown id → ErrTunnelNotFound.
	if err := sv.UpdateTunnel(999, "x", ""); err != localweb.ErrTunnelNotFound {
		t.Errorf("unknown id err = %v, want ErrTunnelNotFound", err)
	}
}

func TestSupervisor_Delete(t *testing.T) {
	sv, _ := testSupervisor(t)
	if err := sv.DeleteTunnel(1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := len(sv.Tunnels()); got != 0 {
		t.Errorf("list size = %d, want 0", got)
	}
	if err := sv.DeleteTunnel(999); err != localweb.ErrTunnelNotFound {
		t.Errorf("delete unknown id err = %v, want ErrTunnelNotFound", err)
	}
}
