package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCfg drops a config file and loads it the way the binary does, so these
// tests exercise the REAL path (Load -> raw parse -> checkRoleConfig) rather
// than calling the guard with a hand-built struct.
func writeCfg(t *testing.T, body string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "edge.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return Load(p)
}

// TestRelayBlockWithoutRoleIsRefused pins the footgun the retired derp-node
// binary used to make impossible: with a separate relay program you could not
// accidentally start an ingress. With one binary, an empty role means "edge",
// so a file that configures a relay and forgets the role would silently serve
// tunnels and ignore the whole relay block.
func TestRelayBlockWithoutRoleIsRefused(t *testing.T) {
	_, err := writeCfg(t, `
node_label: relay-1
relay:
  kind: self
  derp_port: 3340
`)
	if err == nil {
		t.Fatal("a relay: block with no role: was accepted — it would start an EDGE and ignore the relay")
	}
	if !strings.Contains(err.Error(), "role: relay") {
		t.Errorf("error should tell the operator what to write, got: %v", err)
	}
}

// TestRelayBlockWithRoleIsFine: stating the role is all it takes.
func TestRelayBlockWithRoleIsFine(t *testing.T) {
	for _, role := range []string{"relay", "both"} {
		t.Run("role="+role, func(t *testing.T) {
			cfg, err := writeCfg(t, `
node_label: relay-1
role: `+role+`
relay:
  kind: self
  derp_port: 3340
`)
			if err != nil {
				t.Fatalf("role %q rejected: %v", role, err)
			}
			if !cfg.RunsRelay() {
				t.Errorf("role %q should run the relay datapath", role)
			}
		})
	}
}

// TestRelayOnlyRefusesTunnelListeners: a relay-only node's config must describe
// a relay-only node. Those listeners are never bound anyway (main.go skips them
// when RunsEdge is false) — the point is that a config nobody enforces is a
// config someone will read and believe.
func TestRelayOnlyRefusesTunnelListeners(t *testing.T) {
	cases := []struct {
		name  string
		field string
		body  string
	}{
		{"control", "control.addr", "control:\n  addr: \":7443\"\n"},
		{"http", "http.addr", "http:\n  addr: \":80\"\n"},
		{"https", "https.addr", "https:\n  addr: \":443\"\n"},
		{"sni", "sni.addr", "sni:\n  addr: \":8443\"\n"},
		{"mesh forward", "mesh.forward_addr", "mesh:\n  forward_addr: \"10.0.0.5:7090\"\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := writeCfg(t, "node_label: relay-1\nrole: relay\n"+c.body)
			if err == nil {
				t.Fatalf("role: relay accepted a tunnel listener (%s) — the config claims something the process will not do", c.field)
			}
			if !strings.Contains(err.Error(), c.field) {
				t.Errorf("error should name the offending field %q, got: %v", c.field, err)
			}
		})
	}
}

// TestRelayOnlyMinimalConfigPasses: the shape a self-hoster should actually
// write. Defaults fill the listener addresses in the merged config, so this
// also proves the guard reads the RAW parse and not the defaults — otherwise
// every relay-only config would be rejected.
func TestRelayOnlyMinimalConfigPasses(t *testing.T) {
	cfg, err := writeCfg(t, `
node_label: relay-1
region: lax
role: relay
relay:
  kind: self
  derp_port: 3340
  stun_port: 3478
`)
	if err != nil {
		t.Fatalf("a minimal relay-only config was rejected: %v", err)
	}
	if !cfg.RunsRelay() || cfg.RunsEdge() {
		t.Fatalf("expected relay-only, got RunsRelay=%v RunsEdge=%v", cfg.RunsRelay(), cfg.RunsEdge())
	}
	if cfg.Control.Addr == "" {
		t.Fatal("sanity: Default() should still have filled control.addr in the MERGED config")
	}
}

// TestRoleBothMayCarryListeners: role=both is exactly the case where tunnel
// listeners belong, so the guard must not fire there.
func TestRoleBothMayCarryListeners(t *testing.T) {
	if _, err := writeCfg(t, `
node_label: edge-1
role: both
control:
  addr: ":7443"
http:
  addr: ":80"
relay:
  kind: platform
  derp_port: 3340
`); err != nil {
		t.Fatalf("role: both with listeners was rejected: %v", err)
	}
}

// TestEdgeConfigUnaffected: the overwhelmingly common config — no role, no
// relay block — must be untouched by any of this.
func TestEdgeConfigUnaffected(t *testing.T) {
	cfg, err := writeCfg(t, `
node_label: edge-1
control:
  addr: ":7443"
http:
  addr: ":80"
`)
	if err != nil {
		t.Fatalf("a plain edge config was rejected: %v", err)
	}
	if !cfg.RunsEdge() || cfg.RunsRelay() {
		t.Fatalf("empty role must mean edge-only, got RunsEdge=%v RunsRelay=%v", cfg.RunsEdge(), cfg.RunsRelay())
	}
}
