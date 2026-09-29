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
// accidentally start an ingress. With one binary, an empty role means "tunnel",
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
	if !strings.Contains(err.Error(), "role: mesh") {
		t.Errorf("error should tell the operator what to write, got: %v", err)
	}
}

// TestRelayBlockWithRoleIsFine: stating the role is all it takes.
func TestRelayBlockWithRoleIsFine(t *testing.T) {
	// Both current spellings and the retired one: an operator upgrading a node
	// whose file says role: relay must not meet a new startup error.
	for _, role := range []string{"mesh", "both", "relay"} {
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
			if !cfg.ServesMesh() {
				t.Errorf("role %q should run the relay datapath", role)
			}
		})
	}
}

// TestRelayOnlyRefusesTunnelListeners: a relay-only node's config must describe
// a relay-only node. Those listeners are never bound anyway (main.go skips them
// when ServesTunnels is false) — the point is that a config nobody enforces is a
// config someone will read and believe.
func TestRelayOnlyRefusesTunnelListeners(t *testing.T) {
	cases := []struct {
		name  string
		field string
		body  string
	}{
		{"control", "control_port", "control:\n  addr: \":7443\"\n"},
		// Not control_cert_pem / control_key_pem: that certificate is the
		// node's, and a relay-only node presents it on its relay port to the
		// devices that open TLS (TestRelayOnlyMayNameItsCertificate).
		{"http", "http_port", "http:\n  addr: \":80\"\n"},
		{"https", "https_port", "https:\n  addr: \":443\"\n"},
		{"sni", "sni_port", "sni:\n  addr: \":8443\"\n"},
		// Both spellings of the peer-forward block: the pre-1.15 top-level one,
		// which migrateLayout nests before the guard runs, and the current one.
		// A legacy-spelled listener slipping through would leave a mesh-only node
		// whose config claims it forwards tunnel traffic.
		{"peer forward", "peer_forward.forward_addr", "peer_forward:\n  forward_addr: \"10.0.0.5:7090\"\n"},
		{"peer forward, nested", "peer_forward.forward_addr", "tunnel:\n  peer_forward:\n    forward_addr: \"10.0.0.5:7090\"\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := writeCfg(t, "node_label: relay-1\nrole: relay\n"+c.body)
			if err == nil {
				t.Fatalf("role: mesh accepted a tunnel listener (%s) — the config claims something the process will not do", c.field)
			}
			if !strings.Contains(err.Error(), c.field) {
				t.Errorf("error should name the offending field %q, got: %v", c.field, err)
			}
		})
	}
}

// TestRelayOnlyMayNameItsCertificate: the node's certificate is not a tunnel
// setting any more. A relay-only node presents it on its relay port to devices
// that open TLS (cmd/calabi-edge/relaytls.go) — a relay with a certificate from
// a public CA needs somewhere to name it, and this is where every other node
// names its own. It used to be refused here as "a mesh relay terminates no TLS".
func TestRelayOnlyMayNameItsCertificate(t *testing.T) {
	cfg, err := writeCfg(t, "node_label: relay-1\nrole: mesh\n"+
		"tunnel:\n  control_cert_pem: /etc/calabi/relay.crt\n  control_key_pem: /etc/calabi/relay.key\n")
	if err != nil {
		t.Fatalf("a relay-only node naming its certificate was refused: %v", err)
	}
	if cfg.Tunnel.ControlCertPEM != "/etc/calabi/relay.crt" || cfg.Tunnel.ControlKeyPEM != "/etc/calabi/relay.key" {
		t.Fatalf("certificate = (%q, %q), want the one the file names", cfg.Tunnel.ControlCertPEM, cfg.Tunnel.ControlKeyPEM)
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
role: mesh
relay:
  kind: self
  derp_port: 3340
  stun_port: 3478
`)
	if err != nil {
		t.Fatalf("a minimal relay-only config was rejected: %v", err)
	}
	if !cfg.ServesMesh() || cfg.ServesTunnels() {
		t.Fatalf("expected mesh-only, got ServesMesh=%v ServesTunnels=%v", cfg.ServesMesh(), cfg.ServesTunnels())
	}
	if cfg.Tunnel.ControlAddr() == "" {
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
	if !cfg.ServesTunnels() || cfg.ServesMesh() {
		t.Fatalf("empty role must mean tunnels only, got ServesTunnels=%v ServesMesh=%v", cfg.ServesTunnels(), cfg.ServesMesh())
	}
}
