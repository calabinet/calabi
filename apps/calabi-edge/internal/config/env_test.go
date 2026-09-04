package config

import (
	"strings"
	"testing"
)

// TestApplyEnvRelayOnlyNodeNeedsNoFile is the case that justifies this file
// existing: the retired derp-node binary was configured entirely by environment
// variables, and a self-hosted relay still has nothing else to configure — no
// domain, no certificate, no listeners. This proves the same deployment shape
// survives on the edge binary.
func TestApplyEnvRelayOnlyNodeNeedsNoFile(t *testing.T) {
	t.Setenv("CALABI_EDGE_MODE", "standalone")
	t.Setenv("CALABI_EDGE_ROLE", "relay")
	t.Setenv("CALABI_EDGE_RELAY_KIND", "self")
	t.Setenv("CALABI_EDGE_RELAY_LABEL", "hk1")
	t.Setenv("CALABI_EDGE_RELAY_DERP_PORT", "3340")
	t.Setenv("CALABI_EDGE_RELAY_STUN_PORT", "3478")
	t.Setenv("CALABI_EDGE_RELAY_REQUIRE_AUTH", "1")
	t.Setenv("CALABI_EDGE_RELAY_COORD_PUBKEY", "xMqLvONWcTdghKQ4cwvVQ81FuXDj/0npFphl4BujbdA=")
	t.Setenv("CALABI_EDGE_ADMIN_ADDR", ":9200")

	// Load("") = no config file at all, exactly like `docker run` with only env.
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg, err = ApplyEnv(cfg)
	if err != nil {
		t.Fatalf("ApplyEnv: %v", err)
	}

	if !cfg.IsStandaloneMode() {
		t.Error("mode not applied from env")
	}
	if !cfg.RunsRelay() || cfg.RunsEdge() {
		t.Errorf("want relay-only, got RunsRelay=%v RunsEdge=%v", cfg.RunsRelay(), cfg.RunsEdge())
	}
	if cfg.Relay.Kind != "self" || cfg.Relay.Label != "hk1" {
		t.Errorf("relay kind/label = %q/%q", cfg.Relay.Kind, cfg.Relay.Label)
	}
	if cfg.Relay.RelayDERPPort() != 3340 || cfg.Relay.RelaySTUNPort() != 3478 {
		t.Errorf("ports = %d/%d", cfg.Relay.RelayDERPPort(), cfg.Relay.RelaySTUNPort())
	}
	if !cfg.Relay.RequireAuth || cfg.Relay.CoordPubKey == "" {
		t.Error("grant verification not applied from env")
	}
	// Two edge-image containers share a host in the self-hosted stack, so the
	// relay must be able to move off the default admin port :9101.
	if cfg.Admin.Addr != ":9200" {
		t.Errorf("admin addr = %q, want :9200 (port collision with the edge container)", cfg.Admin.Addr)
	}
	// The whole point of kind=self + standalone: no control plane is reached.
	normalized, _ := cfg.NormalizeForMode()
	if normalized.Identity.Addr != "" {
		t.Errorf("standalone relay still carries a control-plane address: %q", normalized.Identity.Addr)
	}
}

// TestApplyEnvUnsetChangesNothing: an edge with a config file and no env must
// be byte-identical to what the file said.
func TestApplyEnvUnsetChangesNothing(t *testing.T) {
	for _, k := range []string{
		"CALABI_EDGE_MODE", "CALABI_EDGE_ROLE", "CALABI_EDGE_RELAY_KIND",
		"CALABI_EDGE_RELAY_LABEL", "CALABI_EDGE_RELAY_COORD_PUBKEY",
		"CALABI_EDGE_RELAY_DERP_PORT", "CALABI_EDGE_RELAY_STUN_PORT",
		"CALABI_EDGE_RELAY_REQUIRE_AUTH",
		"CALABI_EDGE_ADMIN_ADDR",
	} {
		t.Setenv(k, "")
	}
	before := Default()
	before.Role = "both"
	before.Relay = RelayRole{Kind: "platform", DERPPort: 3340, RequireAuth: true, CoordPubKey: "k"}

	after, err := ApplyEnv(before)
	if err != nil {
		t.Fatalf("ApplyEnv: %v", err)
	}
	if after.Role != before.Role || after.Relay != before.Relay || after.Mode != before.Mode {
		t.Errorf("unset env changed the config: %+v -> %+v", before.Relay, after.Relay)
	}
}

// TestApplyEnvRejectsMalformed: a typo must fail loudly. A relay that silently
// ignored REQUIRE_AUTH would be exactly the fail-open posture prodguard.go
// exists to prevent — and it would do it while LOOKING configured.
func TestApplyEnvRejectsMalformed(t *testing.T) {
	cases := []struct{ key, val string }{
		{"CALABI_EDGE_RELAY_REQUIRE_AUTH", "yess"},
		{"CALABI_EDGE_RELAY_REQUIRE_AUTH", "enabled"},
		{"CALABI_EDGE_RELAY_DERP_PORT", "three-thousand"},
		{"CALABI_EDGE_RELAY_DERP_PORT", "70000"},
		{"CALABI_EDGE_RELAY_STUN_PORT", "-1"},
	}
	for _, c := range cases {
		t.Run(c.key+"="+c.val, func(t *testing.T) {
			t.Setenv(c.key, c.val)
			_, err := ApplyEnv(Default())
			if err == nil {
				t.Fatalf("%s=%q was accepted", c.key, c.val)
			}
			if !strings.Contains(err.Error(), c.key) {
				t.Errorf("error should name the variable, got: %v", err)
			}
		})
	}
}

// TestApplyEnvStunPortZeroDisables: 0 is a legal value (it turns the STUN
// responder off), so it must not be treated as "unset" or as an error.
func TestApplyEnvStunPortZeroDisables(t *testing.T) {
	t.Setenv("CALABI_EDGE_RELAY_STUN_PORT", "0")
	cfg, err := ApplyEnv(Default())
	if err != nil {
		t.Fatalf("ApplyEnv: %v", err)
	}
	if cfg.Relay.STUNPort != 0 {
		t.Errorf("STUNPort = %d, want 0 (disabled)", cfg.Relay.STUNPort)
	}
}
