package config

import (
	"strings"
	"testing"
)

// prodCfg is a healthy PLATFORM edge: the control plane reached through
// bff-edge (the only way since F3 step 2b), real tokens, and a platform relay
// that verifies grants — i.e. deploy/compose/edge/edge.yaml.
func prodCfg() Config {
	return Config{
		Mode: "",
		Role: "both",
		MultiRegion: MultiRegionConfig{
			Mode:        "bff-edge",
			BFFEdgeAddr: "bff-edge.calabi.net:443",
			ClientCert:  "/etc/calabi/edge-client.crt",
			ClientKey:   "/etc/calabi/edge-client.key",
			CA:          "/etc/calabi/ca.crt",
		},
		AcceptedTokens: []TokenEntry{{Token: "a-real-secret", TenantID: "1"}},
		Relay: RelayRole{
			Kind:        "platform",
			RequireAuth: true,
			CoordPubKey: "xMqLvONWcTdghKQ4cwvVQ81FuXDj/0npFphl4BujbdA=",
		},
	}
}

// TestProductionPostureAcceptsTheRealDeployment pins that the guard is silent
// for the actual production edge — a guard that fires on the real config would
// just get switched off.
func TestProductionPostureAcceptsTheRealDeployment(t *testing.T) {
	t.Setenv("CALABI_ENV", "production")
	if err := prodCfg().ValidateProductionPosture(); err != nil {
		t.Fatalf("healthy production edge rejected: %v", err)
	}
}

// TestProductionPostureIgnoredOutsideProduction: dev and self-hosted edges keep
// every fallback, including the shipped placeholder token.
func TestProductionPostureIgnoredOutsideProduction(t *testing.T) {
	broken := Config{AcceptedTokens: []TokenEntry{{Token: PlaceholderToken}}}
	for _, env := range []string{"", "dev", "staging"} {
		t.Run("CALABI_ENV="+env, func(t *testing.T) {
			t.Setenv("CALABI_ENV", env)
			if err := broken.ValidateProductionPosture(); err != nil {
				t.Fatalf("guard fired outside production (CALABI_ENV=%q): %v", env, err)
			}
		})
	}
}

func TestProductionPostureRejectsFailOpen(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*Config)
		wantMention string
	}{
		{
			name:        "platform mode with no bff-edge falls back to static tokens",
			mutate:      func(c *Config) { c.MultiRegion = MultiRegionConfig{} },
			wantMention: "static accepted_tokens table",
		},
		{
			name:        "the shipped placeholder credential",
			mutate:      func(c *Config) { c.AcceptedTokens[0].Token = PlaceholderToken },
			wantMention: PlaceholderToken,
		},
		{
			name:        "platform relay that does not verify grants",
			mutate:      func(c *Config) { c.Relay.RequireAuth = false },
			wantMention: "relay.require_auth",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("CALABI_ENV", "production")
			cfg := prodCfg()
			c.mutate(&cfg)
			err := cfg.ValidateProductionPosture()
			if err == nil {
				t.Fatal("production posture accepted a fail-open fallback")
			}
			if !strings.Contains(err.Error(), c.wantMention) {
				t.Errorf("error does not name the problem %q: %v", c.wantMention, err)
			}
		})
	}
}

// TestStandaloneIsAStatedIntent: a standalone edge legitimately has no control
// plane, so the static-token fallback must NOT be reported for it — only the
// placeholder credential is still refused.
func TestStandaloneIsAStatedIntent(t *testing.T) {
	t.Setenv("CALABI_ENV", "production")
	cfg := prodCfg()
	cfg.Mode = "standalone"
	cfg.MultiRegion = MultiRegionConfig{}
	if err := cfg.ValidateProductionPosture(); err != nil {
		t.Fatalf("a standalone edge states its own intent and must pass: %v", err)
	}

	cfg.AcceptedTokens[0].Token = PlaceholderToken
	if err := cfg.ValidateProductionPosture(); err == nil {
		t.Fatal("a standalone edge carrying the published placeholder token is just as open; want an error")
	}
}

// TestSelfHostedRelayMayRunUngranted: only kind=platform relays are held to
// grant verification — a BYOI node's own relay is the org's business.
func TestSelfHostedRelayMayRunUngranted(t *testing.T) {
	t.Setenv("CALABI_ENV", "production")
	cfg := prodCfg()
	cfg.Relay.Kind = "self"
	cfg.Relay.RequireAuth = false
	if err := cfg.ValidateProductionPosture(); err != nil {
		t.Fatalf("a self-hosted relay may run without grants: %v", err)
	}
}

// TestEdgeOnlyRoleSkipsRelayChecks: relay settings are inert when the node
// serves no relay datapath.
func TestEdgeOnlyRoleSkipsRelayChecks(t *testing.T) {
	t.Setenv("CALABI_ENV", "production")
	cfg := prodCfg()
	cfg.Role = "edge"
	cfg.Relay.RequireAuth = false
	if err := cfg.ValidateProductionPosture(); err != nil {
		t.Fatalf("role=edge runs no relay, so relay.require_auth is irrelevant: %v", err)
	}
}

// TestProductionPostureReportsEveryProblem: one restart, the whole list.
func TestProductionPostureReportsEveryProblem(t *testing.T) {
	t.Setenv("CALABI_ENV", "production")
	cfg := prodCfg()
	cfg.MultiRegion = MultiRegionConfig{}
	cfg.AcceptedTokens[0].Token = PlaceholderToken
	cfg.Relay.RequireAuth = false

	err := cfg.ValidateProductionPosture()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"static accepted_tokens table", PlaceholderToken, "relay.require_auth", "3 fail-open"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("combined error is missing %q: %v", want, err)
		}
	}
}
