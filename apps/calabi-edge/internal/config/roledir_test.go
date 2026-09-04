package config

import "testing"

// The edge directory is where a daemon picks its control target. A node that
// runs only the relay has no control listener, so appearing there hands
// daemons an address that refuses every connection. These are the exact
// predicates wire_platform.go gates the edge-registrar on, so pin their truth
// table rather than the wiring.
func TestRoleGating_WhoBelongsInTheEdgeDirectory(t *testing.T) {
	cases := []struct {
		name      string
		role      string
		relayKind string
		wantInDir bool
	}{
		// Empty role means "edge" — every config written before roles existed.
		{"legacy config, no role", "", "", true},
		{"entry only", "edge", "", true},
		{"entry + relay", "both", "", true},
		// Self-hosted relay-only: registers its RELAY via bff-edge, and must
		// stay out of the tunnel directory.
		{"self-hosted relay only", "relay", "", false},
		{"self-hosted relay only, explicit kind", "relay", "self", false},
		// A PLATFORM relay is different: coord assembles the platform DERP map
		// from the edge directory, so dropping the row would drop the relay.
		{"platform relay only", "relay", "platform", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Config{Role: c.role, Relay: RelayRole{Kind: c.relayKind}}
			got := cfg.RunsEdge() || cfg.Relay.IsPlatformKind()
			if got != c.wantInDir {
				t.Errorf("role=%q kind=%q: belongs in edge directory = %v, want %v",
					c.role, c.relayKind, got, c.wantInDir)
			}
		})
	}
}
