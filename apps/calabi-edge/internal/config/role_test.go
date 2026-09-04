package config

import "testing"

// The edge/derp merge hinges on role gating: an empty role MUST behave exactly
// like today's edge (RunsEdge true, RunsRelay false), and a typo must be rejected
// rather than silently run neither datapath.
func TestRoleGating(t *testing.T) {
	cases := []struct {
		role                string
		wantEdge, wantRelay bool
	}{
		{"", true, false},        // default = edge, unchanged
		{"edge", true, false},    //
		{"relay", false, true},   // relay only: no tunnels
		{"both", true, true},     //
		{"  Both ", true, true},  // case/space-insensitive
		{"RELAY", false, true},   //
	}
	for _, c := range cases {
		cfg := Config{Role: c.role}
		if got := cfg.RunsEdge(); got != c.wantEdge {
			t.Errorf("role=%q RunsEdge()=%v want %v", c.role, got, c.wantEdge)
		}
		if got := cfg.RunsRelay(); got != c.wantRelay {
			t.Errorf("role=%q RunsRelay()=%v want %v", c.role, got, c.wantRelay)
		}
	}
}

func TestValidateRole(t *testing.T) {
	for _, ok := range []string{"", "edge", "relay", "both", "EDGE", " both "} {
		if err := (Config{Role: ok}).ValidateRole(); err != nil {
			t.Errorf("role=%q should be valid, got %v", ok, err)
		}
	}
	for _, bad := range []string{"foo", "gateway", "edge,relay"} {
		if err := (Config{Role: bad}).ValidateRole(); err == nil {
			t.Errorf("role=%q should be rejected", bad)
		}
	}
}

func TestRelayPortDefaults(t *testing.T) {
	var zero RelayRole
	if got := zero.RelayDERPPort(); got != 3340 {
		t.Errorf("default derp_port=%d want 3340", got)
	}
	if got := zero.RelaySTUNPort(); got != 3478 {
		t.Errorf("default stun_port=%d want 3478", got)
	}
	set := RelayRole{DERPPort: 4000, STUNPort: 4001}
	if set.RelayDERPPort() != 4000 || set.RelaySTUNPort() != 4001 {
		t.Errorf("explicit ports not honoured: %+v", set)
	}
}
