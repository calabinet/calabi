package config

import (
	"strings"
	"testing"
)

// Role gating, both vocabularies at once.
//
// The two current names say which SERVICE a node provides (tunnel / mesh); the
// two retired ones named the machinery (edge / relay). The retired pair is not
// deprecated-and-scheduled-for-removal, it is permanent: `CALABI_EDGE_ROLE=relay`
// is the copy-paste line in the published self-hosting guide, so it already sits
// in strangers' systemd units where we cannot migrate it.
//
// An empty role MUST still behave exactly like today's edge, and a typo must be
// rejected rather than silently running neither datapath.
func TestRoleGating(t *testing.T) {
	cases := []struct {
		role                 string
		wantTunnel, wantMesh bool
	}{
		{"", true, false},       // default = tunnels, unchanged
		{"tunnel", true, false}, //
		{"edge", true, false},   // retired spelling of the same thing
		{"mesh", false, true},   // mesh only: no tunnels
		{"relay", false, true},  // retired spelling of the same thing
		{"both", true, true},    //
		{"  Both ", true, true}, // case/space-insensitive
		{"RELAY", false, true},  //
		{"  Mesh ", false, true},
	}
	for _, c := range cases {
		cfg := Config{Role: c.role}
		if got := cfg.ServesTunnels(); got != c.wantTunnel {
			t.Errorf("role=%q ServesTunnels()=%v want %v", c.role, got, c.wantTunnel)
		}
		if got := cfg.ServesMesh(); got != c.wantMesh {
			t.Errorf("role=%q ServesMesh()=%v want %v", c.role, got, c.wantMesh)
		}
	}
}

// The two predicates are driven by ONE table, and this is why: a role that
// satisfies neither runs no data plane at all (the node boots healthy and
// serves nothing), and a role that satisfies both binds tunnel listeners on a
// node its operator believes is mesh-only. Either way nothing throws.
func TestEveryAcceptedRoleRunsExactlyWhatItNames(t *testing.T) {
	for spelling, canonical := range roleAliases {
		cfg := Config{Role: spelling}
		if err := cfg.ValidateRole(); err != nil {
			t.Errorf("role=%q is in roleAliases but ValidateRole refuses it: %v", spelling, err)
		}
		if !cfg.ServesTunnels() && !cfg.ServesMesh() {
			t.Errorf("role=%q (=%q) runs NEITHER data plane", spelling, canonical)
		}
		if canonical != "both" && cfg.ServesTunnels() && cfg.ServesMesh() {
			t.Errorf("role=%q (=%q) runs BOTH data planes", spelling, canonical)
		}
	}
}

func TestValidateRole(t *testing.T) {
	for _, ok := range []string{"", "tunnel", "mesh", "both", "edge", "relay", "EDGE", " both ", "Tunnel"} {
		if err := (Config{Role: ok}).ValidateRole(); err != nil {
			t.Errorf("role=%q should be valid, got %v", ok, err)
		}
	}
	for _, bad := range []string{"foo", "gateway", "edge,relay", "tunnels", "meshes"} {
		if err := (Config{Role: bad}).ValidateRole(); err == nil {
			t.Errorf("role=%q should be rejected", bad)
		}
	}
	// The message must name what to write now, and say the old names still work
	// — an operator who hits this is usually mid-rename.
	err := (Config{Role: "gateway"}).ValidateRole()
	for _, want := range []string{"tunnel", "mesh", "both", "edge", "relay"} {
		if err == nil || !contains(err.Error(), want) {
			t.Errorf("the error should mention %q: %v", want, err)
		}
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestRelayPortDefaults(t *testing.T) {
	var zero MeshService
	if got := zero.RelayDERPPort(); got != 3340 {
		t.Errorf("default derp_port=%d want 3340", got)
	}
	if got := zero.RelaySTUNPort(); got != 3478 {
		t.Errorf("default stun_port=%d want 3478", got)
	}
	set := MeshService{DERPPort: 4000, STUNPort: 4001}
	if set.RelayDERPPort() != 4000 || set.RelaySTUNPort() != 4001 {
		t.Errorf("explicit ports not honoured: %+v", set)
	}
}
