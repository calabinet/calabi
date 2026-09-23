package config

import "testing"

func TestIsStandaloneMode(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"standalone", true},
		{"Standalone", true},
		{"  standalone  ", true},
		{"platform", false},
		{"", false},
		{"bogus", false},
	}
	for _, c := range cases {
		if got := (Config{Mode: c.mode}).IsStandaloneMode(); got != c.want {
			t.Errorf("Mode=%q: IsStandaloneMode()=%v want %v", c.mode, got, c.want)
		}
	}
}

// TestTrustsClientPolicy pins the BYOI guard: client-supplied policy is trusted
// ONLY in standalone mode AND when no control plane is wired. A control-plane-
// connected edge (managed or BYOI) must never trust the client, even if
// mode=standalone is mistakenly set.
func TestTrustsClientPolicy(t *testing.T) {
	cases := []struct {
		name              string
		mode              string
		controlPlaneWired bool
		want              bool
	}{
		{"standalone fork (no control plane)", "standalone", false, true},
		{"standalone but control plane wired (BYOI/misconfig)", "standalone", true, false},
		{"platform fork", "platform", false, false},
		{"platform managed", "platform", true, false},
		{"empty mode defaults platform", "", false, false},
	}
	for _, c := range cases {
		got := (Config{Mode: c.mode}).TrustsClientPolicy(c.controlPlaneWired)
		if got != c.want {
			t.Errorf("%s: TrustsClientPolicy(controlPlaneWired=%v) with mode=%q = %v, want %v",
				c.name, c.controlPlaneWired, c.mode, got, c.want)
		}
	}
}

// TestNormalizeForMode covers the standalone normalization: a standalone fork
// must end up with NO control plane wired so the trust guard fires correctly,
// and its relay must require grants whatever the file said; a BYOI (bff-edge)
// edge must be refused standalone and downgraded to platform.
//
// This used to be written in terms of clearing identity.addr / tunnel.addr /
// quota.addr, which config.Default() injected. Those settings are gone — the
// edge has reached the control plane only through bff-edge since F3 — so
// "is a control plane wired" is now multi_region's question alone.
func TestNormalizeForMode(t *testing.T) {
	t.Run("standalone fork keeps standalone and forces grants", func(t *testing.T) {
		in := Config{Mode: "standalone"}
		out, refused := in.NormalizeForMode()
		if refused {
			t.Fatal("fork must not be byoiRefused")
		}
		if !out.IsStandaloneMode() {
			t.Fatal("fork should stay standalone")
		}
		if !out.Mesh.RequireAuth {
			t.Fatal("a standalone node's relay serves its coordinator's devices only; grants must be forced on")
		}
		if !out.TrustsClientPolicy(false) {
			t.Fatal("standalone fork should trust client policy after normalize")
		}
	})

	t.Run("standalone cannot switch the trust guard off by saying so", func(t *testing.T) {
		// The guard takes controlPlaneWired from the CALLER, not from the config,
		// so a node that does have one cannot talk its way out of platform rules.
		out, _ := Config{Mode: "standalone"}.NormalizeForMode()
		if out.TrustsClientPolicy(true) {
			t.Fatal("a wired control plane must override mode: standalone")
		}
	})

	t.Run("BYOI (bff-edge) refused standalone → platform", func(t *testing.T) {
		in := Config{Mode: "standalone"}
		in.MultiRegion.Mode = "bff-edge"
		in.MultiRegion.ClientCert = "/etc/calabi/edge.crt"
		out, refused := in.NormalizeForMode()
		if !refused {
			t.Fatal("BYOI standalone must be refused")
		}
		if out.IsStandaloneMode() {
			t.Fatal("BYOI must be downgraded to platform")
		}
		if out.TrustsClientPolicy(false) {
			t.Fatal("BYOI must never trust client policy")
		}
	})

	t.Run("platform unchanged", func(t *testing.T) {
		in := Config{Mode: "platform", NodeLabel: "edge-1"}
		in.Mesh.RequireAuth = false
		out, refused := in.NormalizeForMode()
		if refused || out.NodeLabel != "edge-1" || out.Mesh.RequireAuth {
			t.Fatalf("platform must pass through unchanged: refused=%v out=%+v", refused, out)
		}
	})
}
