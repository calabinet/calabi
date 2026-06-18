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
		name             string
		mode             string
		controlPlaneWired bool
		want             bool
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

// TestNormalizeForMode covers the standalone normalization that fixes the
// config.Default() interaction: a config-less standalone edge (which inherits
// dev-localhost identity/tunnel addrs from Default) must end up with NO control
// plane wired so the trust guard fires correctly; a BYOI (bff-edge) edge must be
// refused standalone and downgraded to platform.
func TestNormalizeForMode(t *testing.T) {
	t.Run("standalone fork clears control-plane addrs", func(t *testing.T) {
		in := Config{Mode: "standalone"}
		in.Identity.Addr = "127.0.0.1:7001" // as config.Default() injects
		in.Tunnel.Addr = "127.0.0.1:7003"
		in.Quota.Addr = "127.0.0.1:7004"
		out, refused := in.NormalizeForMode()
		if refused {
			t.Fatal("fork must not be byoiRefused")
		}
		if out.Identity.Addr != "" || out.Tunnel.Addr != "" || out.Quota.Addr != "" {
			t.Fatalf("control-plane addrs not cleared: %+v", out)
		}
		if !out.IsStandaloneMode() {
			t.Fatal("fork should stay standalone")
		}
		// And the trust guard now trusts (no control plane wired).
		wired := out.Identity.Addr != "" || out.Tunnel.Addr != ""
		if !out.TrustsClientPolicy(wired) {
			t.Fatal("standalone fork should trust client policy after normalize")
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
		in := Config{Mode: "platform"}
		in.Identity.Addr = "127.0.0.1:7001"
		out, refused := in.NormalizeForMode()
		if refused || out.Identity.Addr != "127.0.0.1:7001" {
			t.Fatalf("platform must pass through unchanged: refused=%v out=%+v", refused, out)
		}
	})
}
