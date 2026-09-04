package config

// SECURITY AUDIT — Domain 3 (data plane): the per-proxy security policy a
// client supplies in NEW_PROXY (IP allowlist, basic-auth, rate-limit, OAuth
// wall) must be honoured ONLY on a standalone/self-hosted edge with NO control
// plane. A platform or BYOI edge (controlPlaneWired=true) must NEVER trust the
// client — otherwise a tampered client could self-grant paid features or drop
// its own restrictions. This drives the real Config.TrustsClientPolicy guard.
//
//   go test./apps/calabi-edge/internal/config/ -run TestReproTrustPolicy -v

import "testing"

func TestReproTrustPolicy_PlatformNeverTrustsClient(t *testing.T) {
	cases := []struct {
		name              string
		mode              string
		controlPlaneWired bool
		wantTrust         bool
	}{
		{"standalone-fork (no control plane)", "standalone", false, true},
		{"standalone-but-control-plane-wired (BYOI)", "standalone", true, false},
		{"platform", "platform", false, false},
		{"platform-with-control-plane", "platform", true, false},
		{"empty-mode defaults to platform", "", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Config{Mode: c.mode}.TrustsClientPolicy(c.controlPlaneWired)
			if got != c.wantTrust {
				t.Fatalf("TrustsClientPolicy(mode=%q, wired=%v)=%v, want %v",
					c.mode, c.controlPlaneWired, got, c.wantTrust)
			}
		})
	}
	t.Logf("CONFIRMED: only standalone+no-control-plane trusts client policy; platform/BYOI never do")
}
