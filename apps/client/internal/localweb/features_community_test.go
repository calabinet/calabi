package localweb

import (
	"strings"
	"testing"
)

// On the community build transformSecurityConfig strips the advanced blocks and
// the capability map disables them (so the SPA hides those editor sections).
func TestCommunity_AdvancedSecurityStripped(t *testing.T) {
	in := `{"security":{"ip":{"allow":["10.0.0.0/8"]},"rate_limit":{"per_minute":100},"request_headers":{"set":{"X":"y"}},"oauth":{"provider":"google"}}}`
	out, err := transformSecurityConfig(in)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if !strings.Contains(out, `"allow":["10.0.0.0/8"]`) {
		t.Errorf("IP policy should survive in community: %s", out)
	}
	for _, gone := range []string{"rate_limit", "request_headers", "oauth"} {
		if strings.Contains(out, gone) {
			t.Errorf("advanced block %q should be stripped in community: %s", gone, out)
		}
	}
	for _, k := range []string{`"rate_limit":false`, `"header_rewrite":false`, `"oauth":false`} {
		if !strings.Contains(standaloneFeatures, k) {
			t.Errorf("standaloneFeatures should disable %s: %s", k, standaloneFeatures)
		}
	}
}
