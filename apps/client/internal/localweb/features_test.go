package localweb

import (
	"strings"
	"testing"
)

// On the platform build the advanced blocks pass through transformSecurityConfig
// untouched, and the capability map advertises them.
func TestPlatform_AdvancedSecurityPreserved(t *testing.T) {
	in := `{"security":{"rate_limit":{"per_minute":100},"oauth":{"provider":"google"}}}`
	out, err := transformSecurityConfig(in)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if !strings.Contains(out, `"per_minute":100`) || !strings.Contains(out, `"provider":"google"`) {
		t.Errorf("advanced blocks not preserved on platform: %s", out)
	}
	for _, k := range []string{`"rate_limit":true`, `"header_rewrite":true`, `"oauth":true`} {
		if !strings.Contains(standaloneFeatures, k) {
			t.Errorf("standaloneFeatures missing %s: %s", k, standaloneFeatures)
		}
	}
}
