package policy

import "testing"

// In the community build the advanced features (rate limit / header rewrite /
// OAuth) are absent: a config_json carrying those blocks still parses its IP +
// Basic-auth rules, but the advanced predicates report "off" so the blocks are
// silently ignored.
func TestCommunity_AdvancedFeaturesIgnored(t *testing.T) {
	blob := `{"security":{
		"ip":{"allow":["203.0.113.0/24"]},
		"basic_auth":{"users":[{"user":"a","hash":"$2a$10$abcdefghijklmnopqrstuv"}]},
		"rate_limit":{"per_minute":60},
		"request_headers":{"set":{"X-From":"calabi"}},
		"oauth":{"provider":"google","client_id":"x","client_secret":"y"}
	}}`
	p, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p == nil {
		t.Fatal("Parse returned nil; IP + basic_auth should be actionable")
	}
	// Kept features still apply.
	if !p.HasIPRules() {
		t.Error("HasIPRules = false, want true (IP allow kept in community)")
	}
	if !p.HasBasicAuth() {
		t.Error("HasBasicAuth = false, want true (basic auth kept in community)")
	}
	// Advanced features are off.
	if p.HasRateLimit() {
		t.Error("HasRateLimit = true, want false in community build")
	}
	if p.HasRequestHeaders() {
		t.Error("HasRequestHeaders = true, want false in community build")
	}
	if p.HasOAuth() {
		t.Error("HasOAuth = true, want false in community build")
	}
	// RewriteRequestHead is a passthrough.
	head := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if got := string(p.RewriteRequestHead(head)); got != string(head) {
		t.Errorf("RewriteRequestHead mutated head in community build:\n%q", got)
	}
	// AllowRate always permits.
	if !p.AllowRate() {
		t.Error("AllowRate = false, want true (no limiting in community)")
	}
}

// A config_json that contains ONLY advanced blocks has no actionable rules in
// the community build, so Parse returns nil (allow-all).
func TestCommunity_OnlyAdvancedBlocks_NoPolicy(t *testing.T) {
	blob := `{"security":{"rate_limit":{"per_minute":60},"oauth":{"provider":"google"}}}`
	p, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p != nil {
		t.Errorf("Parse = %+v, want nil (advanced-only blob is no-op in community)", p)
	}
}
