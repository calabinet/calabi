package policy

import "testing"

func TestRateLimit(t *testing.T) {
	p, err := Parse(`{"security":{"rate_limit":{"per_minute":60}}}`)
	if err != nil || p == nil {
		t.Fatalf("parse: p=%v err=%v", p, err)
	}
	if !p.HasRateLimit() {
		t.Fatalf("policy must have a rate limit")
	}
	// A rate-limit-only policy has no IP / basic-auth rules.
	if p.HasIPRules() || p.HasBasicAuth() {
		t.Fatalf("rate-limit-only policy must report no IP / basic-auth rules")
	}

	// burst = 60/6 = 10 (the floor). In a tight loop only the burst is admitted
	// (refill is 1/sec — no real time passes), so ~10 pass and the rest shed.
	allowed := 0
	for i := 0; i < 50; i++ {
		if p.AllowRate() {
			allowed++
		}
	}
	if allowed < 8 || allowed > 12 {
		t.Fatalf("expected ~10 (burst) admitted, got %d", allowed)
	}
}

func TestRateLimit_ZeroIsUnlimited(t *testing.T) {
	// per_minute <= 0 means no cap → no actionable policy.
	p, err := Parse(`{"security":{"rate_limit":{"per_minute":0}}}`)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if p != nil {
		t.Fatalf("per_minute=0 must yield no policy, got %+v", p)
	}
	var nilP *Policy
	if !nilP.AllowRate() || nilP.HasRateLimit() {
		t.Fatalf("nil policy must be unlimited")
	}
}
