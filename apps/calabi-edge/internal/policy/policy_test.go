package policy

import (
	"net"
	"testing"
)

func TestParse_NoPolicy(t *testing.T) {
	for _, in := range []string{
		"", "   ", "{}",
		`{"security":{}}`,
		`{"security":{"ip":{}}}`,
		`{"security":{"ip":{"allow":[],"deny":[]}}}`,
		`{"other":{"foo":1}}`, // unrelated config, no security block
	} {
		p, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q) unexpected err: %v", in, err)
		}
		if p != nil {
			t.Fatalf("Parse(%q) = %+v, want nil (no actionable policy)", in, p)
		}
		// nil policy must allow everything.
		if !p.EvaluateIP(net.ParseIP("203.0.113.1")) {
			t.Fatalf("nil policy must allow all")
		}
	}
}

func TestParse_MalformedJSON_FailOpen(t *testing.T) {
	p, err := Parse(`{"security":{"ip":{"allow":[`)
	if err == nil {
		t.Fatalf("want error on malformed JSON")
	}
	// On parse error the caller treats the (nil) policy as allow-all.
	if p != nil {
		t.Fatalf("malformed JSON should yield nil policy, got %+v", p)
	}
}

func TestEvaluateIP_Allowlist(t *testing.T) {
	p, err := Parse(`{"security":{"ip":{"allow":["203.0.113.0/24","198.51.100.7"]}}}`)
	if err != nil || p == nil {
		t.Fatalf("Parse: p=%v err=%v", p, err)
	}
	cases := map[string]bool{
		"203.0.113.5":  true,  // in /24
		"203.0.113.0":  true,  // network addr in range
		"198.51.100.7": true,  // bare IP → /32 host route
		"198.51.100.8": false, // adjacent host, not listed
		"8.8.8.8":      false, // outside allowlist → deny
	}
	for ip, want := range cases {
		if got := p.AllowIPString(ip); got != want {
			t.Fatalf("AllowIPString(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestEvaluateIP_DenyWinsOverAllow(t *testing.T) {
	// 10.0.0.0/8 allowed, but 10.0.0.66 explicitly denied → deny wins.
	p, err := Parse(`{"security":{"ip":{"allow":["10.0.0.0/8"],"deny":["10.0.0.66/32"]}}}`)
	if err != nil || p == nil {
		t.Fatalf("Parse: p=%v err=%v", p, err)
	}
	if p.AllowIPString("10.0.0.5") != true {
		t.Fatalf("10.0.0.5 should be allowed (in allow, not in deny)")
	}
	if p.AllowIPString("10.0.0.66") != false {
		t.Fatalf("10.0.0.66 should be denied (deny wins over allow)")
	}
}

func TestEvaluateIP_DenyOnly(t *testing.T) {
	// No allow list → allow everything except the deny set.
	p, err := Parse(`{"security":{"ip":{"deny":["192.0.2.0/24"]}}}`)
	if err != nil || p == nil {
		t.Fatalf("Parse: p=%v err=%v", p, err)
	}
	if p.AllowIPString("192.0.2.10") != false {
		t.Fatalf("192.0.2.10 should be denied")
	}
	if p.AllowIPString("8.8.8.8") != true {
		t.Fatalf("8.8.8.8 should be allowed (deny-only mode, not in deny)")
	}
}

func TestEvaluateIP_UnknownSourceDeniedUnderAllowlist(t *testing.T) {
	// With an allow list configured, an unparseable / unknown source IP must
	// NOT slip through (correct restrictive default for "only these IPs").
	p, _ := Parse(`{"security":{"ip":{"allow":["203.0.113.0/24"]}}}`)
	if p.AllowIPString("not-an-ip") != false {
		t.Fatalf("unparseable source must be denied when an allowlist exists")
	}
	if p.EvaluateIP(nil) != false {
		t.Fatalf("nil ip must be denied when an allowlist exists")
	}
}

func TestEvaluateIP_UnknownSourceAllowedWithoutAllowlist(t *testing.T) {
	// Deny-only policy: an unknown source isn't in the deny set → allow.
	p, _ := Parse(`{"security":{"ip":{"deny":["192.0.2.0/24"]}}}`)
	if p.AllowIPString("not-an-ip") != true {
		t.Fatalf("unparseable source should be allowed under deny-only policy")
	}
}

func TestParse_SkipsMalformedCIDR(t *testing.T) {
	// A bogus allow entry is skipped; the valid one still applies.
	p, err := Parse(`{"security":{"ip":{"allow":["bogus","203.0.113.0/24","999.1.1.1"]}}}`)
	if err != nil || p == nil {
		t.Fatalf("Parse: p=%v err=%v", p, err)
	}
	if len(p.IPAllow) != 1 {
		t.Fatalf("want 1 valid allow net, got %d", len(p.IPAllow))
	}
	if !p.AllowIPString("203.0.113.9") {
		t.Fatalf("valid allow entry must still match")
	}
}

func TestParse_AllMalformedAllow_NoPolicy(t *testing.T) {
	// If every entry is junk, there are no rules → nil policy (allow all),
	// NOT an accidental allowlist that blocks everyone.
	p, err := Parse(`{"security":{"ip":{"allow":["bogus","also-bogus"]}}}`)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if p != nil {
		t.Fatalf("all-malformed allow should yield nil policy, got %+v", p)
	}
}

func TestEvaluateIP_IPv6(t *testing.T) {
	p, err := Parse(`{"security":{"ip":{"allow":["2001:db8::/32"]}}}`)
	if err != nil || p == nil {
		t.Fatalf("Parse: p=%v err=%v", p, err)
	}
	if !p.AllowIPString("2001:db8::1") {
		t.Fatalf("2001:db8::1 should be allowed")
	}
	if p.AllowIPString("2001:dead::1") {
		t.Fatalf("2001:dead::1 should be denied")
	}
}

func TestHasIPRules(t *testing.T) {
	var nilP *Policy
	if nilP.HasIPRules() {
		t.Fatalf("nil policy has no rules")
	}
	p, _ := Parse(`{"security":{"ip":{"allow":["203.0.113.0/24"]}}}`)
	if !p.HasIPRules() {
		t.Fatalf("policy with allow rules should report HasIPRules")
	}
}
