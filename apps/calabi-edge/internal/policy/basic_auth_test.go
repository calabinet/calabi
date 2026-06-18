package policy

import (
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func basicHeader(userPass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userPass))
}

func TestBasicAuth(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("gen hash: %v", err)
	}
	cfg := fmt.Sprintf(`{"security":{"basic_auth":{"users":[{"user":"alice","hash":%q}]}}}`, string(hash))
	p, err := Parse(cfg)
	if err != nil || p == nil {
		t.Fatalf("parse: p=%v err=%v", p, err)
	}
	if !p.HasBasicAuth() {
		t.Fatalf("policy must require basic auth")
	}
	// A basic-auth-only policy has no IP rules but is still a real policy.
	if p.HasIPRules() {
		t.Fatalf("basic-auth-only policy must report no IP rules")
	}

	if !p.CheckBasicAuth(basicHeader("alice:s3cret")) {
		t.Fatalf("correct credentials must pass")
	}
	// Second call exercises the success cache.
	if !p.CheckBasicAuth(basicHeader("alice:s3cret")) {
		t.Fatalf("cached credentials must pass")
	}

	for _, bad := range []struct {
		name, header string
	}{
		{"wrong password", basicHeader("alice:wrong")},
		{"unknown user", basicHeader("bob:s3cret")},
		{"missing header", ""},
		{"non-basic scheme", "Bearer abc"},
		{"malformed base64", "Basic not_base64!!"},
		{"no colon", basicHeader("alicenopass")},
	} {
		if p.CheckBasicAuth(bad.header) {
			t.Fatalf("%s must be rejected", bad.name)
		}
	}
}

func TestBasicAuth_NilPolicyAllows(t *testing.T) {
	var p *Policy
	if !p.CheckBasicAuth("") {
		t.Fatalf("nil policy must not require auth")
	}
	if p.HasBasicAuth() {
		t.Fatalf("nil policy has no basic auth")
	}
}

func TestParse_BasicAuthSkipsIncompleteUsers(t *testing.T) {
	// Entries missing a user or hash are dropped; if none remain → no policy.
	p, _ := Parse(`{"security":{"basic_auth":{"users":[{"user":"","hash":"x"},{"user":"a","hash":""}]}}}`)
	if p != nil {
		t.Fatalf("all-incomplete users should yield no policy, got %+v", p)
	}
}
