package localweb

import (
	"strings"
	"testing"
)

// A cleartext basic-auth password from the SPA must be bcrypt-hashed and the
// cleartext stripped before it's forwarded / persisted.
func TestTransformSecurityConfig_BcryptsCleartext(t *testing.T) {
	in := `{"security":{"basic_auth":{"users":[{"user":"admin","password":"hunter2"}]}}}`
	out, err := transformSecurityConfig(in)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if !strings.Contains(out, `"hash":"$2`) {
		t.Errorf("password not bcrypt-hashed: %s", out)
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("cleartext password leaked: %s", out)
	}
	if strings.Contains(out, `"password"`) {
		t.Errorf("cleartext password field not stripped: %s", out)
	}
	if !strings.Contains(out, `"user":"admin"`) {
		t.Errorf("user lost: %s", out)
	}
}

// An existing bcrypt hash is left untouched (re-saving an unchanged editor).
func TestTransformSecurityConfig_KeepsExistingHash(t *testing.T) {
	in := `{"security":{"basic_auth":{"users":[{"user":"a","hash":"$2a$10$abcdefghijklmnopqrstuv"}]}}}`
	out, err := transformSecurityConfig(in)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if !strings.Contains(out, "$2a$10$abcdefghijklmnopqrstuv") {
		t.Errorf("existing hash not preserved: %s", out)
	}
}

// IP policy survives the transform untouched in every deployment.
func TestTransformSecurityConfig_PreservesIP(t *testing.T) {
	in := `{"security":{"ip":{"allow":["10.0.0.0/8"]}}}`
	out, err := transformSecurityConfig(in)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if !strings.Contains(out, `"allow":["10.0.0.0/8"]`) {
		t.Errorf("ip policy not preserved: %s", out)
	}
}

func TestTransformSecurityConfig_Empty(t *testing.T) {
	out, err := transformSecurityConfig("")
	if err != nil || out != "" {
		t.Errorf("empty → (%q,%v), want empty", out, err)
	}
}

func TestTransformSecurityConfig_BadJSON(t *testing.T) {
	if _, err := transformSecurityConfig("{not json"); err == nil {
		t.Error("want error for malformed config_json")
	}
}
