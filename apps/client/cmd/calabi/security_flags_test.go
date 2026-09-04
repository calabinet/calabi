package main

import (
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBuildConfigJSON_Empty(t *testing.T) {
	sf := &securityFlags{l7: true}
	got, err := sf.buildConfigJSON()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "" {
		t.Fatalf("want empty string when nothing configured, got %q", got)
	}
}

// IP allow/deny is present in every edition.
func TestBuildConfigJSON_IPOnly(t *testing.T) {
	sf := &securityFlags{l7: false}
	sf.ipAllow = stringList{"10.0.0.0/8", "1.2.3.4"}
	sf.ipDeny = stringList{"5.6.7.8"}
	got, err := sf.buildConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	var env secEnvelope
	if err := json.Unmarshal([]byte(got), &env); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, got)
	}
	if env.Security.IP == nil || len(env.Security.IP.Allow) != 2 || env.Security.IP.Deny[0] != "5.6.7.8" {
		t.Fatalf("ip block wrong: %+v", env.Security.IP)
	}
}

func TestBuildConfigJSON_BasicAuthHashesNotCleartext(t *testing.T) {
	sf := &securityFlags{l7: true}
	sf.basicAuth = stringList{"alice:s3cret"}
	got, err := sf.buildConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	var env secEnvelope
	if err := json.Unmarshal([]byte(got), &env); err != nil {
		t.Fatal(err)
	}
	if env.Security.BasicAuth == nil || len(env.Security.BasicAuth.Users) != 1 {
		t.Fatalf("basic_auth missing: %s", got)
	}
	u := env.Security.BasicAuth.Users[0]
	if u.User != "alice" {
		t.Fatalf("user wrong: %q", u.User)
	}
	// The cleartext password must never reach the wire — only the bcrypt hash.
	if strings.Contains(got, "s3cret") {
		t.Fatalf("cleartext password leaked into config_json: %s", got)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte("s3cret")); err != nil {
		t.Fatalf("bcrypt hash does not verify the original password: %v", err)
	}
}

func TestBuildConfigJSON_BasicAuthMalformed(t *testing.T) {
	sf := &securityFlags{l7: true, basicAuth: stringList{"noseparator"}}
	if _, err := sf.buildConfigJSON(); err == nil {
		t.Fatal("want error for basic-auth missing ':'")
	}
}
