package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildConfigJSON_Rate(t *testing.T) {
	sf := &securityFlags{l7: false, rate: 600}
	sf.ipAllow = stringList{"10.0.0.0/8"}
	got, err := sf.buildConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	var env secEnvelope
	if err := json.Unmarshal([]byte(got), &env); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, got)
	}
	if env.Security.RateLimit == nil || env.Security.RateLimit.PerMinute != 600 {
		t.Fatalf("rate block wrong: %+v", env.Security.RateLimit)
	}
}

func TestBuildConfigJSON_RateNegative(t *testing.T) {
	sf := &securityFlags{l7: false, rate: -1}
	if _, err := sf.buildConfigJSON(); err == nil {
		t.Fatal("want error for negative --rate")
	}
}

// YAML rate: on the platform build it survives toSessionTunnel.
func TestToSessionTunnel_L4RatePreserved(t *testing.T) {
	tc := localTunnelConfig{
		Name: "ssh", Type: "tcp", Local: "127.0.0.1:22", RemotePort: 2222,
		Security: &localSecurityConfig{IPDeny: []string{"1.2.3.4"}, Rate: 100},
	}
	tun, err := toSessionTunnel(tc)
	if err != nil {
		t.Fatalf("toSessionTunnel: %v", err)
	}
	if !strings.Contains(tun.SecurityConfigJSON, `"per_minute":100`) {
		t.Errorf("rate should survive on platform: %s", tun.SecurityConfigJSON)
	}
}

func TestBuildConfigJSON_Headers(t *testing.T) {
	sf := &securityFlags{l7: true}
	sf.setHeader = stringList{"X-Foo: bar"}
	sf.delHeader = stringList{"X-Bar"}
	got, err := sf.buildConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	var env secEnvelope
	if err := json.Unmarshal([]byte(got), &env); err != nil {
		t.Fatal(err)
	}
	rh := env.Security.RequestHeaders
	if rh == nil || rh.Set["X-Foo"] != "bar" {
		t.Fatalf("set header wrong: %+v", rh)
	}
	if len(rh.Remove) != 1 || rh.Remove[0] != "X-Bar" {
		t.Fatalf("remove header wrong: %+v", rh)
	}
}

func TestBuildConfigJSON_OAuthRequiresCreds(t *testing.T) {
	// provider without creds → error
	sf := &securityFlags{l7: true, oauthProvider: "google"}
	if _, err := sf.buildConfigJSON(); err == nil {
		t.Fatal("want error: oauth provider without client id/secret")
	}
	// provider with creds → ok
	sf = &securityFlags{l7: true, oauthProvider: "google", oauthClientID: "id", oauthClientSecret: "sec"}
	sf.oauthEmail = stringList{"a@b.com"}
	got, err := sf.buildConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	var env secEnvelope
	if err := json.Unmarshal([]byte(got), &env); err != nil {
		t.Fatal(err)
	}
	o := env.Security.OAuth
	if o == nil || o.Provider != "google" || o.ClientID != "id" || o.ClientSecret != "sec" {
		t.Fatalf("oauth block wrong: %+v", o)
	}
	if len(o.AllowEmails) != 1 || o.AllowEmails[0] != "a@b.com" {
		t.Fatalf("oauth allow_emails wrong: %+v", o.AllowEmails)
	}
}
