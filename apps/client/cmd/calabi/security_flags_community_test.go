package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// In the community build the advanced knobs are absent: even if the fields are
// populated (e.g. from tunnels.yaml or a --security-file), buildConfigJSON emits
// no rate_limit / request_headers / oauth — while IP + Basic auth still apply.
func TestBuildConfigJSON_CommunityStripsAdvanced(t *testing.T) {
	sf := &securityFlags{l7: true}
	sf.ipAllow = stringList{"10.0.0.0/8"}
	sf.basicAuth = stringList{"alice:s3cret"}
	// These would be set by YAML toConfigJSON; the community build must ignore them.
	sf.rate = 600
	sf.setHeader = stringList{"X-Foo: bar"}
	sf.oauthProvider = "google"
	sf.oauthClientID = "id"
	sf.oauthClientSecret = "sec"

	got, err := sf.buildConfigJSON()
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var env secEnvelope
	if err := json.Unmarshal([]byte(got), &env); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, got)
	}
	// Kept.
	if env.Security.IP == nil || len(env.Security.IP.Allow) != 1 {
		t.Errorf("IP block missing: %s", got)
	}
	if env.Security.BasicAuth == nil || len(env.Security.BasicAuth.Users) != 1 {
		t.Errorf("basic_auth missing: %s", got)
	}
	// Stripped.
	if env.Security.RateLimit != nil {
		t.Errorf("rate_limit should be absent in community: %+v", env.Security.RateLimit)
	}
	if env.Security.RequestHeaders != nil {
		t.Errorf("request_headers should be absent in community: %+v", env.Security.RequestHeaders)
	}
	if env.Security.OAuth != nil {
		t.Errorf("oauth should be absent in community: %+v", env.Security.OAuth)
	}
}

// A --security-file can't smuggle advanced blocks past the community build.
func TestBuildConfigJSON_CommunityStripsSecurityFileAdvanced(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sec.json"
	blob := `{"security":{"ip":{"allow":["10.0.0.0/8"]},"oauth":{"provider":"google","client_id":"x","client_secret":"y"},"rate_limit":{"per_minute":60}}}`
	if err := os.WriteFile(path, []byte(blob), 0o600); err != nil {
		t.Fatal(err)
	}
	sf := &securityFlags{l7: true, file: path}
	got, err := sf.buildConfigJSON()
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var env secEnvelope
	if err := json.Unmarshal([]byte(got), &env); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, got)
	}
	if env.Security.IP == nil {
		t.Errorf("IP from --security-file should survive: %s", got)
	}
	if env.Security.OAuth != nil || env.Security.RateLimit != nil {
		t.Errorf("advanced blocks from --security-file should be stripped in community: %s", got)
	}
}

// YAML rate on an L4 tunnel is stripped in the community build.
func TestToSessionTunnel_L4RateStripped(t *testing.T) {
	tc := localTunnelConfig{
		Name: "ssh", Type: "tcp", Local: "127.0.0.1:22", RemotePort: 2222,
		Security: &localSecurityConfig{IPDeny: []string{"1.2.3.4"}, Rate: 100},
	}
	tun, err := toSessionTunnel(tc)
	if err != nil {
		t.Fatalf("toSessionTunnel: %v", err)
	}
	if !strings.Contains(tun.SecurityConfigJSON, `"deny":["1.2.3.4"]`) {
		t.Errorf("IP should survive in community: %s", tun.SecurityConfigJSON)
	}
	if strings.Contains(tun.SecurityConfigJSON, "per_minute") {
		t.Errorf("rate should be stripped in community: %s", tun.SecurityConfigJSON)
	}
}
