package main

import (
	"path/filepath"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// Regression: a fresh interactive login must win over a stale CALABI_API_KEY
// left in the environment. Otherwise the desktop/SPA sign-in appears to do
// nothing and the edge rejects the handshake with code 2002, because the
// leftover env key hijacks the bearer.
func TestResolveCredential_LoginBeatsStaleEnvKey(t *testing.T) {
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	t.Setenv("CALABI_API_KEY", "tk_stale")
	t.Setenv("CALABI_TOKEN", "")
	if err := creds.Save(&creds.Config{AccessToken: "login-jwt"}); err != nil {
		t.Fatal(err)
	}
	tok, kind := resolveCredential()
	if tok != "login-jwt" || kind != credLogin {
		t.Fatalf("got (%q, %v), want (login-jwt, credLogin)", tok, kind)
	}
	if daemonUsesAPIKey() {
		t.Fatal("daemonUsesAPIKey must be false when the login token is in use")
	}
}

// A real OS service has no interactive user — its credential is the env API
// key, even if some access_token happens to sit in the creds file.
func TestResolveCredential_ServiceUsesEnvKey(t *testing.T) {
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	t.Setenv("CALABI_API_KEY", "tk_service")
	t.Setenv("CALABI_TOKEN", "")
	if err := creds.Save(&creds.Config{AccessToken: "login-jwt"}); err != nil {
		t.Fatal(err)
	}
	prev := inServiceManager
	inServiceManager = true
	t.Cleanup(func() { inServiceManager = prev })

	tok, kind := resolveCredential()
	if tok != "tk_service" || kind != credAPIKey {
		t.Fatalf("got (%q, %v), want (tk_service, credAPIKey)", tok, kind)
	}
	if !daemonUsesAPIKey() {
		t.Fatal("daemonUsesAPIKey must be true for a service running on its env key")
	}
}

// With no interactive login saved (the CI / installed-service shape), fall
// through to the env API key.
func TestResolveCredential_NoLoginFallsToEnvKey(t *testing.T) {
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	t.Setenv("CALABI_API_KEY", "tk_env")
	t.Setenv("CALABI_TOKEN", "")
	tok, kind := resolveCredential()
	if tok != "tk_env" || kind != credAPIKey {
		t.Fatalf("got (%q, %v), want (tk_env, credAPIKey)", tok, kind)
	}
}
