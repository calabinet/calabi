package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// stubKeyVerify replaces the network key-check with a no-op for tests that
// only exercise credential resolution, restoring it when the test ends.
func stubKeyVerify(t *testing.T) {
	t.Helper()
	prev := verifyInstallKeyFn
	verifyInstallKeyFn = func(string) error { return nil }
	t.Cleanup(func() { verifyInstallKeyFn = prev })
}

// A local-config service authenticates from its YAML, so install must not try
// to resolve a platform API key for it.
func TestServiceInstallEnv_LocalConfigSkips(t *testing.T) {
	env, err := serviceInstallEnv([]string{"--config", "tunnels.yaml"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env != nil {
		t.Fatalf("expected nil env for --config service, got %v", env)
	}
}

// The --api-key flag is the explicit, preferred source (and wins over the env).
func TestServiceInstallEnv_FromFlag(t *testing.T) {
	stubKeyVerify(t)
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	t.Setenv("CALABI_API_KEY", "tk_env")
	env, err := serviceInstallEnv([]string{"--api-key", "tk_flag"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env["CALABI_API_KEY"] != "tk_flag" {
		t.Fatalf("got %q, want tk_flag (flag should win over env)", env["CALABI_API_KEY"])
	}
}

// Falls back to CALABI_API_KEY when no flag is given.
func TestServiceInstallEnv_FromEnv(t *testing.T) {
	stubKeyVerify(t)
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	t.Setenv("CALABI_API_KEY", "tk_env")
	env, err := serviceInstallEnv(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env["CALABI_API_KEY"] != "tk_env" {
		t.Fatalf("got %q, want tk_env", env["CALABI_API_KEY"])
	}
}

// No flag and no env → an INTERACTIVE-mode service (no error, no baked key).
// The service waits for a :7400 login rather than refusing to install.
func TestServiceInstallEnv_NoKeyInteractive(t *testing.T) {
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	t.Setenv("CALABI_API_KEY", "")
	env, err := serviceInstallEnv(nil)
	if err != nil {
		t.Fatalf("no-key install should not error (interactive mode): %v", err)
	}
	if _, ok := env["CALABI_API_KEY"]; ok {
		t.Fatalf("interactive install must NOT bake a key, got %q", env["CALABI_API_KEY"])
	}
}

// The user's region + edge-affinity ride along so the service picks the same
// edge as their interactive runs.
func TestServiceInstallEnv_CarriesRegionAndAffinity(t *testing.T) {
	stubKeyVerify(t)
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	t.Setenv("CALABI_API_KEY", "")
	if err := creds.Save(&creds.Config{
		EdgeRegion:         "cn-a",
		PreferPlatformEdge: true,
	}); err != nil {
		t.Fatalf("save creds: %v", err)
	}
	env, err := serviceInstallEnv([]string{"--api-key", "tk_x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]string{
		"CALABI_API_KEY":       "tk_x",
		"CALABI_EDGE_REGION":   "cn-a",
		"CALABI_EDGE_AFFINITY": "platform",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("env[%q] = %q, want %q", k, env[k], v)
		}
	}
}

// A server that 401s the key (invalid / revoked) must make install REFUSE,
// catching the bad key now instead of after the service starts.
func TestVerifyInstallKey_RejectedFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"token not recognized"}`))
	}))
	defer srv.Close()
	t.Setenv("CALABI_BFF_CONSOLE", srv.URL)
	if err := verifyInstallKey("tk_bogus"); err == nil {
		t.Fatal("expected an error when the server rejects the key (401)")
	}
}

// A 200 means the key authenticates → no error.
func TestVerifyInstallKey_AcceptedOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tk_good" {
			t.Errorf("Authorization = %q, want Bearer tk_good", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"user":{}}`))
	}))
	defer srv.Close()
	t.Setenv("CALABI_BFF_CONSOLE", srv.URL)
	if err := verifyInstallKey("tk_good"); err != nil {
		t.Fatalf("expected success for an accepted key, got %v", err)
	}
}

// An unreachable server (or any non-401 failure) must NOT block the install —
// warn-and-proceed, since the key is re-checked when the service connects.
func TestVerifyInstallKey_UnreachableProceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now nothing is listening → connection refused
	t.Setenv("CALABI_BFF_CONSOLE", url)
	if err := verifyInstallKey("tk_whatever"); err != nil {
		t.Fatalf("an unreachable server must not block install, got %v", err)
	}
}
