// service_mode_test.go — `calabi mode standalone` must not be lost at
// `daemon install`.
//
// The mode lives in creds.Config.Mode, which is per DATA DIRECTORY. An
// installed service has its own (next to the exe, or ProgramData for --system),
// so a value the user saved interactively is simply not there when the service
// boots: resolveClientMode falls back to "platform" and the service dials the
// control plane, registers the device and joins the mesh — the exact opposite
// of what the user asked for, with nothing on screen saying so.
//
// serviceInstallEnv already carried EdgeRegion and PreferPlatformEdge across
// that boundary. The mode — the one preference that decides whether this
// machine talks to the platform at all — was the one that did not travel.
//
// RUN: go test./apps/client/cmd/calabi/ -run TestServiceInstallEnv_Standalone -v
package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// A standalone client installing a PLATFORM service (no --config) is a
// contradiction: refuse it, rather than register something that defects to the
// platform on its first boot.
func TestServiceInstallEnv_StandaloneWithoutConfigRefuses(t *testing.T) {
	stubKeyVerify(t)
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	t.Setenv("CALABI_MODE", "standalone")
	t.Setenv("CALABI_API_KEY", "tk_whatever")

	env, err := serviceInstallEnv([]string{"--api-key", "tk_flag"})
	if err == nil {
		t.Fatalf("standalone install without --config was accepted (env=%v) — "+
			"the installed service would resolve to platform mode and dial the control plane", env)
	}
	// The message has to name a way out, or the user is stuck with a refusal.
	for _, want := range []string{"--config", "calabi mode platform"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q:\n%s", want, err)
		}
	}
}

// The local supervisor is the standalone answer, and it authenticates from its
// YAML — so --config must still short-circuit before any of this.
func TestServiceInstallEnv_StandaloneWithConfigIsFine(t *testing.T) {
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	t.Setenv("CALABI_MODE", "standalone")

	env, err := serviceInstallEnv([]string{"--config", "tunnels.yaml"})
	if err != nil {
		t.Fatalf("standalone install WITH --config should be the supported path: %v", err)
	}
	if env != nil {
		t.Fatalf("expected nil env for a --config service, got %v", env)
	}
}

// The refusal must not catch a platform client — that is the ordinary install.
func TestServiceInstallEnv_PlatformModeUnaffected(t *testing.T) {
	stubKeyVerify(t)
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	t.Setenv("CALABI_MODE", "platform")

	env, err := serviceInstallEnv([]string{"--api-key", "tk_flag"})
	if err != nil {
		t.Fatalf("platform install refused: %v", err)
	}
	if env["CALABI_API_KEY"] != "tk_flag" {
		t.Fatalf("key not baked into the service env: %v", env)
	}
}

// An explicit CALABI_MODE=platform in the install shell is a third way out, and
// it has to work: clientIsStandalone reads the environment before creds, so a
// persisted standalone mode is overridable for this one command.
func TestServiceInstallEnv_EnvOverridesPersistedStandalone(t *testing.T) {
	stubKeyVerify(t)
	dir := t.TempDir()
	t.Setenv("CALABI_CONFIG", filepath.Join(dir, "creds.json"))
	t.Setenv("CALABI_MODE", "standalone")
	// Persist standalone the way `calabi mode standalone` does...
	if code := runMode([]string{"standalone"}); code != 0 {
		t.Fatalf("runMode standalone: exit %d", code)
	}
	// ...then override it for this install only.
	t.Setenv("CALABI_MODE", "platform")

	if _, err := serviceInstallEnv([]string{"--api-key", "tk_flag"}); err != nil {
		t.Fatalf("CALABI_MODE=platform should override the persisted standalone: %v", err)
	}
}
