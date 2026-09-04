package main

import (
	"path/filepath"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// TestDefaultClientMode pins the single binary's default mode. There is no
// longer a build to vary it by (full-oss-plan F1): the binary can reach the
// managed control plane, so "platform" is what a fresh install gets, and a
// self-hoster opts out with `calabi mode standalone`.
func TestDefaultClientMode(t *testing.T) {
	if defaultClientMode != clientModePlatform {
		t.Fatalf("defaultClientMode = %q, want %q", defaultClientMode, clientModePlatform)
	}
}

// TestResolveClientMode_FallsToDefault: with no CALABI_MODE and no
// persisted mode, resolveClientMode returns the built-in default. This is what
// used to make the self-hosted binary standalone out of the box; the single
// binary now defaults to platform and a self-hoster opts out explicitly.
func TestResolveClientMode_FallsToDefault(t *testing.T) {
	t.Setenv("CALABI_MODE", "")
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json")) // no file yet
	if got := resolveClientMode(); got != defaultClientMode {
		t.Fatalf("resolveClientMode() = %q, want the built-in default %q", got, defaultClientMode)
	}
}

// TestResolveClientMode_PersistedPlatformOverrides: an explicit persisted
// "platform" still wins over the built-in default (the precedence change must not
// break the override path — relevant for a self-hoster who deliberately ran
// `calabi mode platform`).
func TestResolveClientMode_PersistedPlatformOverrides(t *testing.T) {
	t.Setenv("CALABI_MODE", "")
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	if err := creds.Save(&creds.Config{Mode: clientModePlatform}); err != nil {
		t.Fatalf("save creds: %v", err)
	}
	if got := resolveClientMode(); got != clientModePlatform {
		t.Fatalf("persisted platform: resolveClientMode() = %q, want %q", got, clientModePlatform)
	}
}
