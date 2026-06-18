package main

import (
	"path/filepath"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// TestDefaultClientModeMatchesEdition pins the per-edition default: the platform
// build defaults to "platform", the community build to "standalone". Compiled
// under both build tags (no tag on this file), so it checks whichever edition is
// being built.
func TestDefaultClientModeMatchesEdition(t *testing.T) {
	switch edition {
	case "community":
		if defaultClientMode != clientModeStandalone {
			t.Fatalf("community edition: defaultClientMode = %q, want %q", defaultClientMode, clientModeStandalone)
		}
	case "platform":
		if defaultClientMode != clientModePlatform {
			t.Fatalf("platform edition: defaultClientMode = %q, want %q", defaultClientMode, clientModePlatform)
		}
	default:
		t.Fatalf("unexpected edition %q", edition)
	}
}

// TestResolveClientMode_FallsToEditionDefault: with no CALABI_MODE and no
// persisted mode, resolveClientMode returns the edition default. This is what
// makes a community binary standalone out of the box (no --local / --standalone).
func TestResolveClientMode_FallsToEditionDefault(t *testing.T) {
	t.Setenv("CALABI_MODE", "")
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json")) // no file yet
	if got := resolveClientMode(); got != defaultClientMode {
		t.Fatalf("resolveClientMode() = %q, want edition default %q", got, defaultClientMode)
	}
}

// TestResolveClientMode_PersistedPlatformOverrides: an explicit persisted
// "platform" still wins over the edition default (the precedence change must not
// break the override path — relevant for a community user who deliberately ran
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
