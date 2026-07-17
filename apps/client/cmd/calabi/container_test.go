package main

import (
	"os"
	"testing"
)

// TestContainerizeDaemonArgs covers the container adaptation of the daemon
// service subcommands: in a container there's no OS service manager, so
// install/start/restart become a foreground daemon (with --api-key folded into
// CALABI_API_KEY) and stop/uninstall/status short-circuit.
func TestContainerizeDaemonArgs(t *testing.T) {
	t.Setenv("CALABI_IN_CONTAINER", "1")

	t.Run("install translates to foreground + sets api key", func(t *testing.T) {
		t.Setenv("CALABI_API_KEY", "")
		args, handled, code := containerizeDaemonArgs(
			[]string{"install", "--api-key=tk_secret", "--status-port", "7450", "--name", "edge-box"})
		if handled {
			t.Fatalf("install should fall through to the foreground daemon, got handled=true (code=%d)", code)
		}
		// Subcommand + install-only flags stripped; only foreground-valid flags kept.
		for _, a := range args {
			if a == "install" || a == "--api-key=tk_secret" || a == "--status-port" {
				t.Fatalf("foreground args still carry a service-only token: %q in %v", a, args)
			}
		}
		if got := os.Getenv("CALABI_API_KEY"); got != "tk_secret" {
			t.Fatalf("CALABI_API_KEY = %q, want tk_secret", got)
		}
		if got := os.Getenv("CALABI_STATUS_ADDR"); got != "127.0.0.1:7450" {
			t.Fatalf("CALABI_STATUS_ADDR = %q, want 127.0.0.1:7450", got)
		}
		// --name is foreground-valid → preserved.
		var sawName bool
		for i, a := range args {
			if a == "--name" && i+1 < len(args) && args[i+1] == "edge-box" {
				sawName = true
			}
		}
		if !sawName {
			t.Fatalf("expected --name edge-box to survive into foreground args, got %v", args)
		}
	})

	t.Run("stop short-circuits", func(t *testing.T) {
		_, handled, code := containerizeDaemonArgs([]string{"stop"})
		if !handled || code != 0 {
			t.Fatalf("stop in a container should be handled with code 0, got handled=%v code=%d", handled, code)
		}
	})
}

// TestContainerizeDaemonArgs_NotContainer verifies the helper is a pure
// passthrough when not in a container, so host installs are untouched.
func TestContainerizeDaemonArgs_NotContainer(t *testing.T) {
	t.Setenv("CALABI_IN_CONTAINER", "0")
	in := []string{"install", "--api-key=tk_x"}
	out, handled, _ := containerizeDaemonArgs(in)
	if handled {
		t.Fatalf("non-container should not handle; got handled=true")
	}
	if len(out) != len(in) || out[0] != "install" {
		t.Fatalf("non-container should pass args through unchanged, got %v", out)
	}
}
