package main

import "testing"

// resolveServiceName precedence: --service-name flag > CALABI_SERVICE_NAME env >
// "calabi" default. The env fallback is how an SCM-launched service (no args)
// recovers the name install baked in.
func TestResolveServiceName(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv("CALABI_SERVICE_NAME", "")
		if got := resolveServiceName(nil); got != "calabi" {
			t.Fatalf("default: got %q, want calabi", got)
		}
	})
	t.Run("env fallback", func(t *testing.T) {
		t.Setenv("CALABI_SERVICE_NAME", "calabi-client2")
		if got := resolveServiceName(nil); got != "calabi-client2" {
			t.Fatalf("env: got %q, want calabi-client2", got)
		}
	})
	t.Run("flag wins over env", func(t *testing.T) {
		t.Setenv("CALABI_SERVICE_NAME", "from-env")
		for _, args := range [][]string{
			{"--service-name", "calabi-client1"},
			{"--service-name=calabi-client1"},
			{"--api-key", "tk_x", "--service-name", "calabi-client1"},
		} {
			if got := resolveServiceName(args); got != "calabi-client1" {
				t.Fatalf("flag %v: got %q, want calabi-client1", args, got)
			}
		}
	})
}
