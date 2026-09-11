package main

import (
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

func isolateConsoleSecret(t *testing.T) {
	t.Helper()
	creds.SetDataDir(t.TempDir())
	t.Cleanup(func() { creds.SetDataDir("") })
}

// An operator's own choice wins over anything generated.
func TestConsoleSecret_EnvWins(t *testing.T) {
	isolateConsoleSecret(t)
	t.Setenv("CALABI_STATUS_SECRET", "  chosen-by-the-operator \n")
	secret, source, _, err := resolveConsoleSecret()
	if err != nil {
		t.Fatal(err)
	}
	if secret != "chosen-by-the-operator" || source != "env" {
		t.Fatalf("got (%q, %q), want the trimmed env value", secret, source)
	}
}

// With nothing chosen, one secret is generated, saved, and then kept — a secret
// that rolled on every restart would lock out whoever just read it from the log.
func TestConsoleSecret_GeneratedOnceThenKept(t *testing.T) {
	isolateConsoleSecret(t)
	t.Setenv("CALABI_STATUS_SECRET", "")

	first, source, path, err := resolveConsoleSecret()
	if err != nil {
		t.Fatal(err)
	}
	if source != "generated" {
		t.Fatalf("first run source = %q, want generated", source)
	}
	if !regexp.MustCompile(`^[a-z2-7]{6}(-[a-z2-7]{6}){3}$`).MatchString(first) {
		t.Fatalf("generated secret %q is not four groups of six base32 characters", first)
	}
	b, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(b)) != first {
		t.Fatalf("saved file = %q (%v), want the secret", b, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Fatalf("secret file mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	again, source, path2, err := resolveConsoleSecret()
	if err != nil {
		t.Fatal(err)
	}
	if again != first || source != "file" || path2 != path {
		t.Fatalf("second run = (%q, %q), want the same secret read back from %s", again, source, path)
	}
}
