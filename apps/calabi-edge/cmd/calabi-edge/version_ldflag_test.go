package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestVersionIsStampedByLdflags builds this package with `-X main.version=<probe>`
// and asks the resulting binary what version it is.
//
// # WHY THIS TEST EXISTS
//
// Linker flags are invisible to an ordinary unit test: `version` is "dev" in the
// test binary no matter what any release passes. So a normal assertion could
// never have caught what was wrong here.
//
// Until 2026-09-05 this package declared `const edgeVersion = "0.1.0-m3-sprint5"`,
// which defeated the flag twice over: -X only rewrites a package-level string
// VAR (a const is compiled in, not linked), and the name did not match the flag
// anyway. `go build -X main.version=...` names a symbol that does not exist, and
// the linker accepts that SILENTLY. Every release therefore shipped an edge with
// no version in it at all, while reporting an-sprint-5 label to the control
// plane (wire_platform.go) and into its own metrics (observability.New).
//
// It survived a year of releases because nothing checked that the flag LANDED —
// only that it was passed.
//
// # WHY IT RUNS THE BINARY INSTEAD OF SEARCHING IT
//
// The first version of this test grepped the built bytes for the probe, and it
// PASSED with the bug deliberately reintroduced: `go build` records the
// -ldflags string itself in the binary's build info, so the probe is present
// either way. Executing -version is the only check that walks the same path an
// operator does.
//
// Deliberately not skipped under -short: a guard the fast path skips is the same
// shape of mistake all over again.
func TestVersionIsStampedByLdflags(t *testing.T) {
	const probe = "9.9.9-ldflag-probe"

	out := filepath.Join(t.TempDir(), "probe")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}

	// The same flag string the Dockerfile and scripts/package-release-edge.sh use.
	build := exec.Command("go", "build", "-ldflags", "-X main.version="+probe, "-o", out, ".")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, b)
	}

	got, err := exec.Command(out, "-version").Output()
	if err != nil {
		t.Fatalf("running -version failed: %v", err)
	}
	if strings.TrimSpace(string(got)) != probe {
		t.Fatalf("-X main.version=%s did not reach the binary: -version printed %q.\n"+
			"The linker only rewrites a package-level string VAR named exactly as the\n"+
			"flag says, and it does NOT warn when the symbol is missing. Check that\n"+
			"main.go still declares `var version = \"dev\"` — not a const, not another\n"+
			"name. A release built this way carries no version at all.",
			probe, strings.TrimSpace(string(got)))
	}
}
