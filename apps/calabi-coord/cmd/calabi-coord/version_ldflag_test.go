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
// coord had the identical bug the edge did (found 2026-09-05): its version lived
// as `serviceVersion = "0.0.0-mesh.1"` inside a const block, so the
// `-X main.version=${VERSION}` the Dockerfile passes could never apply — the
// linker only rewrites a package-level string VAR, and it ignores a name it
// cannot find WITHOUT warning. svcboot logs this value at startup and reports it
// on the admin surface, so every coord announced "0.0.0-mesh.1" regardless of
// what shipped.
//
// It runs the binary rather than searching its bytes: `go build` records the
// -ldflags string itself in the build info, so a byte search finds the probe
// whether or not the stamp took — an earlier version of this test passed with
// the bug deliberately reintroduced. See the longer note in
// apps/calabi-edge/cmd/calabi-edge/version_ldflag_test.go.
func TestVersionIsStampedByLdflags(t *testing.T) {
	const probe = "9.9.9-ldflag-probe"

	out := filepath.Join(t.TempDir(), "probe")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}

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
			"Check that main.go still declares `var version = \"dev\"` at package\n"+
			"level — not a const, not another name. The linker does not warn when\n"+
			"-X names a symbol that does not exist.",
			probe, strings.TrimSpace(string(got)))
	}
}
