package testhome

// RUN: go test./apps/client/internal/testhome/

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// sandboxAt enters a sandbox at a fresh temp dir for this test only, restoring
// the package-wide one Main set up when the test ends.
func sandboxAt(t *testing.T) string {
	t.Helper()
	for name := range dirVars {
		t.Setenv(name, os.Getenv(name)) // registers the restore
	}
	for _, name := range clearedVars {
		t.Setenv(name, os.Getenv(name))
	}
	root := t.TempDir()
	if err := enter(root); err != nil {
		t.Fatalf("enter: %v", err)
	}
	return root
}

func under(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Every per-user location the client resolves has to land in the sandbox on the
// platform the tests run on — a variable missing from dirVars is a real
// directory the guard cannot see.
func TestSandboxCoversEveryPerUserPath(t *testing.T) {
	t.Setenv("CALABI_CONFIG", `C:\real\config.json`)
	t.Setenv("CALABI_LOCAL_TOKEN", "/real/local_token")
	root := sandboxAt(t)

	paths := map[string]func() (string, error){
		"creds.DataDir":        creds.DataDir,
		"creds.Path":           creds.Path,
		"creds.LocalTokenPath": creds.LocalTokenPath,
		"os.UserCacheDir":      os.UserCacheDir,
		"os.UserConfigDir":     os.UserConfigDir,
		"os.UserHomeDir":       os.UserHomeDir,
	}
	for name, resolve := range paths {
		p, err := resolve()
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !under(root, p) {
			t.Errorf("%s = %q, outside the sandbox %q", name, p, root)
		}
	}
}

// The guard has to see what a leaking test leaves behind — the local token a
// test mints without isolating itself, a staged cache file, a directory created
// and left empty — and nothing on a sandbox that was only set up.
func TestWrittenUnderReportsWhatALeakingTestLeaves(t *testing.T) {
	root := sandboxAt(t)

	if got, err := writtenUnder(root); err != nil || len(got) != 0 {
		t.Fatalf("fresh sandbox: writtenUnder = %v, %v; want nothing", got, err)
	}

	if _, err := creds.MintLocalToken(); err != nil {
		t.Fatalf("MintLocalToken: %v", err)
	}
	cache, _ := os.UserCacheDir()
	if err := os.MkdirAll(filepath.Join(cache, "calabi", "wintun"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "calabi", "wintun", "wintun.dll"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	if err := os.MkdirAll(filepath.Join(home, ".calabi-empty"), 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := writtenUnder(root)
	if err != nil {
		t.Fatalf("writtenUnder: %v", err)
	}
	for _, want := range []string{"calabi/local_token", "calabi/wintun/wintun.dll", ".calabi-empty"} {
		if !anyHasSuffix(got, want) {
			t.Errorf("writtenUnder = %v, missing …/%s", got, want)
		}
	}
}

func anyHasSuffix(list []string, suffix string) bool {
	for _, s := range list {
		if strings.HasSuffix(s, "/"+suffix) {
			return true
		}
	}
	return false
}

// A test package without the sandbox is unguarded, and nothing about a green
// run would say so. Discovered from the tree, not listed, so a new package is
// covered the day it gets its first test.
func TestEveryTestPackageRunsInTheSandbox(t *testing.T) {
	moduleRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	if err != nil {
		t.Fatalf("expected the client module at %s: %v", moduleRoot, err)
	}
	if first, _, _ := strings.Cut(string(b), "\n"); strings.TrimSpace(first) != "module github.com/calabi/calabi/apps/client" {
		t.Fatalf("expected the client module at %s, go.mod starts %q", moduleRoot, first)
	}

	checked := 0
	err = filepath.WalkDir(moduleRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if p != moduleRoot && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		tests, _ := filepath.Glob(filepath.Join(p, "*_test.go"))
		if len(tests) == 0 {
			return nil
		}
		checked++
		rel, _ := filepath.Rel(moduleRoot, p)
		// A fixed, untagged file: a TestMain behind a build tag or an OS suffix
		// guards only some platforms, and export-public.sh deletes repro_*_test.go.
		b, err := os.ReadFile(filepath.Join(p, "main_test.go"))
		if err != nil {
			t.Errorf("%s: has tests but no main_test.go running testhome.Main", filepath.ToSlash(rel))
			return nil
		}
		src := string(b)
		call := "testhome.Main(m)"
		if filepath.Base(p) == "testhome" {
			call = "Main(m)"
		}
		if !strings.Contains(src, "func TestMain(m *testing.M) { "+call+" }") {
			t.Errorf("%s/main_test.go: TestMain must be exactly `func TestMain(m *testing.M) { %s }`", filepath.ToSlash(rel), call)
		}
		if strings.Contains(src, "//go:build") {
			t.Errorf("%s/main_test.go: must not carry a build constraint", filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Fatalf("found only %d test packages under %s; the walk is not seeing the module", checked, moduleRoot)
	}
}
