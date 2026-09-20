// Package testhome keeps the client's tests out of the developer's real
// per-user directories. Every test package's TestMain is Main.
//
// Where calabi keeps its per-user files is decided by the environment:
// creds.DataDir (config.json, local_token, calabi.pid) and the log file come
// from %LOCALAPPDATA% or $XDG_CONFIG_HOME/$HOME, the staged wintun.dll from
// os.UserCacheDir, mesh.key from os.UserConfigDir. A test that does not redirect
// the right one writes into the directory the developer's own daemon uses — and
// local_token is the credential a running user-level daemon checks :7400 writes
// against, so minting one there locks that console out.
//
// It happened: five statusapi tests set CALABI_CONFIG and minted a local token.
// CALABI_CONFIG names the config FILE; the token resolves from the data dir and
// never looked at it. Each of those tests believed it was isolated, which is why
// the guard is not a helper a test has to remember to call. Main points all of
// those variables at an empty temp directory for the whole test binary and fails
// the package, naming the files, if anything lands there.
package testhome

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// dirVars maps each variable a per-user directory resolves from to its place
// in the sandbox.
var dirVars = map[string]string{
	"LOCALAPPDATA":    "localappdata", // Windows: creds.DataDir, logs, os.UserCacheDir
	"APPDATA":         "appdata",      // Windows: os.UserConfigDir
	"USERPROFILE":     "home",         // Windows: os.UserHomeDir
	"HOME":            "home",         // Unix: ~/.config, ~/.cache, ~/Library
	"XDG_CONFIG_HOME": "xdg-config",   // Linux: creds.DataDir, os.UserConfigDir
	"XDG_CACHE_HOME":  "xdg-cache",    // Linux: os.UserCacheDir
}

// clearedVars override the data dir or a data file outright. Inherited from the
// shell that runs `go test`, they would aim every test that does not set them
// itself at a real file, sandbox or not.
var clearedVars = []string{"CALABI_CONFIG", "CALABI_LOCAL_TOKEN", "CALABI_SYSTEM_SERVICE"}

// Main runs the package's tests inside a sandboxed home and exits. Use it as the
// whole of TestMain:
//
//	func TestMain(m *testing.M) { testhome.Main(m) }
func Main(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	root, err := os.MkdirTemp("", "calabi-testhome-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "testhome: create sandbox: %v\n", err)
		return 1
	}
	defer os.RemoveAll(root)
	if err := enter(root); err != nil {
		fmt.Fprintf(os.Stderr, "testhome: %v\n", err)
		return 1
	}

	code := m.Run()

	written, err := writtenUnder(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "testhome: inspect sandbox: %v\n", err)
		return 1
	}
	if len(written) > 0 {
		fmt.Fprintln(os.Stderr, "testhome: tests wrote into the per-user directories. Outside the sandbox these are the developer's real ones (%LOCALAPPDATA%\\calabi, ~/.config/calabi, ...):")
		for _, p := range written {
			fmt.Fprintf(os.Stderr, "\t%s\n", p)
		}
		fmt.Fprintln(os.Stderr, "testhome: give the test its own directory: creds.SetDataDir(t.TempDir()), or CALABI_CONFIG together with CALABI_LOCAL_TOKEN (CALABI_CONFIG alone moves only config.json); for os.UserCacheDir/UserConfigDir, t.Setenv the variable it reads.")
		if code == 0 {
			code = 1
		}
	}
	return code
}

// enter creates the sandbox directories under root and points the process
// environment at them.
func enter(root string) error {
	for name, sub := range dirVars {
		dir := filepath.Join(root, sub)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := os.Setenv(name, dir); err != nil {
			return fmt.Errorf("set %s: %w", name, err)
		}
	}
	for _, name := range clearedVars {
		if err := os.Unsetenv(name); err != nil {
			return fmt.Errorf("unset %s: %w", name, err)
		}
	}
	return nil
}

// writtenUnder lists, relative to root, every file and every empty directory
// below the sandbox directories enter created. Those directories themselves are
// not reported; an empty one is how the sandbox starts.
func writtenUnder(root string) ([]string, error) {
	created := map[string]bool{}
	for _, sub := range dirVars {
		created[sub] = true
	}
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." || created[rel] {
			return nil
		}
		if d.IsDir() {
			entries, err := os.ReadDir(p)
			if err != nil {
				return err
			}
			if len(entries) > 0 {
				return nil
			}
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out, err
}
