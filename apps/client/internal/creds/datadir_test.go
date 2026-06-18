package creds

import (
	"path/filepath"
	"testing"
)

// SetDataDir redirects every data-file path (creds, local-token) to the
// override, and clearing it restores the per-user default. This is what pins a
// service's files next to its executable.
func TestDataDir_Override(t *testing.T) {
	t.Setenv("CALABI_CONFIG", "")     // Path falls through to DataDir
	t.Setenv("CALABI_LOCAL_TOKEN", "") // LocalTokenPath falls through to DataDir
	SetDataDir("")
	t.Cleanup(func() { SetDataDir("") })

	def, err := DataDir()
	if err != nil {
		t.Fatalf("DataDir default: %v", err)
	}

	dir := t.TempDir()
	SetDataDir(dir)

	if d, _ := DataDir(); d != dir {
		t.Fatalf("DataDir = %q, want override %q", d, dir)
	}
	if p, _ := Path(); p != filepath.Join(dir, "config.json") {
		t.Errorf("Path = %q, want %q", p, filepath.Join(dir, "config.json"))
	}
	if lt, _ := LocalTokenPath(); lt != filepath.Join(dir, localTokenFilename) {
		t.Errorf("LocalTokenPath = %q, want under override", lt)
	}

	SetDataDir("")
	if d, _ := DataDir(); d != def {
		t.Errorf("after clear DataDir = %q, want default %q", d, def)
	}
}
