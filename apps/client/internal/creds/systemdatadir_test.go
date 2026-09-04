package creds

import (
	"path/filepath"
	"testing"
)

// SystemDataDir feeds a privileged system service's data location. It must be a non-empty
// absolute path on every platform so SetDataDir(SystemDataDir()) is well-defined.
func TestSystemDataDir(t *testing.T) {
	d := SystemDataDir()
	if d == "" {
		t.Fatal("SystemDataDir() is empty")
	}
	if !filepath.IsAbs(d) {
		t.Errorf("SystemDataDir() = %q, want an absolute path", d)
	}
}
