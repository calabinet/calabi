package runtime

import (
	"path/filepath"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// The daemon pidfile lives in creds.DataDir(), so the service override
// (creds.SetDataDir → next to the exe) moves the lock there too — instead of the
// SYSTEM account's hard-to-find %LOCALAPPDATA%.
func TestPidPath_FollowsDataDirOverride(t *testing.T) {
	dir := t.TempDir()
	creds.SetDataDir(dir)
	t.Cleanup(func() { creds.SetDataDir("") })

	lock, err := AcquireDaemonLock()
	if err != nil {
		t.Fatalf("AcquireDaemonLock: %v", err)
	}
	defer lock.Release()

	if got := filepath.Dir(lock.Path()); got != dir {
		t.Errorf("pidfile dir = %q, want override %q (path %q)", got, dir, lock.Path())
	}
	if filepath.Base(lock.Path()) != "calabi.pid" {
		t.Errorf("pidfile name = %q, want calabi.pid", filepath.Base(lock.Path()))
	}
}
