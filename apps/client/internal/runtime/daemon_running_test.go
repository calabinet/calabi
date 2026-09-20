// daemon_running_test.go — "is MY daemon up", per data dir.
//
// The question used to be answered by probing :7400, which is a question about
// the PORT. One machine can run several clients (separate data dirs; the console
// rolls to the next free port), so the probe answered for whichever instance got
// there first — a second client's `calabi login` saw someone else's daemon,
// announced success, and never started the one the user wanted.
//
// RUN: go test./apps/client/internal/runtime/ -run TestDaemonRunning -v
package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

func isolatedDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	creds.SetDataDir(dir)
	t.Cleanup(func() { creds.SetDataDir("") })
	return dir
}

func TestDaemonRunningTrueWhileTheLockIsHeld(t *testing.T) {
	isolatedDataDir(t)
	lock, err := AcquireDaemonLock()
	if err != nil {
		t.Fatalf("AcquireDaemonLock: %v", err)
	}
	if !DaemonRunning() {
		t.Fatal("DaemonRunning() = false while the lock is held — login would " +
			"spawn a second daemon that the lock then refuses")
	}
	lock.Release()
	if DaemonRunning() {
		t.Fatal("DaemonRunning() = true after Release — login would refuse to " +
			"start a daemon that is not there")
	}
}

// Asking must not create state. A fresh data dir has no pidfile, and leaving one
// behind would make the NEXT question (and anything else reading the dir) see a
// daemon that never existed.
func TestDaemonRunningOnAFreshDataDirAnswersFalseAndLeavesNoFile(t *testing.T) {
	dir := isolatedDataDir(t)
	if DaemonRunning() {
		t.Fatal("DaemonRunning() = true on a data dir no daemon has ever used")
	}
	if _, err := os.Stat(filepath.Join(dir, "calabi.pid")); err == nil {
		t.Fatal("asking the question created calabi.pid")
	}
}

// THE MULTI-CLIENT CASE, which is the whole reason this is not a port probe:
// instance A holds its own lock, and instance B — a different data dir on the
// same machine — must still be told it has no daemon.
func TestDaemonRunningIsScopedPerDataDirNotPerMachine(t *testing.T) {
	isolatedDataDir(t)
	lockA, err := AcquireDaemonLock()
	if err != nil {
		t.Fatalf("AcquireDaemonLock: %v", err)
	}
	defer lockA.Release()

	// Same machine, second client: its own config dir, its own lock, its own
	// console port.
	creds.SetDataDir(t.TempDir())
	if DaemonRunning() {
		t.Fatal("DaemonRunning() = true for a data dir whose daemon is not running, " +
			"because ANOTHER instance on this machine has one. That is the bug: " +
			"the second client's login would skip starting its daemon.")
	}
}
