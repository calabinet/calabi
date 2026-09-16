// Package runtime provides cross-process coordination primitives for the
// calabi client. Today there is exactly one: SingleInstanceLock,
// which prevents two `calabi daemon` processes from racing on the same
// machine.
//
// Why a hard lock instead of "just hope the user notices the second
// terminal output looking weird"?
//
//   - Both daemons would announce the same identity-svc clients.id to
//     the edge in their AUTH frame. Whichever one's heartbeat lands
//     last wins the presence flag — the other one's tunnels would
//     keep going but the console would show the wrong control stream.
//
//   - CONFIG_PUSH auto-claim would race: both daemons would try to
//     claim the same tunnel_id; one wins, the other logs an opaque
//     "already_claimed" and the user has no clue.
//
//   - The status page at :7400 binds the same port; the second daemon
//     gets a benign WARN but the user loses the ability to introspect.
//
// We use file locking via gofrs/flock because it Just Works across
// Windows / Linux / macOS — and crucially, if the holder dies (crash,
// kill -9), the OS releases the lock for the next process automatically.
// That removes the classic stale-pid-file footgun.
package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/gofrs/flock"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// SingleInstanceLock holds the lock that grants exclusive daemon rights.
// Callers MUST keep the returned value alive for the lifetime of the
// daemon; releasing it (or letting it be garbage-collected) frees the
// lock so a second instance can take over.
type SingleInstanceLock struct {
	fl   *flock.Flock
	path string
}

// AcquireDaemonLock attempts to lock <config-dir>/calabi.pid. Returns
// ErrAlreadyRunning (wrapped) if another process already holds it.
//
// On success the lock file is also rewritten with the current pid +
// timestamp for human inspection (`type %LOCALAPPDATA%\calabi\calabi.pid`
// in Windows, etc.). The OS doesn't need the contents — the flock is
// the actual gate — but they're handy when an operator wants to know
// which pid stole the slot.
func AcquireDaemonLock() (*SingleInstanceLock, error) {
	p := pidPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}
	fl := flock.New(p)
	got, err := fl.TryLock()
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", p, err)
	}
	if !got {
		// Read current pid for the error message — best-effort, never
		// fatal. On Windows the file may be held exclusively while we
		// peek; treat the read failure as "unknown holder".
		holder := "unknown"
		if b, rerr := os.ReadFile(p); rerr == nil {
			if pid := firstLine(b); pid != "" {
				holder = pid
			}
		}
		return nil, fmt.Errorf("%w (held by pid %s)", ErrAlreadyRunning, holder)
	}
	// Record pid + meta for human inspection. NOT load-bearing — flock
	// is the lock, this is documentation.
	contents := fmt.Sprintf("%d\n%s\n%s\n", os.Getpid(), runtime.GOOS, runtime.GOARCH)
	_ = os.WriteFile(p, []byte(contents), 0o600)
	return &SingleInstanceLock{fl: fl, path: p}, nil
}

// Release frees the lock. Safe to call multiple times.
func (s *SingleInstanceLock) Release() {
	if s == nil || s.fl == nil {
		return
	}
	_ = s.fl.Unlock()
	// Best-effort cleanup. If the next daemon starts before this file
	// is gone it just re-takes the lock and rewrites — no harm.
	_ = os.Remove(s.path)
}

// Path returns the pid-file path (informational).
func (s *SingleInstanceLock) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// ErrAlreadyRunning is returned (wrapped) by AcquireDaemonLock when
// another process holds the lock. Use errors.Is to detect.
var ErrAlreadyRunning = errors.New("another calabi daemon is already running")

// pidPath is <data-dir>/calabi.pid — the same data dir as creds + local-token,
// so the OS-service override (creds.SetDataDir → next to the exe) moves all
// three together. Falls back to TempDir only if the data dir can't be resolved.
func pidPath() string {
	if d, err := creds.DataDir(); err == nil {
		return filepath.Join(d, "calabi.pid")
	}
	return filepath.Join(os.TempDir(), "calabi.pid")
}

// ReadDaemonPID returns the pid recorded in the lock file WITHOUT taking the
// lock — a best-effort "who's running" read used to stop a transient daemon
// before the OS service takes over. Returns false if the file is absent or
// doesn't begin with a pid.
func ReadDaemonPID() (int, bool) {
	b, err := os.ReadFile(pidPath())
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(firstLine(b))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

func firstLine(b []byte) string {
	for i, c := range b {
		if c == '\n' || c == '\r' {
			return string(b[:i])
		}
	}
	// No newline? Return as-is if it parses as an int (so we don't
	// echo a megabyte of garbage in the error message).
	if _, err := strconv.Atoi(string(b)); err == nil {
		return string(b)
	}
	if len(b) > 32 {
		return string(b[:32])
	}
	return string(b)
}

// DaemonRunning reports whether a daemon is already running FOR THIS DATA DIR.
//
// It is deliberately not "is anything listening on :7400". One machine can run
// several clients — that is a supported setup (separate CALABI_CONFIG / data
// dir, and the status console rolls to the next free port on a conflict) — so
// the port tells you only that SOMEBODY is there, and acting on it means a
// second client's `calabi login` decides your daemon is up when the daemon it
// found belongs to another account entirely.
//
// The lock is the honest signal because it is scoped exactly the way client
// instances are: one flock per data dir, the same dir that holds this instance's
// creds. Taking it momentarily and giving it straight back is safe — nothing
// else can slip in during the caller's own next statement, and a real daemon
// start takes it for its whole lifetime.
//
// A missing lock file means no daemon has ever run here: answer false WITHOUT
// creating one, so merely asking the question does not litter a fresh data dir.
// An unreadable/unlockable file also answers false — the caller then tries to
// start a daemon, and AcquireDaemonLock refuses loudly if one really was there.
func DaemonRunning() bool {
	p := pidPath()
	if _, err := os.Stat(p); err != nil {
		return false
	}
	fl := flock.New(p)
	got, err := fl.TryLock()
	if err != nil {
		return false
	}
	if !got {
		return true
	}
	_ = fl.Unlock()
	return false
}
