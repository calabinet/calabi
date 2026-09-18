package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// launchWaiting is an Apply that "starts" an installer which exits, with exit,
// only when the returned channel is closed.
func launchWaiting(exit error) (func(context.Context, string) (func() error, error), chan struct{}) {
	exited := make(chan struct{})
	return func(context.Context, string) (func() error, error) {
		return func() error { <-exited; return exit }, nil
	}, exited
}

func waitForState(t *testing.T, a *Agent, want string) Snapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		snap := a.Snapshot()
		if snap.State == want {
			return snap
		}
		if time.Now().After(deadline) {
			t.Fatalf("State = %q after 3s, want %q", snap.State, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// An installer whose process ends while this daemon is still alive did not
// update it, whatever its exit code: every installer stops this service before
// swapping anything in. The first macOS self-update failed writing the app,
// exited, and the console said "updating" until the service was restarted by
// hand, because nothing ever looked at the installer again.
func TestAnInstallerThatExitsUnderUsIsAFailedUpdate(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit error
		want string
	}{
		{"it failed", errors.New("exit status 1: installer: The upgrade failed."), "The upgrade failed."},
		// A clean exit is no better: the new version is not what is running.
		{"it exited cleanly", nil, "without restarting this service"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apply, exited := launchWaiting(tc.exit)
			a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0"}, apply)
			defer done()

			if err := a.Apply(context.Background()); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if s := a.Snapshot().State; s != StateUpdating {
				t.Fatalf("State while the installer runs = %q, want %q", s, StateUpdating)
			}

			close(exited)
			snap := waitForState(t, a, StateFailed)
			if !strings.Contains(snap.Error, tc.want) {
				t.Errorf("Error = %q, want it to contain %q", snap.Error, tc.want)
			}
			// And the agent is not wedged: the next check runs.
			if _, err := a.Check(context.Background()); err != nil {
				t.Fatalf("Check after the installer exited: %v", err)
			}
		})
	}
}

// While an installer runs, nothing else may start: a check would flip the state
// off "updating", and the periodic tick could start a second installer on top of
// the first.
func TestNothingStartsWhileAnInstallerRuns(t *testing.T) {
	apply, exited := launchWaiting(errors.New("exit status 1"))
	defer close(exited)
	var launches int
	counting := func(ctx context.Context, p string) (func() error, error) {
		launches++
		return apply(ctx, p)
	}
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", critical: true,
		policy: Policy{Mode: ModeAuto, MaxDeferDays: 7}}, counting)
	defer done()

	if launched, _ := a.tick(context.Background(), time.Hour); !launched {
		t.Fatal("the first tick did not launch the installer")
	}
	if _, err := a.Check(context.Background()); !errors.Is(err, ErrBusy) {
		t.Errorf("Check while the installer runs = %v, want ErrBusy", err)
	}
	if err := a.Apply(context.Background()); !errors.Is(err, ErrBusy) {
		t.Errorf("Apply while the installer runs = %v, want ErrBusy", err)
	}
	// Due again (checkEvery 0): the tick must still not launch a second one.
	a.tick(context.Background(), 0)
	if launches != 1 {
		t.Errorf("installer launched %d times, want 1", launches)
	}
	if s := a.Snapshot().State; s != StateUpdating {
		t.Errorf("State = %q, want %q", s, StateUpdating)
	}
}

// The tick path is watched too, not only the button.
func TestTheTickWatchesTheInstallerItLaunched(t *testing.T) {
	apply, exited := launchWaiting(errors.New("exit status 2"))
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", critical: true,
		policy: Policy{Mode: ModeAuto, MaxDeferDays: 7}}, apply)
	defer done()

	if launched, _ := a.tick(context.Background(), time.Hour); !launched {
		t.Fatal("the tick did not launch the installer")
	}
	close(exited)
	if snap := waitForState(t, a, StateFailed); !strings.Contains(snap.Error, "exit status 2") {
		t.Errorf("Error = %q, want the exit status in it", snap.Error)
	}
}

func TestLastLineIsTheLineThatSaysWhatFailed(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "out.log")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	out := "installer: Package name is Calabi\r\ninstaller: Upgrading at base path /\ninstaller: The upgrade failed. (An error occurred.)\n\n"
	if got := lastLine(write(out)); got != "installer: The upgrade failed. (An error occurred.)" {
		t.Errorf("lastLine = %q", got)
	}
	if got := lastLine(write("")); got != "" {
		t.Errorf("lastLine of an empty file = %q, want empty", got)
	}
	if got := lastLine(filepath.Join(dir, "missing")); got != "" {
		t.Errorf("lastLine of a missing file = %q, want empty", got)
	}
	if got := []rune(lastLine(write(strings.Repeat("界", 1000)))); len(got) != maxLastLine+1 {
		t.Errorf("a long line is %d runes, want capped at %d plus the ellipsis", len(got), maxLastLine)
	}
}
