package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func at(h int) time.Time { return time.Date(2026, 9, 15, h, 30, 0, 0, time.Local) }

func TestWindowWrapsMidnight(t *testing.T) {
	p := Policy{WindowStartHour: 23, WindowEndHour: 5}
	for _, h := range []int{23, 0, 3, 4} {
		if !p.InWindow(at(h)) {
			t.Errorf("%02d:30 should be inside 23:00–05:00", h)
		}
	}
	for _, h := range []int{5, 12, 22} {
		if p.InWindow(at(h)) {
			t.Errorf("%02d:30 should be outside 23:00–05:00", h)
		}
	}
}

func TestEqualHoursMeansNoWindow(t *testing.T) {
	p := Policy{WindowStartHour: 0, WindowEndHour: 0}
	for _, h := range []int{0, 7, 13, 23} {
		if !p.InWindow(at(h)) {
			t.Errorf("%02d:30 rejected by a policy that configures no window", h)
		}
	}
}

func TestValidateRejectsNonsense(t *testing.T) {
	for _, p := range []Policy{
		{Mode: "whatever"},
		{Mode: ModeAuto, WindowStartHour: 24},
		{Mode: ModeAuto, WindowEndHour: -1},
		{Mode: ModeAuto, MaxDeferDays: -1},
		{Mode: ModeAuto, MaxDeferDays: 91},
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("accepted %+v", p)
		}
	}
	if err := DefaultPolicy().Validate(); err != nil {
		t.Errorf("the default policy does not validate: %v", err)
	}
}

// Nothing installable is not a policy question — Decide must stay silent rather
// than inventing a hold reason for a Linux box that simply has no installer.
// Otherwise the console would show "waiting for the maintenance window" on a
// machine that will never install anything at any hour.
func TestDecideSaysNothingWhenThereIsNothingToInstall(t *testing.T) {
	p := DefaultPolicy()
	for _, st := range []Status{
		{Available: false, CanApply: false},
		{Available: true, CanApply: false, Reason: ReasonNoArtifact},
	} {
		d := p.Decide(st, at(12), true, time.Time{})
		if d.Install || d.Hold != "" {
			t.Errorf("Decide(%+v) = %+v, want the zero decision", st, d)
		}
	}
}

// A corrupt or truncated settings file must fall back to the default, not to
// "updates off". A bad write would otherwise become a permanent, silent opt-out
// that nothing in the UI explains.
func TestLoadPolicyFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	if got := LoadPolicy(dir); got != DefaultPolicy() {
		t.Errorf("missing file: got %+v, want the default", got)
	}
	if err := os.WriteFile(filepath.Join(dir, policyFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadPolicy(dir); got != DefaultPolicy() {
		t.Errorf("corrupt file: got %+v, want the default", got)
	}
	// A file that parses but says something impossible is the same case.
	if err := os.WriteFile(filepath.Join(dir, policyFile), []byte(`{"mode":"off"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadPolicy(dir); got != DefaultPolicy() {
		t.Errorf("invalid mode: got %+v, want the default", got)
	}
}

func TestSavePolicyRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := Policy{Mode: ModeSecurity, WindowStartHour: 23, WindowEndHour: 5, MaxDeferDays: 3}
	if err := SavePolicy(dir, want); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}
	if got := LoadPolicy(dir); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if err := SavePolicy(dir, Policy{Mode: "nope"}); err == nil {
		t.Error("SavePolicy stored an invalid policy")
	}
}

// The defer clock is per-version: a NEW release has not been waiting, it just
// arrived. Keying it only by "something is deferred" would let a version that
// sat for six days push its successor straight past the backstop on day one.
func TestDeferClockRestartsOnANewVersion(t *testing.T) {
	dir := t.TempDir()
	start := at(12)
	noteDeferred(dir, "1.11.0", start)
	if got := waitingSince(dir, "1.11.0"); !got.Equal(start) {
		t.Errorf("waitingSince = %v, want %v", got, start)
	}
	if got := waitingSince(dir, "1.12.0"); !got.IsZero() {
		t.Errorf("a different version inherited the clock: %v", got)
	}
	// Re-noting the same version must not restart its own clock.
	noteDeferred(dir, "1.11.0", start.Add(time.Hour))
	if got := waitingSince(dir, "1.11.0"); !got.Equal(start) {
		t.Errorf("clock restarted on re-note: %v, want %v", got, start)
	}
	clearDeferState(dir)
	if got := waitingSince(dir, "1.11.0"); !got.IsZero() {
		t.Errorf("clear left %v behind", got)
	}
}
