package selfupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// manifestServer serves a signed manifest for THIS platform, optionally marked
// critical. Separate from testServer because the critical flag is what the whole
// policy tier rests on and the tests need to flip it.
func manifestServer(t *testing.T, version string, priv ed25519.PrivateKey, critical bool, minSupported string) *httptest.Server {
	t.Helper()
	installer := []byte("fake calabi installer payload")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, installer))
	sum := sha256Hex(installer)
	crit := ""
	if critical {
		crit = `"critical":true,`
	}
	if minSupported != "" {
		crit += fmt.Sprintf(`"min_supported":%q,`, minSupported)
	}
	var body []byte
	build := func(host string) []byte {
		if len(body) == 0 {
			body = []byte(fmt.Sprintf(`{"version":%q,%s"platforms":{%q:{"url":%q,"sha256":%q,"signature":%q}}}`,
				version, crit, PlatformKey(), "http://"+host+"/installer", sum, sig))
		}
		return body
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/installer", func(w http.ResponseWriter, _ *http.Request) { w.Write(installer) })
	mux.HandleFunc("/latest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(build(r.Host)) })
	mux.HandleFunc("/latest.json.sig", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, build(r.Host))))
	})
	return httptest.NewServer(mux)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type agentOpts struct {
	current, latest string
	critical        bool
	minSupported    string
	policy          Policy
	unprivileged    bool
	busy            bool
	// at pins the agent's clock. Zero = a time inside the default 03:00–05:00
	// window, so a test that does not care about the window is not silently
	// gated by whatever hour it happens to run at. That bit matters: this suite
	// would otherwise pass or fail depending on the time of day.
	at time.Time
}

func newAgent(t *testing.T, o agentOpts, apply func(context.Context, string) error) (*Agent, func()) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := manifestServer(t, o.latest, priv, o.critical, o.minSupported)
	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: o.current,
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
		Privileged:     !o.unprivileged,
		Managed:        managedForTest,
		Apply:          apply,
		Logf:           func(f string, a ...any) { t.Logf(f, a...) },
	}
	if o.policy.Mode == "" {
		o.policy = DefaultPolicy()
	}
	if err := SavePolicy(u.DownloadDir, o.policy); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	a := NewAgent(u, func() bool { return o.busy })
	at := o.at
	if at.IsZero() {
		at = time.Date(2026, 9, 15, 4, 0, 0, 0, time.Local) // inside 03:00–05:00
	}
	a.now = func() time.Time { return at }
	return a, srv.Close
}

func mustNotApply(t *testing.T) func(context.Context, string) error {
	t.Helper()
	return func(context.Context, string) error {
		t.Error("an installer was launched when it must not have been")
		return nil
	}
}

// ---- the three modes -------------------------------------------------------

// "Tell me, don't touch it." Reported, never installed.
func TestModeNotifyHoldsARoutineUpdate(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0",
		policy: Policy{Mode: ModeNotify, MaxDeferDays: 7}}, mustNotApply(t))
	defer done()

	launched, held := a.tick(context.Background(), time.Hour)
	if launched || !held {
		t.Fatalf("tick=(launched %v, held %v), want (false, true)", launched, held)
	}
	snap := a.Snapshot()
	if !snap.Available || snap.Latest != "1.11.0" {
		t.Errorf("want 1.11.0 reported, got available=%v latest=%q", snap.Available, snap.Latest)
	}
	if !snap.CanApply {
		t.Errorf("CanApply describes CAPABILITY, not policy — it must stay true; reason=%q", snap.Reason)
	}
	if snap.Hold != HoldNotifyOnly {
		t.Errorf("Hold = %q, want %q", snap.Hold, HoldNotifyOnly)
	}
}

// "Security only" installs a critical release but not a routine one. Flip
// `critical` in the manifest and the same policy behaves the opposite way —
// that difference IS the mode.
func TestModeSecurityInstallsOnlyCriticalReleases(t *testing.T) {
	routine, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0",
		policy: Policy{Mode: ModeSecurity, MaxDeferDays: 7}}, mustNotApply(t))
	defer done()
	if launched, _ := routine.tick(context.Background(), time.Hour); launched {
		t.Fatal("a routine update installed under security-only")
	}
	if h := routine.Snapshot().Hold; h != HoldSecurityOnly {
		t.Errorf("Hold = %q, want %q", h, HoldSecurityOnly)
	}

	var applied bool
	crit, done2 := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", critical: true,
		policy: Policy{Mode: ModeSecurity, MaxDeferDays: 7}},
		func(context.Context, string) error { applied = true; return nil })
	defer done2()
	if launched, _ := crit.tick(context.Background(), time.Hour); !launched || !applied {
		t.Fatalf("a critical release did not install under security-only (launched=%v applied=%v)", launched, applied)
	}
	if !crit.Snapshot().Critical {
		t.Error("the manifest's critical flag did not reach the snapshot")
	}
}

// The line that keeps "notify" honest: critical overrides the WINDOW and the
// security-only mode, but NOT someone who said "never without me". The floor
// that overrides even this is min_supported (U3).
func TestModeNotifyIsNotOverriddenByCritical(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", critical: true,
		policy: Policy{Mode: ModeNotify, MaxDeferDays: 7}}, mustNotApply(t))
	defer done()

	if launched, _ := a.tick(context.Background(), time.Hour); launched {
		t.Fatal("a critical release installed against an explicit notify-only setting")
	}
	if h := a.Snapshot().Hold; h != HoldNotifyOnly {
		t.Errorf("Hold = %q, want %q", h, HoldNotifyOnly)
	}
}

// The floor overrides EVERYTHING, including an explicit "never without me". It
// is the only tier that does — reach for it when leaving a machine where it is
// has become worse than restarting it unasked.
func TestBelowMinSupportedInstallsEvenUnderNotifyOnly(t *testing.T) {
	noon := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	var applied bool
	a, done := newAgent(t, agentOpts{current: "1.9.0", latest: "1.11.0", minSupported: "1.10.0",
		at: noon, busy: true,
		policy: Policy{Mode: ModeNotify, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 7}},
		func(context.Context, string) error { applied = true; return nil })
	defer done()

	if launched, _ := a.tick(context.Background(), time.Hour); !launched || !applied {
		t.Fatalf("an unsupported version was left running (launched=%v applied=%v)", launched, applied)
	}
	if !a.Snapshot().Mandatory {
		t.Error("the snapshot does not say the update was mandatory; the console cannot explain the restart")
	}
}

// ...and a client at or above the floor is NOT mandatory, or every release would
// forcibly restart every machine regardless of what its owner asked for.
func TestAtOrAboveMinSupportedIsNotMandatory(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", minSupported: "1.10.0",
		policy: Policy{Mode: ModeNotify, MaxDeferDays: 7}}, mustNotApply(t))
	defer done()

	if launched, _ := a.tick(context.Background(), time.Hour); launched {
		t.Fatal("a supported version was force-updated")
	}
	snap := a.Snapshot()
	if snap.Mandatory {
		t.Error("Mandatory set for a client that meets the floor")
	}
	if snap.Hold != HoldNotifyOnly {
		t.Errorf("Hold = %q, want %q", snap.Hold, HoldNotifyOnly)
	}
}

// A floor NEWER than the release it ships with demands a version nobody
// published. That is a malformed manifest, not a licence to force an install
// that can never satisfy it.
func TestMinSupportedNewerThanTheReleaseIsRefused(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.9.0", latest: "1.11.0", minSupported: "1.12.0",
		policy: Policy{Mode: ModeAuto, MaxDeferDays: 0}}, mustNotApply(t))
	defer done()

	if _, err := a.Check(context.Background()); err == nil {
		t.Fatal("a manifest demanding an unpublished version was accepted")
	}
}

// ---- the waiting rules -----------------------------------------------------

// A window keeps a ROUTINE restart out of the working day. Making a
// remotely-exploitable fix sit until 3am would be using it for something it was
// not for — so critical skips the window and the busy check both.
func TestCriticalIgnoresTheWindowAndBusy(t *testing.T) {
	noon := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	var applied bool
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", critical: true,
		at: noon, busy: true,
		policy: Policy{Mode: ModeAuto, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 7}},
		func(context.Context, string) error { applied = true; return nil })
	defer done()

	if launched, _ := a.tick(context.Background(), time.Hour); !launched || !applied {
		t.Fatalf("a critical release waited for the window (launched=%v applied=%v)", launched, applied)
	}
	if h := a.Snapshot().Hold; h != "" {
		t.Errorf("Hold = %q, want none", h)
	}
}

func TestAutoHoldsOutsideTheMaintenanceWindow(t *testing.T) {
	noon := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", at: noon,
		policy: Policy{Mode: ModeAuto, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 7}},
		mustNotApply(t))
	defer done()

	launched, held := a.tick(context.Background(), time.Hour)
	if launched || !held {
		t.Fatalf("tick=(%v,%v), want (false, true)", launched, held)
	}
	snap := a.Snapshot()
	if snap.Hold != HoldOutsideWindow {
		t.Fatalf("Hold = %q, want %q", snap.Hold, HoldOutsideWindow)
	}
	// The console has to be able to say when the wait ends, not just that it is
	// waiting.
	want := noon.Add(7 * 24 * time.Hour)
	if snap.HoldUntil == nil || !snap.HoldUntil.Equal(want) {
		t.Errorf("HoldUntil = %v, want %v", snap.HoldUntil, want)
	}
	// And the clock must survive a restart, or a daily reboot resets the
	// deadline forever.
	if _, err := os.Stat(filepath.Join(a.u.DownloadDir, deferStateFile)); err != nil {
		t.Errorf("defer state not persisted: %v", err)
	}
}

// A window is a preference, not a gate. A laptop closed every night and a server
// busy every night are the two machines that most need the fix; without the
// backstop they would be the two that never get it.
func TestBackstopInstallsEvenOutsideTheWindow(t *testing.T) {
	noon := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	var applied bool
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", at: noon,
		policy: Policy{Mode: ModeAuto, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 7}},
		func(context.Context, string) error { applied = true; return nil })
	defer done()

	// It has already been waiting eight days.
	noteDeferred(a.u.DownloadDir, "1.11.0", noon.Add(-8*24*time.Hour))

	if launched, _ := a.tick(context.Background(), time.Hour); !launched || !applied {
		t.Fatalf("the backstop did not fire (launched=%v applied=%v)", launched, applied)
	}
}

func TestAutoHoldsWhileTrafficIsMoving(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", busy: true,
		policy: Policy{Mode: ModeAuto, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 7}},
		mustNotApply(t))
	defer done()

	if launched, _ := a.tick(context.Background(), time.Hour); launched {
		t.Fatal("restarted the daemon while traffic was moving")
	}
	if h := a.Snapshot().Hold; h != HoldBusy {
		t.Errorf("Hold = %q, want %q", h, HoldBusy)
	}
}

// MaxDeferDays=0 means "don't wait for anything" — a legitimate setting, and the
// one that reproduces the pre-U2 behaviour exactly.
func TestZeroDeferDaysIgnoresWindowAndBusy(t *testing.T) {
	noon := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	var applied bool
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", at: noon, busy: true,
		policy: Policy{Mode: ModeAuto, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 0}},
		func(context.Context, string) error { applied = true; return nil })
	defer done()

	if launched, _ := a.tick(context.Background(), time.Hour); !launched || !applied {
		t.Fatalf("launched=%v applied=%v, want both true", launched, applied)
	}
}

// A box that is out of date and cannot fix itself must SAY SO IN THE LOG. It is
// the steady state of every Linux and agent install (the manifest publishes no
// artifact for them) and they are precisely the machines with no console open.
// U1 logged it from CheckAndApply; U2 stopped routing that case through
// CheckAndApply and the line went silent with it.
func TestTickLogsThatItCannotApply(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := foreignPlatformServer(t, "1.11.0", priv)
	defer srv.Close()

	var lines []string
	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.10.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
		Privileged:     true,
		Managed:        managedForTest,
		Apply:          func(context.Context, string) error { t.Fatal("apply must not run"); return nil },
		Logf:           func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) },
	}
	a := NewAgent(u, nil)

	if launched, _ := a.tick(context.Background(), time.Hour); launched {
		t.Fatal("unexpected launch")
	}
	var said bool
	for _, l := range lines {
		if strings.Contains(l, "1.11.0") && strings.Contains(l, ReasonNoArtifact) {
			said = true
		}
	}
	if !said {
		t.Errorf("nothing in the log names the available version and why it is stuck: %q", lines)
	}
}

// ---- policy changes and manual action --------------------------------------

// Saving a setting must not restart the machine. The new policy takes effect at
// the next evaluation (at most pendingEvalInterval away), not inside the PUT.
func TestSetPolicyReDecidesButNeverInstalls(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0",
		policy: Policy{Mode: ModeNotify, MaxDeferDays: 7}}, mustNotApply(t))
	defer done()

	a.tick(context.Background(), time.Hour)
	if h := a.Snapshot().Hold; h != HoldNotifyOnly {
		t.Fatalf("setup: Hold = %q", h)
	}
	snap, err := a.SetPolicy(Policy{Mode: ModeAuto, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 7})
	if err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if snap.Policy.Mode != ModeAuto {
		t.Errorf("policy not adopted: %+v", snap.Policy)
	}
	// The hold is gone (the new mode allows it) but nothing was installed.
	if snap.Hold != "" {
		t.Errorf("Hold = %q, want cleared after switching to auto", snap.Hold)
	}
	// And it persisted, so a restart keeps the choice.
	if got := LoadPolicy(a.u.DownloadDir); got.Mode != ModeAuto {
		t.Errorf("stored mode = %q, want %q", got.Mode, ModeAuto)
	}
}

// The button overrides the policy: a person pressing "update now" has already
// answered the question the policy exists to answer.
func TestManualApplyIgnoresThePolicy(t *testing.T) {
	noon := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	var applied bool
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", at: noon, busy: true,
		policy: Policy{Mode: ModeNotify, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 7}},
		func(context.Context, string) error { applied = true; return nil })
	defer done()

	if err := a.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !applied {
		t.Error("the manual button was refused by a policy it does not answer to")
	}
}

// ...but it does not override CanApply. That one is not a preference.
func TestManualApplyStillRefusesWhenItCannotInstall(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", unprivileged: true,
		policy: Policy{Mode: ModeAuto, MaxDeferDays: 7}}, mustNotApply(t))
	defer done()

	if err := a.Apply(context.Background()); !errors.Is(err, ErrCannotApply) {
		t.Fatalf("Apply err = %v, want ErrCannotApply", err)
	}
	if r := a.Snapshot().Reason; r != ReasonNotPrivileged {
		t.Errorf("Reason = %q, want %q", r, ReasonNotPrivileged)
	}
}

func TestAgentApplyOnCurrentVersionIsANoOp(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.11.0", latest: "1.11.0"}, mustNotApply(t))
	defer done()

	if err := a.Apply(context.Background()); err != nil {
		t.Fatalf("Apply on a current install: %v", err)
	}
	if snap := a.Snapshot(); snap.Available || snap.State != StateIdle {
		t.Errorf("available=%v state=%q, want (false, idle)", snap.Available, snap.State)
	}
}

// ---- bookkeeping -----------------------------------------------------------

// What Check RETURNS has to describe a finished check, not one in flight.
//
// The console's "检查更新" button binds its spinner to snapshot.state, so a
// returned state="checking" left it spinning until the next 60-second poll —
// a check that took 200ms looked like it hung. The CLI ignores the field, so
// only the browser showed it.
//
// The shape that caused it is easy to write again: `defer a.leave()` plus
// `return a.Snapshot(), err` reads correct, but Go evaluates the return
// expression BEFORE running defers.
func TestCheckReturnsAFinishedSnapshot(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0",
		policy: Policy{Mode: ModeNotify, MaxDeferDays: 7}}, mustNotApply(t))
	defer done()

	snap, err := a.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if snap.State == StateChecking {
		t.Error("Check returned state=checking — the console's spinner never stops on this")
	}
	if snap.State != StateIdle {
		t.Errorf("state = %q, want %q", snap.State, StateIdle)
	}
	// And the caller must not have to poll again to learn the result.
	if !snap.Available || snap.Latest != "1.11.0" {
		t.Errorf("the returned snapshot is missing the result: %+v", snap.Status)
	}
}

// A failed check reports failed, not checking — same reason.
func TestCheckReturnsFailedNotChecking(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0",
		policy: Policy{Mode: ModeNotify, MaxDeferDays: 7}}, mustNotApply(t))
	done() // the manifest host goes away

	snap, err := a.Check(context.Background())
	if err == nil {
		t.Fatal("expected the check to fail")
	}
	if snap.State != StateFailed {
		t.Errorf("state = %q, want %q", snap.State, StateFailed)
	}
}

// A transient network failure must not erase what the console is showing.
func TestAgentKeepsLastGoodStatusWhenACheckFails(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0",
		policy: Policy{Mode: ModeNotify, MaxDeferDays: 7}}, mustNotApply(t))
	a.tick(context.Background(), time.Hour)
	done() // the manifest host goes away

	a.tick(context.Background(), 0) // 0 = always due, so it refetches
	snap := a.Snapshot()
	if snap.Latest != "1.11.0" || !snap.Available {
		t.Errorf("a failed check erased the last good status: latest=%q available=%v", snap.Latest, snap.Available)
	}
	if snap.State != StateFailed || snap.Error == "" {
		t.Errorf("state=%q err=%q, want failed with a message", snap.State, snap.Error)
	}
}

// Only one operation at a time: the console's button and the periodic tick must
// not both be walking the download directory.
func TestAgentSerializesOperations(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0",
		policy: Policy{Mode: ModeNotify, MaxDeferDays: 7}}, mustNotApply(t))
	defer done()

	if err := a.enter(StateChecking); err != nil {
		t.Fatalf("first enter: %v", err)
	}
	if err := a.enter(StateChecking); !errors.Is(err, ErrBusy) {
		t.Fatalf("second enter = %v, want ErrBusy", err)
	}
	if _, err := a.Check(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("Check while held = %v, want ErrBusy", err)
	}
	a.leave()
	if _, err := a.Check(context.Background()); err != nil {
		t.Fatalf("Check after release: %v", err)
	}
}

// A held update must bring the loop back on the SHORT clock. With only the
// 6-hour fetch interval, ticks at 01:00/07:00/13:00/19:00 never land inside a
// 03:00–05:00 window and the update waits forever.
func TestHeldUpdateAsksForAShorterWait(t *testing.T) {
	noon := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", at: noon,
		policy: Policy{Mode: ModeAuto, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 7}},
		mustNotApply(t))
	defer done()

	if _, held := a.tick(context.Background(), time.Hour); !held {
		t.Fatal("a window-held update did not report itself as held")
	}
	// And an up-to-date machine does not, so the loop stays on the slow clock.
	b, done2 := newAgent(t, agentOpts{current: "1.11.0", latest: "1.11.0"}, mustNotApply(t))
	defer done2()
	if _, held := b.tick(context.Background(), time.Hour); held {
		t.Error("an up-to-date daemon asked to be polled on the fast clock")
	}
}

// "等你决定。 · 最迟 1/1/1" — what the update panel actually offered under
// "只提醒我".
//
// notify-only waits for a PERSON, so there is no deadline and HoldUntil stays
// zero. `omitempty` does nothing to a struct, so that zero time still went out
// as "0001-01-01T00:00:00Z"; `new Date(...)` is truthy, and the console dutifully
// rendered year 1. A hold with no deadline must not carry one on the wire —
// asserted on the JSON, because the wire is where the bug was.
func TestAnIndefiniteHoldSendsNoDeadline(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0",
		policy: Policy{Mode: ModeNotify, MaxDeferDays: 7}}, mustNotApply(t))
	defer done()

	if launched, _ := a.tick(context.Background(), time.Hour); launched {
		t.Fatal("notify-only installed something")
	}
	snap := a.Snapshot()
	if snap.Hold != HoldNotifyOnly {
		t.Fatalf("Hold = %q, want %q", snap.Hold, HoldNotifyOnly)
	}
	if snap.HoldUntil != nil {
		t.Errorf("HoldUntil = %v, want none — nothing is counting down", snap.HoldUntil)
	}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("hold_until")) {
		t.Errorf("an indefinite hold carried a deadline to the console: %s", b)
	}
}
