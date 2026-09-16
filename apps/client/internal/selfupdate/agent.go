package selfupdate

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Agent is the long-lived half: it owns the periodic loop, remembers the last
// check, applies the machine's Policy to it, and serves the manual "check now" /
// "update now" the :7400 console drives. One per daemon process; nil when
// self-update is not configured.
//
// Three separate questions, deliberately three separate things:
//
//	Status.Available  is there something newer         — about the release
//	Status.CanApply   could this machine install it    — about the machine
//	Decision.Install  should it, right now             — about the policy
//
// Collapsing any two of them is how a daemon ends up either unable to say it is
// out of date, or restarting someone's server in the middle of the day.
type Agent struct {
	u *Updater
	// busy reports whether traffic is moving through this client right now. Nil
	// = never busy. Consulted only for routine updates under ModeAuto.
	busy func() bool

	mu     sync.Mutex
	snap   Snapshot
	policy Policy
	busyOp bool
	// launched latches once an installer has been handed off: the daemon is
	// about to be restarted underneath us, so the state must stop reading "idle".
	launched  bool
	lastCheck time.Time
	logf      func(string, ...any)
	now       func() time.Time
}

// Snapshot is what GET /v1/update renders: the last check's Status, the policy
// applied to it, and what this daemon is doing.
type Snapshot struct {
	Status
	// Policy is the machine's current setting, echoed so the console renders the
	// controls from the same response that carries the version.
	Policy Policy `json:"policy"`
	// Auto is a convenience for "would a ROUTINE update install itself here":
	// mode auto AND this machine can install. Critical releases install under
	// ModeSecurity too — read Policy.Mode for the full answer.
	Auto bool `json:"auto"`
	// Hold: why an installable update is not being installed right now —
	// notify-only | security-only | outside-window | busy. Empty when nothing is
	// waiting. Distinct from Status.Reason, which is why it CANNOT be installed
	// here at all.
	Hold string `json:"hold,omitempty"`
	// HoldUntil is when the MaxDeferDays backstop expires for the held version,
	// so the console can say "it will be installed by X" instead of describing
	// an open-ended wait. Absent when the hold has no deadline at all:
	// notify-only and security-only are waiting for a PERSON, not for a clock.
	//
	// A POINTER because `omitempty` does nothing to a struct. As a time.Time the
	// zero value went out on the wire as "0001-01-01T00:00:00Z", the console read
	// that as a real date, and the panel offered "等你决定。· 最迟 1/1/1".
	HoldUntil *time.Time `json:"hold_until,omitempty"`
	// Timezone is the abbreviation for the MACHINE's local zone (e.g. CST, CEST).
	// The maintenance window is on this clock, not the viewer's: the restart
	// happens here. A console opened from another country has to be able to say
	// whose 3am it means.
	Timezone string `json:"timezone,omitempty"`
	// State: idle | checking | updating | failed.
	State string `json:"state"`
	// Error is the last failure, flattened for the SPA. A check failure is
	// informational: the running install is untouched.
	Error string `json:"error,omitempty"`
}

// Agent states.
const (
	StateIdle     = "idle"
	StateChecking = "checking"
	StateUpdating = "updating"
	StateFailed   = "failed"
)

// pendingEvalInterval is how often the loop RE-EVALUATES a held update against
// the policy, without touching the network.
//
// It exists because the check interval (6h) and a maintenance window (2h) do not
// line up: ticks at 01:00/07:00/13:00/19:00 never once land inside 03:00–05:00,
// so a window-gated update would wait forever while the log cheerfully reported
// it every six hours. Only the FETCH is on the slow clock.
const pendingEvalInterval = 10 * time.Minute

// ErrCannotApply is returned when something asks a daemon to install an update
// it is not allowed or able to install. The caller (the REST handler) turns this
// into a 409 with Status.Reason, not a 500 — it is a fact about this machine,
// not a malfunction.
var ErrCannotApply = errors.New("selfupdate: this install cannot apply updates itself")

// ErrBusy is returned when a check or apply is already in flight. Also a 409:
// the caller should wait, not retry harder.
var ErrBusy = errors.New("selfupdate: another update operation is already running")

// ErrDisabled guards the nil agent. A *Agent(nil) stored in an interface is not
// == nil, so a caller that skipped the nil check reaches these methods with a
// nil receiver — an error beats a panic in the daemon's HTTP handler.
var ErrDisabled = errors.New("selfupdate: not configured on this daemon")

// NewAgent wraps an Updater and loads the machine's stored policy. busy may be
// nil (treated as never busy).
func NewAgent(u *Updater, busy func() bool) *Agent {
	p := LoadPolicy(u.DownloadDir)
	return &Agent{
		u:      u,
		busy:   busy,
		policy: p,
		logf:   u.logf,
		now:    time.Now,
		snap: Snapshot{
			Status: Status{Current: u.CurrentVersion},
			Policy: p,
			Auto:   p.Mode == ModeAuto && u.Privileged,
			State:  StateIdle,
		},
	}
}

// Snapshot returns the last known state. Never blocks on the network.
func (a *Agent) Snapshot() Snapshot {
	if a == nil {
		return Snapshot{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.snap
	// Read time, not construction time: DST moves the abbreviation.
	s.Timezone, _ = a.now().Zone()
	return s
}

// Policy returns the machine's current setting.
func (a *Agent) Policy() Policy {
	if a == nil {
		return DefaultPolicy()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.policy
}

// SetPolicy validates, persists and adopts a new setting, then re-decides the
// pending update against it — so switching to "automatic" while something is
// waiting takes effect at the next evaluation rather than at the next fetch.
//
// It never installs as a side effect of a settings save. A person changing a
// preference has not asked to be restarted this second; whatever the new policy
// allows lands within pendingEvalInterval.
func (a *Agent) SetPolicy(p Policy) (Snapshot, error) {
	if a == nil {
		return Snapshot{}, ErrDisabled
	}
	if err := p.Validate(); err != nil {
		return a.Snapshot(), err
	}
	if err := SavePolicy(a.u.DownloadDir, p); err != nil {
		return a.Snapshot(), err
	}
	a.mu.Lock()
	a.policy = p
	a.snap.Policy = p
	a.snap.Auto = p.Mode == ModeAuto && a.u.Privileged
	st := a.snap.Status
	a.mu.Unlock()

	a.evaluate(st, false)
	return a.Snapshot(), nil
}

// Check refreshes the status without installing anything, and returns it.
func (a *Agent) Check(ctx context.Context) (Snapshot, error) {
	if a == nil {
		return Snapshot{}, ErrDisabled
	}
	if err := a.enter(StateChecking); err != nil {
		return a.Snapshot(), err
	}
	defer a.leave() // insurance if the work below panics; finish() is the normal release
	st, err := a.fetch(ctx)
	if err == nil {
		a.evaluate(st, false)
	}
	return a.finish(), err
}

// finish releases the claim and returns the snapshot as it stands AFTERWARDS.
//
// Callers must use this instead of `defer a.leave()` + `return a.Snapshot()`:
// Go evaluates a return expression BEFORE running defers, so that shape hands
// the caller a snapshot still marked state="checking". Nothing in the daemon
// notices — but the console wires its button's spinner to that field, so a
// check that finished in 200ms spun until the next 60-second poll said
// otherwise, while the CLI (which ignores state) looked instant.
func (a *Agent) finish() Snapshot {
	a.leave()
	return a.Snapshot()
}

// Apply installs the update the last check found, through the SAME
// CheckAndApply path the periodic loop uses — deliberately not a shortened
// version of it. Re-running the check costs one small signed document and keeps
// exactly one set of gates in front of the installer.
//
// It ignores the POLICY on purpose: the policy answers "should this machine
// install on its own", and a person pressing "update now" has answered that
// question themselves. It does not ignore CanApply.
func (a *Agent) Apply(ctx context.Context) error {
	if a == nil {
		return ErrDisabled
	}
	if err := a.enter(StateUpdating); err != nil {
		return err
	}
	defer a.leave()

	st, err := a.fetch(ctx)
	if err != nil {
		return err
	}
	if !st.Available {
		return nil // already current: nothing to do, not an error
	}
	if !st.CanApply {
		return ErrCannotApply
	}
	if _, err := a.u.CheckAndApply(ctx); err != nil {
		a.record(st, err)
		return err
	}
	clearDeferState(a.u.DownloadDir)
	a.latchLaunched()
	return nil
}

// Run polls until ctx is cancelled.
//
// Two clocks: the manifest is FETCHED every `interval`, but a held update is
// re-evaluated every pendingEvalInterval — see that constant for why they cannot
// be the same number.
func (a *Agent) Run(ctx context.Context, interval time.Duration) {
	if a == nil {
		return
	}
	// Small initial delay so a freshly-booted service isn't racing the network.
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		launched, held := a.tick(ctx, interval)
		if launched {
			return
		}
		next := interval
		if held {
			next = pendingEvalInterval
		}
		t.Reset(next)
	}
}

// tick fetches when due, then evaluates. Reports whether an update was launched
// (the loop should stop) and whether one is being held (come back sooner).
func (a *Agent) tick(ctx context.Context, checkEvery time.Duration) (launched, held bool) {
	if err := a.enter(StateChecking); err != nil {
		return false, false // a manual check/apply holds the agent; skip this tick
	}
	defer a.leave()

	a.mu.Lock()
	due := a.lastCheck.IsZero() || a.now().Sub(a.lastCheck) >= checkEvery
	st := a.snap.Status
	a.mu.Unlock()

	if due {
		var err error
		st, err = a.fetch(ctx)
		if err != nil {
			a.logf("selfupdate: check failed: %v", err)
			return false, false
		}
		if !st.Available {
			a.logf("selfupdate: up to date (current %s, manifest %s)", st.Current, st.Latest)
		}
	}
	launched = a.evaluate(st, true)
	// "Out of date and nothing here can fix it" has to reach the LOG, not only
	// the console — the machines in that state (a Linux box or an unattended
	// agent, where the manifest publishes no artifact) are exactly the ones
	// nobody opens a console for. evaluate() stays quiet about it because the
	// policy never got a say; say it here, and only on a real fetch so it is
	// once per interval rather than once per pending re-evaluation.
	if due && !launched && st.Available && !st.CanApply {
		a.logf("selfupdate: %s is available; this install cannot apply it (%s) — update it by hand",
			st.Latest, st.Reason)
	}
	return launched, a.Snapshot().Hold != ""
}

// slowCheckWarn is when a check is worth a log line of its own. A check is two
// small GETs; past this it is the network, not us.
const slowCheckWarn = 3 * time.Second

// fetch runs one check and records it.
func (a *Agent) fetch(ctx context.Context) (Status, error) {
	start := a.now()
	st, err := a.u.Check(ctx)
	// The console's button spins for exactly as long as this call takes, so "the
	// button spins" and "the manifest host is slow" arrive as the same complaint.
	// Putting the number in the log is what tells them apart without guessing.
	if d := a.now().Sub(start); d > slowCheckWarn {
		a.logf("selfupdate: check took %s (manifest %s)", d.Round(time.Millisecond), a.u.ManifestURL)
	}
	a.record(st, err)
	if err == nil {
		a.mu.Lock()
		a.lastCheck = a.now()
		a.mu.Unlock()
	}
	return st, err
}

// evaluate applies the policy to a status. install=false makes it decide and
// record without acting.
func (a *Agent) evaluate(st Status, install bool) (launched bool) {
	dir := a.u.DownloadDir
	if !st.Available {
		clearDeferState(dir)
		a.setHold("", time.Time{})
		return false
	}
	a.mu.Lock()
	p := a.policy
	a.mu.Unlock()

	now := a.now()
	d := p.Decide(st, now, a.isBusy(), waitingSince(dir, st.Latest))
	if !d.Install {
		var until time.Time
		// Only the WAITING holds run a clock. notify-only and security-only are
		// indefinite by design — they are waiting for a person, not a deadline.
		if d.Hold == HoldOutsideWindow || d.Hold == HoldBusy {
			noteDeferred(dir, st.Latest, now)
			if s := waitingSince(dir, st.Latest); !s.IsZero() && p.MaxDeferDays > 0 {
				until = s.Add(time.Duration(p.MaxDeferDays) * 24 * time.Hour)
			}
		}
		a.setHold(d.Hold, until)
		if d.Hold != "" {
			a.logf("selfupdate: %s is available, holding (%s)", st.Latest, d.Hold)
		}
		return false
	}
	a.setHold("", time.Time{})
	if !install {
		return false
	}

	a.setState(StateUpdating)
	applied, err := a.u.CheckAndApply(context.Background())
	if err != nil {
		a.record(st, err)
		a.logf("selfupdate: apply failed: %v", err)
		return false
	}
	if applied {
		clearDeferState(dir)
		a.latchLaunched()
	}
	return applied
}

func (a *Agent) isBusy() bool {
	if a.busy == nil {
		return false
	}
	return a.busy()
}

func (a *Agent) latchLaunched() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.launched = true
	a.snap.State = StateUpdating
}

// enter claims the agent for one operation. Only one check/apply runs at a time:
// the console's "check now" button and the periodic tick must not both be
// walking the download directory.
func (a *Agent) enter(state string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busyOp {
		return ErrBusy
	}
	a.busyOp = true
	a.snap.State = state
	return nil
}

// leave releases the claim. A failed state survives until the next successful
// check clears it, and a launched installer keeps "updating" — the process is
// going away, and flipping back to "idle" would tell the console the opposite.
func (a *Agent) leave() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.busyOp = false
	if a.snap.State != StateFailed && !a.launched {
		a.snap.State = StateIdle
	}
}

func (a *Agent) setState(state string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.snap.State = state
}

func (a *Agent) setHold(hold string, until time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.snap.Hold = hold
	if until.IsZero() {
		// A deadline we do not have must not reach the console as one.
		a.snap.HoldUntil = nil
		return
	}
	// A fresh pointer every time, never a mutated one: Snapshot() copies the
	// struct, so callers would otherwise share the pointee with the agent.
	u := until
	a.snap.HoldUntil = &u
}

func (a *Agent) record(st Status, err error) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		// Keep the last GOOD status visible: a transient DNS failure should not
		// erase "1.11.0 is available" from the console.
		a.snap.Error = err.Error()
		a.snap.State = StateFailed
		return a.snap
	}
	a.snap.Status = st
	a.snap.Policy = a.policy
	a.snap.Auto = a.policy.Mode == ModeAuto && a.u.Privileged
	a.snap.Error = ""
	return a.snap
}
