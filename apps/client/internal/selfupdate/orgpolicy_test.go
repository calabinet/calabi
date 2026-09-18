package selfupdate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func intPtr(n int) *int { return &n }

func TestTightenOnlyTightens(t *testing.T) {
	machine := Policy{Mode: ModeNotify, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 7}

	got := machine.Tighten(&OrgPolicy{MinMode: ModeAuto, MaxDeferDays: intPtr(2)})
	want := Policy{Mode: ModeAuto, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 2}
	if got != want {
		t.Errorf("tightened = %+v, want %+v (the window stays the machine's)", got, want)
	}

	strict := Policy{Mode: ModeAuto, MaxDeferDays: 0}
	if got := strict.Tighten(&OrgPolicy{MinMode: ModeSecurity, MaxDeferDays: intPtr(14)}); got != strict {
		t.Errorf("an org requirement LOOSENED a stricter machine: %+v", got)
	}
	if got := machine.Tighten(&OrgPolicy{MinMode: "someday-mode"}); got != machine {
		t.Errorf("an unknown mode changed the policy: %+v", got)
	}
	if got := machine.Tighten(nil); got != machine {
		t.Errorf("no org policy changed the policy: %+v", got)
	}
}

// orgSource is a controllable OrgPolicy source.
type orgSource struct {
	mu  sync.Mutex
	o   *OrgPolicy
	err error
}

func (s *orgSource) fetch(context.Context) (*OrgPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.o, s.err
}

func (s *orgSource) set(o *OrgPolicy, err error) {
	s.mu.Lock()
	s.o, s.err = o, err
	s.mu.Unlock()
}

// The machine said "tell me only"; the org requires automatic updates. The org
// wins while it applies — and the machine's own choice is still what it was.
func TestAnOrgRequirementInstallsOnAMachineThatWouldNot(t *testing.T) {
	src := &orgSource{o: &OrgPolicy{OrgID: 3, MinMode: ModeAuto}}
	var launched bool
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0",
		policy: Policy{Mode: ModeNotify, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 7}},
		func(context.Context, string) (func() error, error) { launched = true; return nil, nil })
	defer done()
	a.u.OrgPolicy = src.fetch

	if l, _ := a.tick(context.Background(), time.Hour); !l || !launched {
		t.Fatal("the org's automatic-update requirement did not install")
	}
	snap := a.Snapshot()
	if snap.Policy.Mode != ModeNotify {
		t.Errorf("the machine's own setting was overwritten: %q", snap.Policy.Mode)
	}
	if snap.OrgPolicy == nil || snap.OrgPolicy.MinMode != ModeAuto || !snap.Auto {
		t.Errorf("snapshot does not show the org requirement: org=%+v auto=%v", snap.OrgPolicy, snap.Auto)
	}
}

// Removing the requirement gives the machine back exactly its own choice.
func TestRemovingTheOrgPolicyRestoresTheMachineSetting(t *testing.T) {
	src := &orgSource{o: &OrgPolicy{OrgID: 3, MinMode: ModeAuto}}
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0",
		policy: Policy{Mode: ModeNotify, MaxDeferDays: 7}}, mustNotApply(t))
	defer done()
	a.u.OrgPolicy = src.fetch
	a.refreshOrgPolicy(context.Background())

	src.set(&OrgPolicy{OrgID: 3}, nil) // the org cleared its policy
	if l, held := a.tick(context.Background(), time.Hour); l || !held {
		t.Fatalf("tick = (launched %v, held %v), want held", l, held)
	}
	if snap := a.Snapshot(); snap.Hold != HoldNotifyOnly || snap.OrgPolicy != nil {
		t.Errorf("hold = %q org = %+v, want notify-only and no org policy", snap.Hold, snap.OrgPolicy)
	}
}

// An unreachable control plane must not loosen an org's rules — not now, and not
// after a restart. Leaving the org does drop them.
func TestTheOrgPolicyOutlivesOutagesButNotLeavingTheOrg(t *testing.T) {
	src := &orgSource{o: &OrgPolicy{OrgID: 3, MinMode: ModeSecurity, MaxDeferDays: intPtr(1)}}
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", policy: Policy{Mode: ModeNotify, MaxDeferDays: 7}}, mustNotApply(t))
	defer done()
	a.u.OrgPolicy = src.fetch
	a.refreshOrgPolicy(context.Background())

	src.set(nil, errors.New("dial tcp: connection refused"))
	a.refreshOrgPolicy(context.Background())
	if snap := a.Snapshot(); snap.OrgPolicy == nil || snap.OrgPolicy.MinMode != ModeSecurity {
		t.Fatalf("an outage dropped the org policy: %+v", snap.OrgPolicy)
	}

	restarted := NewAgent(a.u, nil)
	if snap := restarted.Snapshot(); snap.OrgPolicy == nil || snap.OrgPolicy.MaxDeferDays == nil || *snap.OrgPolicy.MaxDeferDays != 1 {
		t.Fatalf("a restart forgot the org policy: %+v", snap.OrgPolicy)
	}

	src.set(nil, ErrNoOrg)
	restarted.refreshOrgPolicy(context.Background())
	if snap := restarted.Snapshot(); snap.OrgPolicy != nil {
		t.Errorf("leaving the org kept its policy: %+v", snap.OrgPolicy)
	}
	if again := NewAgent(a.u, nil).Snapshot(); again.OrgPolicy != nil {
		t.Errorf("the dropped policy came back from the cache: %+v", again.OrgPolicy)
	}
}

// A bound on holding back: an org that allows no deferral makes a machine outside
// its maintenance window install now.
func TestAnOrgDeferBoundEndsTheWait(t *testing.T) {
	noon := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	var launched bool
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", at: noon,
		policy: Policy{Mode: ModeAuto, WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 7}},
		func(context.Context, string) (func() error, error) { launched = true; return nil, nil })
	defer done()
	a.u.OrgPolicy = (&orgSource{o: &OrgPolicy{OrgID: 3, MaxDeferDays: intPtr(0)}}).fetch

	if l, _ := a.tick(context.Background(), time.Hour); !l || !launched {
		t.Errorf("a 0-day org bound still waited for the window: hold=%q", a.Snapshot().Hold)
	}
}
