package selfupdate

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var rolloutT0 = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

func TestRolloutPercent(t *testing.T) {
	r := &RolloutState{Start: rolloutT0, Hours: 48, CapPercent: 60}
	for _, c := range []struct {
		at   time.Duration
		want int
	}{
		{-time.Hour, 0}, // not started
		{0, 0},          // just started
		{12 * time.Hour, 25},
		{24 * time.Hour, 50},
		{36 * time.Hour, 60}, // capped
		{480 * time.Hour, 60},
	} {
		if got := r.Percent(rolloutT0.Add(c.at)); got != c.want {
			t.Errorf("at %v: %d%%, want %d%%", c.at, got, c.want)
		}
	}
	if got := (&RolloutState{Start: rolloutT0, Hours: 0, CapPercent: 40}).Percent(rolloutT0); got != 40 {
		t.Errorf("hours=0 is the cap at once: %d%%", got)
	}
	var none *RolloutState
	if !none.Included(rolloutT0) {
		t.Error("no rollout must mean every machine")
	}
}

// ETA is the moment the ramp reaches this machine — and none at all when the cap
// stops short of it, so the console never promises a date that will not come.
func TestRolloutETA(t *testing.T) {
	r := &RolloutState{Start: rolloutT0, Hours: 100, CapPercent: 50, Bucket: 19}
	eta, ok := r.ETA()
	if !ok || !eta.Equal(rolloutT0.Add(20*time.Hour)) {
		t.Fatalf("ETA = %v, %v; want start+20h", eta, ok)
	}
	if r.Included(eta.Add(-time.Second)) || !r.Included(eta) {
		t.Errorf("ETA %v is not the moment the machine becomes included", eta)
	}
	r.Bucket = 50
	if _, ok := r.ETA(); ok {
		t.Error("a machine above the cap was given an ETA")
	}
}

// Buckets are stable for one install and one version, and a new version reshuffles
// who goes first.
func TestRolloutBucket(t *testing.T) {
	if rolloutBucket("abc", "1.12.0") != rolloutBucket("abc", "1.12.0") {
		t.Fatal("bucket is not stable")
	}
	seen := map[int]bool{}
	for i := 0; i < 20; i++ {
		b := rolloutBucket("abc", fmt.Sprintf("1.%d.0", i))
		if b < 0 || b > 99 {
			t.Fatalf("bucket %d out of range", b)
		}
		seen[b] = true
	}
	if len(seen) < 10 {
		t.Errorf("20 versions landed in only %d buckets — the same machines would lead every release", len(seen))
	}
}

func TestInstallIDIsMintedOnceAndKept(t *testing.T) {
	dir := t.TempDir()
	a := loadInstallID(dir)
	if len(a) != 32 {
		t.Fatalf("install id = %q", a)
	}
	if b := loadInstallID(dir); b != a {
		t.Errorf("install id changed across loads: %q → %q", a, b)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, installIDFile)); err != nil || strings.TrimSpace(string(raw)) != a {
		t.Errorf("install id not persisted: %q, %v", raw, err)
	}
}

// Where the rollout sits among the other reasons to wait.
func TestDecideWithARollout(t *testing.T) {
	notYet := &RolloutState{Start: rolloutT0, Hours: 48, CapPercent: 100, Bucket: 99}
	now := rolloutT0.Add(time.Hour)
	auto := Policy{Mode: ModeAuto, MaxDeferDays: 7}
	base := Status{Available: true, CanApply: true, Rollout: notYet}

	if d := auto.Decide(base, now, false, time.Time{}); d.Hold != HoldRollout {
		t.Errorf("routine update outside the rollout: %+v, want hold %q", d, HoldRollout)
	}
	// The machine's backstop ends the MACHINE's waiting, not the publisher's.
	if d := auto.Decide(base, now, false, now.Add(-30*24*time.Hour)); d.Hold != HoldRollout {
		t.Errorf("the defer backstop overrode the rollout: %+v", d)
	}
	crit := base
	crit.Critical = true
	if d := auto.Decide(crit, now, false, time.Time{}); d.Hold != HoldRollout {
		t.Errorf("a critical release skipped the rollout: %+v", d)
	}
	// "Tell me only" is the more fundamental answer; say that, not "rollout".
	if d := (Policy{Mode: ModeNotify}).Decide(crit, now, false, time.Time{}); d.Hold != HoldNotifyOnly {
		t.Errorf("notify-only machine told %+v", d)
	}
	floor := base
	floor.Mandatory = true
	if d := (Policy{Mode: ModeNotify}).Decide(floor, now, false, time.Time{}); !d.Install {
		t.Errorf("below min_supported was held by the rollout: %+v", d)
	}
	included := base
	included.Rollout = &RolloutState{Start: rolloutT0, Hours: 0, CapPercent: 100, Bucket: 99}
	if d := auto.Decide(included, now, false, time.Time{}); !d.Install {
		t.Errorf("an included machine did not install: %+v", d)
	}
}

func rolloutMember(start time.Time, hours, capPct int) string {
	return fmt.Sprintf(`"rollout":{"start":%q,"hours":%d,"cap_percent":%d},`, start.Format(time.RFC3339), hours, capPct)
}

// A rollout that holds a machine back reports it, and says when its turn comes.
// The manual button still installs: a person pressing it has decided.
func TestAgentHoldsForTheRolloutButTheButtonDoesNot(t *testing.T) {
	var launched bool
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0",
		policy:  Policy{Mode: ModeAuto, MaxDeferDays: 7},
		rollout: rolloutMember(time.Now().Add(-time.Hour), 0, 0)}, // paused at 0%
		func(context.Context, string) (func() error, error) { launched = true; return nil, nil })
	defer done()

	if l, held := a.tick(context.Background(), time.Hour); l || !held {
		t.Fatalf("tick = (launched %v, held %v), want held", l, held)
	}
	snap := a.Snapshot()
	if snap.Hold != HoldRollout || snap.HoldUntil != nil {
		t.Errorf("hold = %q until %v; want %q with no date (the cap stops short of everyone)", snap.Hold, snap.HoldUntil, HoldRollout)
	}
	if launched {
		t.Fatal("installed while the rollout was paused at 0%")
	}
	if err := a.Apply(context.Background()); err != nil || !launched {
		t.Errorf("the button did not install past the rollout: err=%v launched=%v", err, launched)
	}
}

// A held machine notices the ramp reaching it on a re-evaluation, without
// waiting for the next fetch six hours away.
func TestAgentPicksUpTheRampWithoutRefetching(t *testing.T) {
	start := time.Now().Add(-time.Minute)
	var launched bool
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0",
		policy:  Policy{Mode: ModeAuto, MaxDeferDays: 7},
		at:      start.Add(time.Second),
		rollout: rolloutMember(start, 10, 100)},
		func(context.Context, string) (func() error, error) { launched = true; return nil, nil })
	defer done()

	if l, _ := a.tick(context.Background(), time.Hour); l {
		t.Fatal("installed at 0% of the ramp")
	}
	snap := a.Snapshot()
	if snap.Hold != HoldRollout || snap.HoldUntil == nil {
		t.Fatalf("hold = %q until %v, want a rollout hold with an ETA", snap.Hold, snap.HoldUntil)
	}
	// Past the ETA, and well inside the fetch interval: no new fetch happens.
	eta := *snap.HoldUntil
	a.now = func() time.Time { return eta.Add(time.Second) }
	// A day's fetch interval: this tick re-evaluates the cached status only.
	if l, _ := a.tick(context.Background(), 24*time.Hour); !l || !launched {
		t.Errorf("the ramp reached this machine at %v but a re-evaluation did not install", eta)
	}
}

// A schedule nothing can follow is refused, like a floor above the release.
func TestAMalformedRolloutIsRefused(t *testing.T) {
	for name, member := range map[string]string{
		"hours over a month": rolloutMember(rolloutT0, 721, 100),
		"cap over 100":       rolloutMember(rolloutT0, 1, 101),
		"no start":           `"rollout":{"hours":1},`,
	} {
		pub, priv, _ := ed25519.GenerateKey(nil)
		srv := manifestServerWith(t, "1.11.0", priv, member)
		u := &Updater{ManifestURL: srv.URL + "/latest.json", CurrentVersion: "1.10.0", PubKey: pub,
			DownloadDir: t.TempDir(), Privileged: true, Managed: managedForTest}
		if _, err := u.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "rollout") {
			t.Errorf("%s: err = %v, want a rollout refusal", name, err)
		}
		srv.Close()
	}
}
