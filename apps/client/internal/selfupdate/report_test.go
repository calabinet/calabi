package selfupdate

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// reportSink records what the agent delivers, and can be told to fail.
type reportSink struct {
	mu      sync.Mutex
	batches [][]UpdateEvent
	fail    error
}

func (s *reportSink) report(_ context.Context, evs []UpdateEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.batches = append(s.batches, append([]UpdateEvent(nil), evs...))
	return nil
}

func (s *reportSink) events() []UpdateEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []UpdateEvent
	for _, b := range s.batches {
		all = append(all, b...)
	}
	return all
}

func (s *reportSink) setFail(err error) {
	s.mu.Lock()
	s.fail = err
	s.mu.Unlock()
}

func results(evs []UpdateEvent) string {
	var parts []string
	for _, ev := range evs {
		p := ev.Result
		if ev.Stage != "" {
			p += "/" + ev.Stage
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ",")
}

// The installer's first act is to stop this process, so "started" has to be
// delivered BEFORE it runs — and the pending record written — or the worst
// failure (a service that never comes back) leaves no trace at all.
func TestStartedIsDeliveredBeforeTheInstallerRuns(t *testing.T) {
	sink := &reportSink{}
	var atLaunch string
	var pendingAtLaunch bool
	var a *Agent
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0"},
		func(context.Context, string) (func() error, error) {
			atLaunch = results(sink.events())
			_, err := os.Stat(filepath.Join(a.u.DownloadDir, pendingFile))
			pendingAtLaunch = err == nil
			return func() error { select {} }, nil // killed mid-install: never returns
		})
	defer done()
	a.u.Report = sink.report

	if err := a.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if atLaunch != ResultStarted {
		t.Errorf("delivered before the installer ran = %q, want %q", atLaunch, ResultStarted)
	}
	if !pendingAtLaunch {
		t.Error("no pending record when the installer started: the next process could not close the attempt")
	}
	ev := sink.events()[0]
	if ev.From != "1.10.0" || ev.To != "1.11.0" || ev.Trigger != TriggerManual || ev.AttemptID == "" || ev.Platform != PlatformKey() {
		t.Errorf("started event = %+v", ev)
	}
}

// The process that starts after an install is the one that can say whether it
// worked: it is either the new version or it is not.
func TestTheNextProcessClosesTheAttempt(t *testing.T) {
	for _, tc := range []struct {
		name, current, want string
	}{
		{"it is the new version", "1.11.0", ResultSucceeded},
		{"it is still the old version", "1.10.0", ResultFailed + "/" + StageNotReplaced},
		{"it is neither (installed by hand since)", "1.12.0", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			at := newAttempt("1.10.0", TriggerAuto, time.Now().Add(-90*time.Second))
			at.To = "1.11.0"
			if err := writePending(dir, at); err != nil {
				t.Fatal(err)
			}
			sink := &reportSink{}
			a := NewAgent(&Updater{CurrentVersion: tc.current, DownloadDir: dir, Report: sink.report}, nil)
			a.flushReports(context.Background())

			if got := results(sink.events()); got != tc.want {
				t.Fatalf("reported %q, want %q", got, tc.want)
			}
			if tc.want != "" {
				ev := sink.events()[0]
				if ev.AttemptID != at.AttemptID || ev.DurationMS < 90_000 {
					t.Errorf("event = %+v, want the pending attempt's id and a duration from its start", ev)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, pendingFile)); !os.IsNotExist(err) {
				t.Error("pending record survived: the attempt would be closed again on every restart")
			}
		})
	}
}

// An installer that exits under a live daemon is reported once, as an installer
// failure — and not a second time by the next process as not-replaced.
func TestAnInstallerFailureIsReportedOnce(t *testing.T) {
	sink := &reportSink{}
	apply, exited := launchWaiting(errors.New("exit status 2"))
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0"}, apply)
	defer done()
	a.u.Report = sink.report

	if err := a.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	close(exited)
	waitForState(t, a, StateFailed)
	deadline := time.Now().Add(3 * time.Second)
	for results(sink.events()) != "started,failed/installer" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := results(sink.events()); got != "started,failed/installer" {
		t.Fatalf("reported %q, want started,failed/installer", got)
	}
	if ev := sink.events()[1]; !strings.Contains(ev.Error, "exit status 2") {
		t.Errorf("failure event error = %q, want the exit status in it", ev.Error)
	}

	// Restart on the same (old) version.
	next := NewAgent(&Updater{CurrentVersion: "1.10.0", DownloadDir: a.u.DownloadDir, Report: sink.report}, nil)
	next.flushReports(context.Background())
	if got := results(sink.events()); got != "started,failed/installer" {
		t.Errorf("after a restart the attempt was reported again: %q", got)
	}
}

// A failure before any installer ran is one event naming where it stopped.
func TestAFailureBeforeTheInstallerNamesTheStage(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	payload := []byte("real payload")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))

	t.Run("verify", func(t *testing.T) {
		srv := testServer(t, "1.11.0", payload, sig, strings.Repeat("00", 32), priv)
		defer srv.Close()
		sink := &reportSink{}
		u := &Updater{ManifestURL: srv.URL + "/latest.json", CurrentVersion: "1.10.0", PubKey: pub,
			DownloadDir: t.TempDir(), Privileged: true, Managed: managedForTest,
			Apply: func(context.Context, string) (func() error, error) {
				t.Fatal("the installer must not run")
				return nil, nil
			},
			Report: sink.report}
		a := NewAgent(u, nil)
		if err := a.Apply(context.Background()); err == nil {
			t.Fatal("Apply succeeded with a wrong sha256")
		}
		if got := results(sink.events()); got != "failed/verify" {
			t.Errorf("reported %q, want failed/verify", got)
		}
		if ev := sink.events()[0]; ev.To != "1.11.0" || ev.Error == "" {
			t.Errorf("event = %+v, want the target version and the error", ev)
		}
	})

	t.Run("launch", func(t *testing.T) {
		srv := testServer(t, "1.11.0", payload, sig, "", priv)
		defer srv.Close()
		sink := &reportSink{}
		dir := t.TempDir()
		u := &Updater{ManifestURL: srv.URL + "/latest.json", CurrentVersion: "1.10.0", PubKey: pub,
			DownloadDir: dir, Privileged: true, Managed: managedForTest,
			Apply: func(context.Context, string) (func() error, error) {
				return nil, errors.New("exec: installer not found")
			},
			Report: sink.report}
		a := NewAgent(u, nil)
		if err := a.Apply(context.Background()); err == nil {
			t.Fatal("Apply succeeded with an installer that could not start")
		}
		if got := results(sink.events()); got != "started,failed/launch" {
			t.Errorf("reported %q, want started,failed/launch", got)
		}
		if _, err := os.Stat(filepath.Join(dir, pendingFile)); !os.IsNotExist(err) {
			t.Error("pending record left behind by an installer that never started")
		}
	})
}

// The trigger says why the machine installed: the policy, the release, or a
// person. Without it a failure rate cannot be read against the rollout.
func TestTheTriggerIsRecorded(t *testing.T) {
	sink := &reportSink{}
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0", critical: true,
		policy: Policy{Mode: ModeSecurity, MaxDeferDays: 7}},
		func(context.Context, string) (func() error, error) { return nil, nil })
	defer done()
	a.u.Report = sink.report

	if launched, _ := a.tick(context.Background(), time.Hour); !launched {
		t.Fatal("the critical release did not launch")
	}
	if evs := sink.events(); len(evs) == 0 || evs[0].Trigger != TriggerCritical {
		t.Errorf("events = %+v, want trigger %q", evs, TriggerCritical)
	}
}

// Delivery is best-effort and never loses what it could not send.
func TestUndeliveredResultsAreKept(t *testing.T) {
	dir := t.TempDir()
	sink := &reportSink{}
	a := NewAgent(&Updater{CurrentVersion: "1.10.0", DownloadDir: dir, Report: sink.report}, nil)
	at := newAttempt("1.10.0", TriggerAuto, time.Now())
	at.To = "1.11.0"

	sink.setFail(errors.New("dial tcp: connection refused"))
	a.enqueueReport(at.event(ResultStarted, "", nil, time.Now()))
	a.flushReports(context.Background())
	if n := len(readOutbox(dir)); n != 1 {
		t.Fatalf("after a failed delivery the queue holds %d, want 1", n)
	}

	sink.setFail(ErrReportNoCredential)
	a.flushReports(context.Background())
	if n := len(readOutbox(dir)); n != 1 {
		t.Fatalf("with no credential the queue holds %d, want 1 kept", n)
	}

	sink.setFail(nil)
	a.flushReports(context.Background())
	if n := len(readOutbox(dir)); n != 0 {
		t.Errorf("after a delivery the queue holds %d, want 0", n)
	}
	if got := results(sink.events()); got != ResultStarted {
		t.Errorf("delivered %q", got)
	}
}

// A batch the platform calls malformed would fail the same way forever.
func TestARejectedBatchIsDropped(t *testing.T) {
	dir := t.TempDir()
	sink := &reportSink{}
	a := NewAgent(&Updater{CurrentVersion: "1.10.0", DownloadDir: dir, Report: sink.report}, nil)
	a.enqueueReport(newAttempt("1.10.0", TriggerAuto, time.Now()).event(ResultStarted, "", nil, time.Now()))

	sink.setFail(fmt.Errorf("%w: HTTP 400", ErrReportRejected))
	a.flushReports(context.Background())
	if n := len(readOutbox(dir)); n != 0 {
		t.Errorf("a rejected batch is still queued (%d)", n)
	}
}

func TestTheQueueIsBounded(t *testing.T) {
	dir := t.TempDir()
	var last string
	for i := 0; i < maxOutbox+7; i++ {
		ev := newAttempt("1.10.0", TriggerAuto, time.Now()).event(ResultStarted, "", nil, time.Now())
		last = ev.AttemptID
		if err := appendOutbox(dir, ev); err != nil {
			t.Fatal(err)
		}
	}
	evs := readOutbox(dir)
	if len(evs) != maxOutbox || evs[len(evs)-1].AttemptID != last {
		t.Errorf("queue = %d events ending %q, want %d ending with the newest", len(evs), evs[len(evs)-1].AttemptID, maxOutbox)
	}
}

// Nothing wired, nothing written: a daemon with no platform keeps no queue.
func TestNoReporterWritesNoQueue(t *testing.T) {
	a, done := newAgent(t, agentOpts{current: "1.10.0", latest: "1.11.0"},
		func(context.Context, string) (func() error, error) { return nil, nil })
	defer done()

	if err := a.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := os.Stat(filepath.Join(a.u.DownloadDir, outboxFile)); !os.IsNotExist(err) {
		t.Error("an outbox was written with no reporter configured")
	}
}

func TestAnEventErrorIsCapped(t *testing.T) {
	at := newAttempt("1.10.0", TriggerAuto, time.Now())
	ev := at.event(ResultFailed, StageDownload, errors.New(strings.Repeat("x", 1000)), time.Now())
	if n := len([]rune(ev.Error)); n != maxEventError+1 {
		t.Errorf("error is %d runes, want capped at %d plus the ellipsis", n, maxEventError)
	}
}
