package selfupdate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// UpdateEvent is one step of one update attempt, reported to the platform this
// daemon is logged into.
//
// Nothing else in the daemon can answer "how many machines tried 1.12.0, and
// where did the ones that failed stop". The server only ever sees the version a
// device registers with, and a failure changes nothing it can see.
//
// One attempt produces at most two events: either a single failure before the
// installer ran, or "started" followed by its outcome. A "started" with no
// outcome is itself the answer for the worst case — an installer that took the
// service down and never brought it back leaves nothing running to say so.
type UpdateEvent struct {
	AttemptID  string    `json:"attempt_id"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	Platform   string    `json:"platform"`
	Trigger    string    `json:"trigger"`
	Result     string    `json:"result"`
	Stage      string    `json:"stage,omitempty"`
	Error      string    `json:"error,omitempty"`
	At         time.Time `json:"at"`
	DurationMS int64     `json:"duration_ms,omitempty"`
}

// What started an attempt. Stable strings: the server stores them.
const (
	TriggerAuto      = "auto"      // the policy allowed a routine update
	TriggerCritical  = "critical"  // a security release
	TriggerMandatory = "mandatory" // below min_supported
	TriggerManual    = "manual"    // someone pressed "update now" / ran `calabi update`
)

// Results and failure stages. Stable strings: the server stores them.
const (
	ResultStarted   = "started"
	ResultSucceeded = "succeeded"
	ResultFailed    = "failed"

	StageDownload  = "download"  // fetching the installer
	StageVerify    = "verify"    // sha256 or signature did not match
	StageLaunch    = "launch"    // the installer (or the binary swap) could not be started
	StageInstaller = "installer" // the installer exited and this daemon was still running
	// StageNotReplaced: the daemon came back after an install still on the old
	// version. Seen by the NEXT process, from the pending record.
	StageNotReplaced = "not-replaced"
)

// ErrReportRejected tells the agent the platform refused the batch as malformed.
// Resending the same bytes can only fail the same way, so it is dropped rather
// than left to block the queue until the cap evicts it.
var ErrReportRejected = errors.New("selfupdate: update report rejected")

// ErrReportNoCredential: nothing to report with (not logged in, no device yet).
// The events stay queued and nothing is logged — a desktop nobody has signed
// into is a normal state, not a failure worth a line every six hours.
var ErrReportNoCredential = errors.New("selfupdate: no credential to report with")

// attemptError carries the stage an attempt failed at back to the agent,
// without changing what the error says or what it wraps.
type attemptError struct {
	Stage  string
	Status Status
	Err    error
}

func (e *attemptError) Error() string { return e.Err.Error() }
func (e *attemptError) Unwrap() error { return e.Err }

// maxEventError caps the error text one event carries.
const maxEventError = 300

// attempt is what the agent knows about the attempt in progress. The same shape
// is persisted as the pending record, so the process that starts after an
// install can close the attempt the previous one opened.
type attempt struct {
	AttemptID string    `json:"attempt_id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Platform  string    `json:"platform"`
	Trigger   string    `json:"trigger"`
	StartedAt time.Time `json:"started_at"`
}

func newAttempt(from, trigger string, now time.Time) attempt {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return attempt{
		AttemptID: hex.EncodeToString(b[:]),
		From:      from,
		Platform:  PlatformKey(),
		Trigger:   trigger,
		StartedAt: now,
	}
}

func (at attempt) event(result, stage string, err error, now time.Time) UpdateEvent {
	ev := UpdateEvent{
		AttemptID: at.AttemptID,
		From:      at.From,
		To:        at.To,
		Platform:  at.Platform,
		Trigger:   at.Trigger,
		Result:    result,
		Stage:     stage,
		At:        now.UTC(),
	}
	if result != ResultStarted && !at.StartedAt.IsZero() {
		ev.DurationMS = now.Sub(at.StartedAt).Milliseconds()
	}
	if err != nil {
		ev.Error = err.Error()
		if r := []rune(ev.Error); len(r) > maxEventError {
			ev.Error = string(r[:maxEventError]) + "…"
		}
	}
	return ev
}

// ---- the pending record ----------------------------------------------------

const pendingFile = "pending.json"

func writePending(dir string, at attempt) error {
	b, err := json.Marshal(at)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, pendingFile), b)
}

func clearPending(dir string) { os.Remove(filepath.Join(dir, pendingFile)) }

// resolvePending closes the attempt a previous process opened, and removes the
// record so it is closed exactly once. nil when there was nothing to close, or
// when the running version is neither end of it (installed by hand since, say):
// that says nothing about whether THIS attempt worked.
func resolvePending(dir, current string, now time.Time) *UpdateEvent {
	b, err := os.ReadFile(filepath.Join(dir, pendingFile))
	if err != nil {
		return nil
	}
	clearPending(dir)
	var at attempt
	if json.Unmarshal(b, &at) != nil || at.AttemptID == "" {
		return nil
	}
	switch current {
	case at.To:
		ev := at.event(ResultSucceeded, "", nil, now)
		return &ev
	case at.From:
		ev := at.event(ResultFailed, StageNotReplaced,
			errors.New("the installer ran, but the service came back on the old version"), now)
		return &ev
	}
	return nil
}

// ---- the outbox ------------------------------------------------------------

const outboxFile = "outbox.json"

// maxOutbox bounds the queue. A machine that cannot reach the platform for
// months should not grow a file without limit; the oldest events are the ones
// least worth keeping. It also matches the server's per-request cap, so one
// flush is always one request.
const maxOutbox = 50

func readOutbox(dir string) []UpdateEvent {
	b, err := os.ReadFile(filepath.Join(dir, outboxFile))
	if err != nil {
		return nil
	}
	var evs []UpdateEvent
	if json.Unmarshal(b, &evs) != nil {
		return nil // a corrupt queue is dropped, not allowed to wedge reporting
	}
	return evs
}

func writeOutbox(dir string, evs []UpdateEvent) error {
	if len(evs) == 0 {
		err := os.Remove(filepath.Join(dir, outboxFile))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	b, err := json.Marshal(evs)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, outboxFile), b)
}

func appendOutbox(dir string, ev UpdateEvent) error {
	evs := append(readOutbox(dir), ev)
	if len(evs) > maxOutbox {
		evs = evs[len(evs)-maxOutbox:]
	}
	return writeOutbox(dir, evs)
}

// removeFromOutbox drops the events that were sent, by identity rather than by
// position: something may have been appended while the request was in flight.
func removeFromOutbox(dir string, sent []UpdateEvent) error {
	done := make(map[string]bool, len(sent))
	for _, ev := range sent {
		done[ev.AttemptID+"/"+ev.Result] = true
	}
	var keep []UpdateEvent
	for _, ev := range readOutbox(dir) {
		if !done[ev.AttemptID+"/"+ev.Result] {
			keep = append(keep, ev)
		}
	}
	return writeOutbox(dir, keep)
}

// writeFileAtomic replaces path in one step, so a crash mid-write (and an
// installer stopping this service IS a crash, from the file's point of view)
// leaves the old content or the new one, never half of either.
func writeFileAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
