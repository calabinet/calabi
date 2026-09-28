package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// A registrar that fails forever used to say so only at DEBUG, which at the
// default level says nothing. That is how an empty coord token kept every
// self-hosted relay out of its org's DERP map for weeks while the node itself
// looked healthy (2026-09-25). The opposite — warning on all of it — is no
// better: this runs every 30 seconds, so a permanent warning is filtered within
// a day and takes the one that mattered with it.
//
// What these tests pin is the middle: the transitions are loud, the steady
// state is quiet.

type capture struct {
	recs []slog.Record
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.recs = append(c.recs, r.Clone())
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

func (c *capture) atLevel(l slog.Level) []string {
	var out []string
	for _, r := range c.recs {
		if r.Level == l {
			out = append(out, r.Message)
		}
	}
	return out
}

func (c *capture) attrsOf(msg string) map[string]string {
	for _, r := range c.recs {
		if r.Message != msg {
			continue
		}
		m := map[string]string{}
		r.Attrs(func(a slog.Attr) bool {
			m[a.Key] = a.Value.String()
			return true
		})
		return m
	}
	return nil
}

func newHeartbeat() (*heartbeatLog, *capture) {
	c := &capture{}
	return &heartbeatLog{
		log:   slog.New(c),
		what:  "relay",
		hurts: "its devices are never offered it",
	}, c
}

func TestTheFirstHeartbeatFailureIsAWarningThatSaysWhatBreaks(t *testing.T) {
	hb, c := newHeartbeat()
	hb.failed(errors.New("coord admin: status 401: unauthorized"))

	warns := c.atLevel(slog.LevelWarn)
	if len(warns) != 1 {
		t.Fatalf("warnings = %v, want exactly one", warns)
	}
	a := c.attrsOf(warns[0])
	if !strings.Contains(a["err"], "401") {
		t.Errorf("the warning drops the error: %v", a)
	}
	// Without this the reader has to already know what a relay registrar is
	// for to tell whether the line matters.
	if a["consequence"] == "" {
		t.Errorf("the warning does not say what breaks: %v", a)
	}
}

func TestARepeatingFailureDoesNotWarnEveryThirtySeconds(t *testing.T) {
	hb, c := newHeartbeat()
	err := errors.New("nope")
	for i := 0; i < 20; i++ { // ten minutes of ticks
		hb.failed(err)
	}
	if got := len(c.atLevel(slog.LevelWarn)); got != 1 {
		t.Fatalf("warnings = %d, want 1 — the rest belong at debug", got)
	}
	if got := len(c.atLevel(slog.LevelDebug)); got != 19 {
		t.Errorf("debug lines = %d, want the other 19", got)
	}
}

// ...but it does say so again eventually, because the first warning has
// scrolled away by the time anyone looks.
func TestAStillFailingHeartbeatRepeatsItselfOccasionally(t *testing.T) {
	hb, c := newHeartbeat()
	err := errors.New("nope")
	hb.failed(err)
	hb.lastWarn = time.Now().Add(-registerWarnEvery - time.Second)
	hb.since = time.Now().Add(-2 * time.Hour)
	hb.failed(err)

	warns := c.atLevel(slog.LevelWarn)
	if len(warns) != 2 {
		t.Fatalf("warnings = %v, want the first one and a reminder", warns)
	}
	a := c.attrsOf(warns[1])
	if a["failing_for"] == "" || a["attempts"] == "" {
		t.Errorf("the reminder should say how long and how many: %v", a)
	}
}

func TestRecoveryIsStatedAndResetsTheState(t *testing.T) {
	hb, c := newHeartbeat()
	hb.failed(errors.New("nope"))
	hb.ok()

	infos := c.atLevel(slog.LevelInfo)
	if len(infos) != 1 || !strings.Contains(infos[0], "recovered") {
		t.Fatalf("info lines = %v, want one recovery", infos)
	}
	// And the NEXT outage is a new outage: it warns again rather than being
	// swallowed as a continuation of the old one.
	hb.failed(errors.New("nope again"))
	if got := len(c.atLevel(slog.LevelWarn)); got != 2 {
		t.Errorf("warnings = %d, want the second outage to warn too", got)
	}
}

// A healthy registrar stays out of the way entirely.
func TestASucceedingHeartbeatSaysNothingAboveDebug(t *testing.T) {
	hb, c := newHeartbeat()
	for i := 0; i < 5; i++ {
		hb.ok()
	}
	if len(c.atLevel(slog.LevelWarn))+len(c.atLevel(slog.LevelInfo)) != 0 {
		t.Fatalf("a working heartbeat logged above debug: %v", c.recs)
	}
}
