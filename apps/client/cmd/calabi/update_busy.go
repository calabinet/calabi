package main

import (
	"context"
	"sync"
	"time"
)

// trafficWatch answers one question for the update policy: is anything actually
// moving through this client right now?
//
// It is a byte-counter watcher, not a connection counter, because there is no
// live "open visitor connections" gauge in the daemon — mActive counts
// registered TUNNELS (a tunnel sits registered and idle for weeks) and mConns is
// a cumulative counter. "Bytes grew in the last few minutes" is the signal that
// actually exists, and it is also the honest one to put in front of a user: the
// console says "traffic is moving", not "N connections are open".
//
// Deliberately coarse. Getting this wrong in the safe direction costs a delayed
// update, which the MaxDeferDays backstop bounds anyway; getting it wrong in the
// other direction cuts someone's transfer in half.
type trafficWatch struct {
	grace time.Duration

	mu         sync.Mutex
	last       int64
	seen       bool
	lastActive time.Time
}

// busyGrace is how long after the last byte the machine still counts as busy.
// Long enough that the gaps inside an interactive session (typing in an SSH
// shell, a paused download) do not read as idle.
const busyGrace = 10 * time.Minute

func newTrafficWatch() *trafficWatch { return &trafficWatch{grace: busyGrace} }

// sample records a cumulative byte total. Growth means activity.
//
// A DROP is not activity and not an error: per-tunnel counters restart when a
// tunnel re-registers, so the total can legitimately go backwards. Rebase on it
// quietly — treating it as growth would make every reconnect look like traffic
// and keep a quiet machine permanently "busy".
func (w *trafficWatch) sample(total int64, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.seen && total > w.last {
		w.lastActive = now
	}
	w.last, w.seen = total, true
}

// busy reports whether bytes moved within the grace period.
func (w *trafficWatch) busy(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lastActive.IsZero() {
		return false
	}
	return now.Sub(w.lastActive) < w.grace
}

// run samples until ctx is cancelled. The interval only has to be well under
// busyGrace; it is not a rate measurement.
func (w *trafficWatch) run(ctx context.Context, every time.Duration, total func() int64) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			w.sample(total(), now)
		}
	}
}
