// Package wake detects that this machine was suspended and has resumed, so the
// things a suspend silently invalidates can be rebuilt before the user notices.
//
// Why a clock heuristic and not an OS power event: the symptom is the same on
// every platform (a laptop lid, Windows standby, a paused VM, a frozen
// container) and so is the recovery, so one portable detector is worth more than
// three platform-specific ones.
//
// BOTH clocks are read because neither is reliable on its own — whether a
// monotonic source keeps running across a suspend depends on the platform and
// the sleep state, and the wall clock is the one an NTP step can move.
//
// This lived inside the mesh controller first. It is a package because the edge
// session needed the same thing and a second copy of a heuristic is how two code
// paths quietly drift apart.
package wake

import (
	"context"
	"time"
)

const (
	// CheckInterval is how often the detector looks for a gap in time. Short,
	// because the entire point is to react before the user does.
	CheckInterval = 5 * time.Second
	// Gap is how much longer than one interval a tick has to be before the
	// machine counts as having been asleep rather than merely busy.
	Gap = 30 * time.Second
)

// Woke reads the two clock gaps between consecutive checks and says whether the
// machine was asleep. Either clock alone is enough: on some platforms and sleep
// states the monotonic source stops, on others it keeps running and only the
// wall clock shows the jump.
func Woke(monoGap, wallGap time.Duration) bool {
	return max(monoGap, wallGap) >= CheckInterval+Gap
}

// Loop calls onWake once per detected resume, with the observed gap, until ctx
// ends. Blocking; call it in a goroutine.
//
// A false positive costs whatever onWake does — one re-dial, typically. That is
// the right way round: missing a real wake costs the user a datapath that looks
// up and carries nothing, which is far more expensive and far harder to notice.
func Loop(ctx context.Context, onWake func(gap time.Duration)) {
	t := time.NewTicker(CheckInterval)
	defer t.Stop()
	mono, wall := time.Now(), time.Now().Round(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		monoGap, wallGap := time.Since(mono), time.Now().Round(0).Sub(wall)
		if Woke(monoGap, wallGap) {
			onWake(max(monoGap, wallGap))
		}
		// Re-read AFTER the recovery, never before: onWake can take seconds, and
		// measuring the next gap from before it would report that work as a sleep.
		mono, wall = time.Now(), time.Now().Round(0)
	}
}
