package main

import (
	"errors"
	"fmt"
	"time"
)

// errOperatorMustSwitchRegion marks the ONE failure whose only remedy is a human
// picking a different region: the control plane ANSWERED, and the answer was
// "there is no healthy edge in the region you are anchored to". Cross-region
// auto-switch is deliberately disabled, so the daemon cannot resolve that alone.
//
// It is named for the REMEDY, not for the symptom. It used to be called
// errNoUsableEdge, and that name described both this and "we could not reach the
// control plane at all" — which is how the second one came to be wrapped in it.
//
// THE COST OF GETTING THAT WRONG, measured in the field 2026-09-09: a plain
// network outage made every /v1/edges query time out, which lands on
// edgepicker's tier-4 fall-through (NoUsableEdge). Classified as
// operator-actionable, the loop showed the manual-region prompt after three
// failures and dropped to the 5-minute cadence — so the tunnel came back 5
// minutes after the network did, while the mesh took seconds. The previous
// behaviour, the one this policy replaced, would have retried every 15s.
//
// The precondition is checked in edgepicker, not asserted here: RegionUnavailable
// is only set when attemptListEdges saw reached=true, i.e. bff-console answered.
// NoUsableEdge is the reached=false path. They are opposites.
var errOperatorMustSwitchRegion = errors.New("no healthy edge in the anchored region")

// errRegionHasNoEdge: bff-console answered and the anchored region is empty.
// A person has to choose another region, so this one carries the sentinel.
func errRegionHasNoEdge(region string) error {
	return fmt.Errorf("no healthy edge in region %q; cross-region auto-switch disabled — switch region manually: %w",
		region, errOperatorMustSwitchRegion)
}

// errEdgeDiscoveryFailed: we could not reach the control plane at all, so there
// is nothing to fall back to.
//
// It deliberately does NOT carry the sentinel. This is a NETWORK failure — it
// heals by itself and needs nobody — and treating it as operator-actionable both
// slowed recovery to a 5-minute cadence and offered a remedy that does not even
// apply: switching region cannot help when /v1/edges is unreachable in every
// region.
func errEdgeDiscoveryFailed(reason string) error {
	return errors.New(reason)
}

const (
	// baseRetryDelay is the wait after the first failure, and the fixed cadence
	// for anything the daemon is still expecting to recover on its own.
	baseRetryDelay = 15 * time.Second
	// maxRetryDelay caps the network back-off. It is deliberately SHORT: this is
	// the worst case for how long a machine stays dark after its network comes
	// back, and a minute of that is already noticeable. Backing off to hours
	// would save nothing measurable and cost exactly the thing the loop exists
	// for.
	maxRetryDelay = 60 * time.Second
	// operatorHintAfter is how many consecutive "region has no edge" answers it
	// takes before the SPA is shown the manual-region prompt. Small, because the
	// signal is definitive (the control plane said so) — the only reason to wait
	// at all is to ride out an edge rolling restart without alarming anyone.
	operatorHintAfter = 3
	// parkedRetryInterval is the cadence the loop drops to once the prompt is up.
	// It keeps retrying because THAT STATE ALSO HEALS ITSELF — the region's edge
	// comes back — and the previous behaviour (stop entirely, wait for a click)
	// left an unattended machine down forever after a brief empty window.
	parkedRetryInterval = 5 * time.Minute
)

// reconnectDelay decides how long to wait before the next dial after n
// CONSECUTIVE failures to establish a session, and whether the daemon should
// surface the "server unavailable — switch region by hand" prompt.
//
// THE BUG THIS REPLACES: one counter served both failure classes, and hitting it
// stopped the loop outright. A home connection that dropped for three minutes
// therefore killed the tunnel plane permanently, while the mesh plane — which
// has no cap at all — came back on its own. Worse on a machine installed as a
// service: no SPA is open, so nothing ever un-parks it and the only cure is a
// service restart.
//
// The fix is to split "tell the user" from "give up". We keep the first and drop
// the second: this function never returns a delay that means stop.
func reconnectDelay(err error, fails int) (wait time.Duration, needsOperator bool) {
	if errors.Is(err, errOperatorMustSwitchRegion) {
		if fails >= operatorHintAfter {
			return parkedRetryInterval, true
		}
		return baseRetryDelay, false
	}
	return networkBackoff(fails), false
}

// networkBackoff doubles from baseRetryDelay up to maxRetryDelay. The point of
// backing off at all is not to spare the server — a dial into a dead network
// never reaches one — it is to keep a laptop that is offline for a day from
// spending it re-resolving DNS.
func networkBackoff(fails int) time.Duration {
	d := baseRetryDelay
	// The loop condition only stops the doubling from running away (thousands of
	// failures would overflow); the clamp below is what actually enforces the
	// cap. Written this way on purpose: an early `return maxRetryDelay` from
	// inside the loop holds the ceiling only for constants that double exactly
	// onto it, so editing either one to a value that does not — 45s, say — would
	// silently overshoot, and no test could see it.
	for i := 1; i < fails && d <= maxRetryDelay; i++ {
		d *= 2
	}
	return min(d, maxRetryDelay)
}
