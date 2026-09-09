package main

import (
	"errors"
	"fmt"
	"time"
)

// errNoUsableEdge marks the one failure class where a human is genuinely needed:
// the control plane ANSWERED, and the answer was "there is no edge for you in
// the region you are anchored to". Cross-region auto-switch is deliberately
// disabled, so nothing the daemon can do on its own resolves that — the user
// picks another region from the top bar.
//
// Everything else — dial refused, DNS dead, handshake timed out, no route to
// host — means we could not reach ANYTHING, which is the machine's network being
// down. That fixes itself, and needs no one.
//
// The distinction is free: reaching bff-console at all is what produces this
// error, so its presence proves the network works.
var errNoUsableEdge = errors.New("no usable edge in the anchored region")

// The two — and only two — places that failure comes from. They live here, next
// to the sentinel and the policy that reads it, so a third one cannot be added
// without seeing that the classification exists: forgetting the wrap silently
// demotes an actionable failure to "network is down", which retries forever and
// never tells the user the one thing they could do about it.
func errRegionHasNoEdge(region string) error {
	return fmt.Errorf("no healthy edge in region %q; cross-region auto-switch disabled — switch region manually: %w",
		region, errNoUsableEdge)
}

func errEdgeDiscoveryFailed(reason string) error {
	return fmt.Errorf("%s: %w", reason, errNoUsableEdge)
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
	if errors.Is(err, errNoUsableEdge) {
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
