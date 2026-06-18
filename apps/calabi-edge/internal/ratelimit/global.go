// GlobalLimiter is the process-wide, ORG-AGNOSTIC backpressure for one
// calabi-edge (Phase B anti-abuse, 2026-06-11).
//
// Phase A's per-org caps (ConnLimiter / RateLimiter) stop a single tenant
// from monopolising an edge — but the SUM of every org's caps can still
// exceed what one box can physically carry (file descriptors, goroutines,
// accept CPU). GlobalLimiter is the machine-wide ceiling that no tenant
// combination — or a raw connection flood — can breach:
//   - maxConns:     total concurrent visitor connections across ALL orgs
//   - acceptPerSec: total NEW connections/sec accepted across ALL orgs
//
// On trip the listener SHEDS the connection (close / drop) rather than
// queueing (the decided policy) — protecting the box instead of letting a
// backlog grow. App-level shed cannot undo the TCP handshake the kernel
// already completed; pair it with OS-level defences (listen backlog, SYN
// cookies, ulimit -n) —
//
// Both caps default to 0 = unlimited (opt-in via env), so dev / unset
// edges behave exactly as before. All methods are nil-safe: a nil
// *GlobalLimiter admits everything, so callers can carry a nil and skip
// the wiring on an un-configured edge.
package ratelimit

import (
	"sync/atomic"

	"golang.org/x/time/rate"
)

// GlobalLimiter bounds total machine load for one calabi-edge.
type GlobalLimiter struct {
	maxConns int64         // <=0 = unlimited concurrent cap
	inUse    atomic.Int64  // current global concurrent count
	accept   *rate.Limiter // nil = unlimited accept rate
}

// NewGlobalLimiter builds a limiter. maxConns<=0 disables the concurrent
// cap; acceptPerSec<=0 disables the accept-rate cap. Returns a usable
// (all-unlimited) limiter when both are <=0.
func NewGlobalLimiter(maxConns, acceptPerSec int64) *GlobalLimiter {
	g := &GlobalLimiter{}
	if maxConns > 0 {
		g.maxConns = maxConns
	}
	if acceptPerSec > 0 {
		// Burst = 1s of accepts (floor 1) so normal arrival jitter isn't
		// nuisance-shed while a sustained flood is paced to the rate.
		burst := int(acceptPerSec)
		if burst < 1 {
			burst = 1
		}
		g.accept = rate.NewLimiter(rate.Limit(acceptPerSec), burst)
	}
	return g
}

// Configured reports whether either cap is active (boot logging).
func (g *GlobalLimiter) Configured() bool {
	return g != nil && (g.maxConns > 0 || g.accept != nil)
}

// MaxConns / AcceptPerSec expose the configured ceilings for logging.
func (g *GlobalLimiter) MaxConns() int64 {
	if g == nil {
		return 0
	}
	return g.maxConns
}

// AllowAccept consumes one token from the global accept-rate bucket.
// Returns true when allowed (or unlimited / nil receiver).
func (g *GlobalLimiter) AllowAccept() bool {
	if g == nil || g.accept == nil {
		return true
	}
	return g.accept.Allow()
}

// AcquireConn reserves one global concurrent slot. Returns (release, true)
// on success — including the unlimited / nil path where release is a no-op
// — or (nil, false) when the cap is hit. The release MUST be called once
// on connection teardown when ok is true.
func (g *GlobalLimiter) AcquireConn() (release func(), ok bool) {
	if g == nil || g.maxConns <= 0 {
		return func() {}, true
	}
	if g.inUse.Add(1) > g.maxConns {
		g.inUse.Add(-1)
		return nil, false
	}
	return func() { g.inUse.Add(-1) }, true
}

// Active returns the current global concurrent connection count.
func (g *GlobalLimiter) Active() int64 {
	if g == nil {
		return 0
	}
	return g.inUse.Load()
}
