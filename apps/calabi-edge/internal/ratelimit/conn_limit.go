// ConnLimiter caps the number of *concurrent* visitor connections per
// org — the anti-abuse "how many open at once" ceiling.
//
// Wired in Phase A (2026-06-11): main installs one process-global
// instance; calabi-edge sets each org's cap from quota-svc's `max_conns`
// at handshake (SetCap), and every visitor-facing listener Acquire()s
// before opening the upstream stream + releases on close. Current plan
// caps (quota-svc seedPlans): free=10, basic=50, pro=200, enterprise=800,
// custom=unlimited(-1→0). Tunable per-org via the admin quota override
// (SetCap is hot-update safe).
//
// Why a separate limiter from the bandwidth (token-bucket) one:
// connection count is a step function (open/close events) while
// bandwidth is a continuous rate. Mixing them through x/time/rate
// would force every accept() to pay one event into a bucket that's
// already tracking byte-level fairness.
//
// Multi-replica safety (D7): each calabi-edge holds an independent
// counter for the same org. A 4-replica deployment with Free user
// (cap=50) effectively grants 4×50 = 200 concurrent connections —
// acceptable because edges are heavily affinity-
// routed by the GSLB, and
// because Pro users are the ones who care about exact caps. may
// add a redis-backed cluster-wide counter if the over-grant becomes
// a real concern.
package ratelimit

import (
	"errors"
	"sync"
	"sync/atomic"
)

// ErrConnLimitExceeded is returned by ConnLimiter.Acquire when the
// caller has hit the cap. calabi-edge's proxy layer maps this to HTTP 503
// (or TCP reset) on visitor sessions.
var ErrConnLimitExceeded = errors.New("ratelimit: per-org connection cap exceeded")

// ConnLimiter is the per-org concurrent-connection cap.
//
// Lookup is keyed by org_id (int64). Unknown org_ids inherit the
// DefaultCap; SetCap(id, n) overrides per-org. SetCap(id, 0) means
// "no cap for this org" (used by Enterprise plans / internal accounts).
type ConnLimiter struct {
	mu     sync.RWMutex
	caps   map[int64]int64
	in     map[int64]*atomic.Int64 // current concurrent count
	defcap int64                   // cap for orgs without an explicit entry
}

// NewConnLimiter builds an empty limiter; defaultCap is the floor any
// org without an explicit SetCap gets. defaultCap = 0 means "unlimited
// by default" — typically only useful in tests.
func NewConnLimiter(defaultCap int64) *ConnLimiter {
	return &ConnLimiter{
		caps:   make(map[int64]int64),
		in:     make(map[int64]*atomic.Int64),
		defcap: defaultCap,
	}
}

// SetCap overrides the cap for one org. n = 0 means "unlimited for
// this org". Hot-update safe: in-flight Acquire calls see the new
// limit on the next call to Acquire (existing connections aren't
// retroactively closed — that would surprise users).
func (l *ConnLimiter) SetCap(orgID int64, cap int64) {
	if cap < 0 {
		cap = 0
	}
	l.mu.Lock()
	l.caps[orgID] = cap
	l.mu.Unlock()
}

// Cap reports the current cap for orgID. Returns the default if no
// per-org override exists.
func (l *ConnLimiter) Cap(orgID int64) int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if v, ok := l.caps[orgID]; ok {
		return v
	}
	return l.defcap
}

// Acquire atomically increments the counter for orgID iff the cap
// isn't already hit. Returns a release func (the caller MUST call it on
// connection close) and ErrConnLimitExceeded otherwise.
//
// Race-correctness: we compare-and-swap by reading-then-incrementing.
// Two replicas racing to increment from cap-1 → cap-1 would both think
// they passed (read=cap-1, decide ok), then both increment to cap+1. We
// avoid this by using a single atomic Add + post-check rollback if the
// add lifted the counter past the cap.
func (l *ConnLimiter) Acquire(orgID int64) (release func(), err error) {
	cap := l.Cap(orgID)
	counter := l.counterFor(orgID)
	if cap == 0 {
		counter.Add(1)
		return func() { counter.Add(-1) }, nil
	}
	now := counter.Add(1)
	if now > cap {
		counter.Add(-1)
		return nil, ErrConnLimitExceeded
	}
	return func() { counter.Add(-1) }, nil
}

// Active returns the current concurrent connection count for orgID.
// Useful for /metrics gauge emission and admin debug pages.
func (l *ConnLimiter) Active(orgID int64) int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	c, ok := l.in[orgID]
	if !ok {
		return 0
	}
	return c.Load()
}

func (l *ConnLimiter) counterFor(orgID int64) *atomic.Int64 {
	l.mu.RLock()
	c, ok := l.in[orgID]
	l.mu.RUnlock()
	if ok {
		return c
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if c, ok := l.in[orgID]; ok {
		return c
	}
	c = &atomic.Int64{}
	l.in[orgID] = c
	return c
}
