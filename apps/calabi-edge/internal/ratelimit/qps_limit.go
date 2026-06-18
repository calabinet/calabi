// QPSLimiter caps the per-org HTTP request rate for visitor traffic,
// measured in requests-per-SECOND.
//
// STATUS (2026-06-11): NOT wired into the proxy path. It is held for the
// future *per-request* HTTP cap — a later phase that parses individual
// requests off the keepalive byte-splice (the edge currently sees only
// the first request per connection, so true per-request limiting needs
// that parser). Phase A's anti-abuse shipped a per-MINUTE *connection*
// rate gate instead (see rate_limit.go: RateLimiter), which is all the
// edge can enforce per-request today. Keep this type + its tests; the
// per-request phase will wire it.
//
// Implementation reuses golang.org/x/time/rate (already a dep for the
// bandwidth limiter) so we get the same well-tested token-bucket
// semantics + small memory footprint. Each org gets one *rate.Limiter
// stored in a sync.Map for lock-free reads on the hot path.
//
// Why a separate package member from the bandwidth Limiter: bandwidth
// counts bytes and chunks tokens; QPS counts whole requests and asks
// Allow() per request. Conflating them would force every HTTP request
// to either over-account (1 request = burst capacity worth of bytes)
// or under-account (1 request = 1 byte, which makes bandwidth meaningless).
package ratelimit

import (
	"errors"
	"sync"

	"golang.org/x/time/rate"
)

// ErrQPSLimitExceeded is returned by QPSLimiter.Allow when the org has
// hit its per-second cap. Proxy layer maps to HTTP 429.
var ErrQPSLimitExceeded = errors.New("ratelimit: per-org QPS cap exceeded")

// QPSLimiter is the per-org HTTP request-rate cap.
//
// Per-org caps live in `rates`; the underlying rate.Limiter is built
// lazily on first Allow() so cold orgs don't allocate. defaultQPS
// applies to orgs without an explicit SetRate.
type QPSLimiter struct {
	mu         sync.RWMutex
	rates      map[int64]int64
	limiters   sync.Map // orgID(int64) → *rate.Limiter
	defaultQPS int64
}

// NewQPSLimiter constructs a limiter; defaultQPS = 0 means "unlimited
// for any org without an explicit SetRate" (rare; mostly a test helper).
func NewQPSLimiter(defaultQPS int64) *QPSLimiter {
	return &QPSLimiter{
		rates:      make(map[int64]int64),
		defaultQPS: defaultQPS,
	}
}

// SetRate overrides the QPS cap for one org. qps = 0 means "unlimited
// for this org" — the limiter is removed from the map and Allow() short-
// circuits to true. Hot-update safe.
func (l *QPSLimiter) SetRate(orgID int64, qps int64) {
	if qps < 0 {
		qps = 0
	}
	l.mu.Lock()
	l.rates[orgID] = qps
	l.mu.Unlock()
	// Invalidate any cached limiter so the next Allow() rebuilds it.
	l.limiters.Delete(orgID)
}

// Rate returns the current QPS cap for orgID.
func (l *QPSLimiter) Rate(orgID int64) int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if v, ok := l.rates[orgID]; ok {
		return v
	}
	return l.defaultQPS
}

// Allow asks the limiter for permission to process one request.
// Returns nil if allowed, ErrQPSLimitExceeded otherwise.
//
// Cold path (first request after SetRate or service boot) allocates a
// rate.Limiter; subsequent calls are lock-free reads from sync.Map.
func (l *QPSLimiter) Allow(orgID int64) error {
	qps := l.Rate(orgID)
	if qps == 0 {
		return nil
	}
	rl := l.limiterFor(orgID, qps)
	if rl.Allow() {
		return nil
	}
	return ErrQPSLimitExceeded
}

func (l *QPSLimiter) limiterFor(orgID int64, qps int64) *rate.Limiter {
	if v, ok := l.limiters.Load(orgID); ok {
		return v.(*rate.Limiter)
	}
	// Burst = qps (1 second of headroom). Smaller and you reject
	// micro-bursts that humans don't perceive; larger and you give
	// abusive clients a free pass at boot.
	burst := int(qps)
	if burst < 1 {
		burst = 1
	}
	rl := rate.NewLimiter(rate.Limit(qps), burst)
	actual, _ := l.limiters.LoadOrStore(orgID, rl)
	return actual.(*rate.Limiter)
}
