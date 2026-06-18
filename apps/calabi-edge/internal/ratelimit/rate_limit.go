// RateLimiter caps a per-org event rate expressed in events-per-MINUTE.
//
// It is the anti-abuse "new-connection rate" gate (Phase A, 2026-06-11):
// the edge installs two instances per process — one for new HTTP(S)
// connections, one for new TCP/TLS(+SNI/UDP-flow) connections — and feeds
// each org's cap from quota-svc at handshake. Visitor-facing listeners
// call Allow(orgID) once per accepted connection and shed (429 / close)
// when the bucket is empty.
//
// Why per-minute (not per-second like QPSLimiter): the public framing
// (and ngrok's) is per-minute, and connection-rate ceilings are coarse —
// 100/min is a meaningful raw-TCP cap that reads as nonsense at "1.6/s".
// We still implement on golang.org/x/time/rate (events/sec internally =
// perMin/60) so the token-bucket maths are the same battle-tested code as
// the bandwidth + QPS limiters.
//
// Burst: a per-minute rate of N admits a clump of up to `burst` events at
// once before pacing kicks in. We size burst = N/6 (≈10s of budget) with
// a small floor so a browser opening a handful of parallel connections,
// or an SSH client reconnecting, isn't nuisance-rejected. Without the
// floor, low caps (free TCP = 100/min) would round burst down toward 16
// — fine — but a 60/min cap would give burst 10, which the floor keeps
// usable.
//
// Distinct from QPSLimiter (qps_limit.go): that one is reserved for the
// eventual true per-REQUEST HTTP cap (a later phase that parses requests
// off the keepalive splice). This one limits CONNECTIONS, which is all
// the edge can see per-request today.
package ratelimit

import (
	"errors"
	"sync"

	"golang.org/x/time/rate"
)

// ErrRateLimitExceeded is returned by RateLimiter.Allow when the org has
// drained its per-minute connection-rate bucket. Listeners map this to
// HTTP 429 (for HTTP/HTTPS) or a silent connection close (TCP/SNI/UDP).
var ErrRateLimitExceeded = errors.New("ratelimit: per-org connection-rate cap exceeded")

// minRateBurst is the floor for a bucket's burst capacity so low caps
// still tolerate a small clump (parallel browser connections, a client
// reconnect storm) without nuisance rejections.
const minRateBurst = 10

// RateLimiter is a per-org connection-rate cap measured in events/MINUTE.
//
// Per-org rates live in `rates` (events/min; 0 = unlimited); the backing
// rate.Limiter is built lazily on first Allow() so cold orgs don't
// allocate. defaultPerMin applies to orgs without an explicit SetRate
// (0 = unlimited default, the production wiring — dev / static-token
// sessions never get a SetRate and stay unlimited).
type RateLimiter struct {
	mu            sync.RWMutex
	rates         map[int64]int64 // orgID → events/min (0 = unlimited)
	limiters      sync.Map        // orgID(int64) → *rate.Limiter
	defaultPerMin int64
}

// NewRateLimiter constructs a limiter; defaultPerMin = 0 means "unlimited
// for any org without an explicit SetRatePerMin".
func NewRateLimiter(defaultPerMin int64) *RateLimiter {
	if defaultPerMin < 0 {
		defaultPerMin = 0
	}
	return &RateLimiter{
		rates:         make(map[int64]int64),
		defaultPerMin: defaultPerMin,
	}
}

// SetRatePerMin overrides the per-minute cap for one org. perMin <= 0
// means "unlimited for this org" (Allow short-circuits to nil). Hot-update
// safe: the cached limiter is dropped so the next Allow rebuilds it.
func (l *RateLimiter) SetRatePerMin(orgID int64, perMin int64) {
	if perMin < 0 {
		perMin = 0
	}
	l.mu.Lock()
	l.rates[orgID] = perMin
	l.mu.Unlock()
	l.limiters.Delete(orgID)
}

// RatePerMin returns the current per-minute cap for orgID (0 = unlimited).
func (l *RateLimiter) RatePerMin(orgID int64) int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if v, ok := l.rates[orgID]; ok {
		return v
	}
	return l.defaultPerMin
}

// Allow consumes one token for orgID. Returns nil if allowed,
// ErrRateLimitExceeded otherwise. Unlimited orgs (rate 0) always pass.
//
// Cold path (first call after SetRatePerMin / boot) allocates a
// rate.Limiter; subsequent calls are lock-free reads from sync.Map.
func (l *RateLimiter) Allow(orgID int64) error {
	perMin := l.RatePerMin(orgID)
	if perMin <= 0 {
		return nil
	}
	if l.limiterFor(orgID, perMin).Allow() {
		return nil
	}
	return ErrRateLimitExceeded
}

func (l *RateLimiter) limiterFor(orgID int64, perMin int64) *rate.Limiter {
	if v, ok := l.limiters.Load(orgID); ok {
		return v.(*rate.Limiter)
	}
	burst := int(perMin / 6)
	if burst < minRateBurst {
		burst = minRateBurst
	}
	// events/sec = perMin/60.
	rl := rate.NewLimiter(rate.Limit(float64(perMin)/60.0), burst)
	actual, _ := l.limiters.LoadOrStore(orgID, rl)
	return actual.(*rate.Limiter)
}
