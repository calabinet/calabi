// DailyCounter is a per-org CUMULATIVE daily counter with a hard cap that
// resets at UTC midnight. It backs the anti-abuse "per-day" quota dimensions
// added 2026-06-12:
//
//   - daily_tcp_conns: new TCP/TLS(+SNI/UDP-flow) connections per day
//   - daily_http_reqs: HTTP/HTTPS requests per day (true per-request, fed by
//     the listener's request-boundary parser — see listener/reqcount.go)
//
// Only the free plan carries a finite cap today (1000 conns/day, 5000
// reqs/day); every paid tier is unlimited (-1 / absent). Because the free
// plan cannot run a self-hosted (BYOI) edge, the "self-hosted is unlimited"
// promise is satisfied automatically — a free org never has an off-platform
// data plane, so no BYOI exemption is needed here.
//
// Distinct from RateLimiter (per-MINUTE token bucket) and ConnLimiter
// (concurrent count): this is a monotonic count for the calendar day, which a
// token bucket can't express. Like the other limiters it is process-global
// and shared across every session of the same org (counts aggregate across a
// customer's client devices), but it is per-replica — a multi-edge org gets
// up to N× the cap, which is acceptable for a free-tier abuse guard (free
// users are affinity-routed to one edge in practice).
package ratelimit

import (
	"errors"
	"sync"
	"time"
)

// ErrDailyLimitExceeded is returned by DailyCounter.Allow once an org has
// used its whole day's budget. Listeners map it to HTTP 429 (HTTP/HTTPS) or a
// silent close (TCP/SNI/UDP).
var ErrDailyLimitExceeded = errors.New("ratelimit: per-org daily cap exceeded")

// DailyCounter caps a per-org cumulative count per UTC day.
//
// limits maps orgID → daily cap (0 = unlimited). state holds each org's
// current UTC-day number + count; on the first event of a new day the entry
// resets to 0. now is injectable so tests can pin the clock / roll the day.
type DailyCounter struct {
	mu       sync.Mutex
	limits   map[int64]int64
	state    map[int64]*dailyState
	deflimit int64
	now      func() time.Time
}

type dailyState struct {
	day   int64 // UTC day number (unix seconds / 86400)
	count int64
}

// NewDailyCounter builds an empty counter. defaultLimit applies to orgs
// without an explicit SetLimit (0 = unlimited default — the production
// wiring; dev / static-token sessions never get a SetLimit and stay
// unlimited).
func NewDailyCounter(defaultLimit int64) *DailyCounter {
	if defaultLimit < 0 {
		defaultLimit = 0
	}
	return &DailyCounter{
		limits:   make(map[int64]int64),
		state:    make(map[int64]*dailyState),
		deflimit: defaultLimit,
		now:      time.Now,
	}
}

// SetLimit overrides the daily cap for one org. limit < 0 (the quota
// "unlimited" sentinel) or 0 both mean "unlimited for this org". Hot-update
// safe; existing day counts are preserved (lowering a cap mid-day takes
// effect immediately, raising it un-blocks the org at once).
func (d *DailyCounter) SetLimit(orgID int64, limit int64) {
	if limit < 0 {
		limit = 0
	}
	d.mu.Lock()
	d.limits[orgID] = limit
	d.mu.Unlock()
}

// Limit returns the current daily cap for orgID (0 = unlimited).
func (d *DailyCounter) Limit(orgID int64) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if v, ok := d.limits[orgID]; ok {
		return v
	}
	return d.deflimit
}

// Allow records one event for orgID against the current UTC day. Returns nil
// when under cap (or unlimited), ErrDailyLimitExceeded once the day's budget
// is spent. Rejected events do NOT increment the count, so Count stays pinned
// at the limit rather than growing unbounded under a flood.
func (d *DailyCounter) Allow(orgID int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	limit := d.deflimit
	if v, ok := d.limits[orgID]; ok {
		limit = v
	}
	if limit <= 0 {
		return nil // unlimited
	}
	day := d.now().UTC().Unix() / 86400
	st := d.state[orgID]
	if st == nil || st.day != day {
		st = &dailyState{day: day, count: 0}
		d.state[orgID] = st
	}
	if st.count >= limit {
		return ErrDailyLimitExceeded
	}
	st.count++
	return nil
}

// Count returns orgID's count for the current UTC day (0 if the stored entry
// is for a prior day). Exposed for /metrics + admin debug.
func (d *DailyCounter) Count(orgID int64) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.state[orgID]
	if st == nil {
		return 0
	}
	if st.day != d.now().UTC().Unix()/86400 {
		return 0
	}
	return st.count
}
