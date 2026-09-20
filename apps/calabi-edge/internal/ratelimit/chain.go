// Two-tier bandwidth limiting: per-tunnel AND per-org (2026-09-20).
//
// Until now the bucket was installed on the CONTROL SESSION: one client
// connection, one bucket, shared by every tunnel that connection carried —
// and nothing at all above it, so the same org opening N client connections
// simply got N times the rate.
//
// Now every byte passes two buckets in series:
//
//	per-tunnel (Proxy)  ->  per-org (shared by all of that org's tunnels)
//
// Each tier is itself the existing dual (sustained + peak) Limiter, so a byte
// clears four token buckets. That sounds like a lot and is not: the wait is
// taken per WRITE (32 KB io.Copy chunks, or MinBurstBytes for the peak tier),
// not per byte.
//
// SCOPE, stated plainly: the org tier is per EDGE PROCESS. An org whose
// tunnels land on three edges can run three times its org allowance. That is
// the same limitation the per-org connection caps have carried since
// 2026-06-11 and is a deliberate, documented trade-off, not an oversight.
// Closing it needs the minute-scale feedback loop sketched in
// bandwidth-model.md not a bigger lock.
package ratelimit

import (
	"io"
	"sync"
)

// Chain applies two tiers of limiting to one stream. A nil *Chain, or a
// Chain whose tiers are both unconfigured, is a pass-through — callers do not
// need to branch.
type Chain struct {
	tunnel *Limiter
	org    *Limiter
}

// NewChain pairs a per-tunnel limiter with the org-wide one. Either may be
// nil (that tier simply does not apply).
func NewChain(tunnel, org *Limiter) *Chain { return &Chain{tunnel: tunnel, org: org} }

// Tunnel / Org expose the tiers for tests and metrics.
func (c *Chain) Tunnel() *Limiter {
	if c == nil {
		return nil
	}
	return c.tunnel
}

func (c *Chain) Org() *Limiter {
	if c == nil {
		return nil
	}
	return c.org
}

// Writer wraps w so each write clears BOTH tiers before the bytes go out.
//
// The nesting order (tunnel outside, org inside) is the order the waits
// happen in, and it does not change the result: a byte leaves only after both
// buckets have granted it. Limiter.Writer already returns w untouched when
// its tier is unlimited, so an unconfigured tier costs nothing.
func (c *Chain) Writer(w io.Writer) io.Writer {
	if c == nil {
		return w
	}
	return c.tunnel.Writer(c.org.Writer(w))
}

// Reader is the mirror of Writer for the read side.
func (c *Chain) Reader(r io.Reader) io.Reader {
	if c == nil {
		return r
	}
	return c.tunnel.Reader(c.org.Reader(r))
}

// Allow is the NON-BLOCKING form: both tiers must grant n bytes, or neither
// is charged. Used by the mesh relay, where a refused frame is dropped rather
// than waited on (pkg/relay/rate.go explains why waiting is the wrong answer
// on a datagram path).
//
// The all-or-nothing part matters: charging the lower tier for a frame the
// upper tier refused would throttle the NEXT frame against a debt for bytes
// that never went out.
func (c *Chain) Allow(n int) bool {
	if c == nil {
		return true
	}
	ok, cancelLower := c.tunnel.tryTake(n)
	if !ok {
		return false
	}
	if ok, _ = c.org.tryTake(n); !ok {
		cancelLower()
		return false
	}
	return true
}

// OrgRegistry hands out ONE shared Limiter per org id, so every tunnel of
// that org — across every session on this edge — draws from the same bucket.
//
// Lifetime is reference-counted by SESSION: a session Acquires at handshake
// and Releases when it ends. The bucket is dropped once the last session of
// that org goes away, which is what keeps the map from growing without bound
// on an edge that has served many orgs over its uptime.
//
// Refcounting by session (not by tunnel) is deliberate: a tunnel comes and
// goes many times inside one session, and rebuilding the org bucket each time
// would hand the org a fresh full burst on every reconnect — an easy way to
// average well above the configured rate by flapping a tunnel.
type OrgRegistry struct {
	mu sync.Mutex
	m  map[int64]*orgSlot
}

type orgSlot struct {
	lim *Limiter
	// sustained / peak are the rates as CONFIGURED, kept so a later Acquire
	// can tell "same quota, nothing to do" from "quota changed, hot-swap it".
	// Limiter.Rate() is not usable for that: it reports the value after the
	// MinBytesPerSecond floor has been applied, so a tiny configured rate
	// would compare unequal forever and re-Set on every single handshake.
	sustained int64
	peak      int64
	refs      int
}

// NewOrgRegistry builds an empty registry. A nil *OrgRegistry is usable and
// yields no org tier at all, so an edge without quota wiring needs no branch.
func NewOrgRegistry() *OrgRegistry { return &OrgRegistry{m: make(map[int64]*orgSlot)} }

// Acquire returns the org's shared limiter and bumps its refcount. Every
// Acquire must be matched by exactly one Release.
//
// orgID <= 0 means the tenant could not be resolved to a number (dev /
// static-YAML tenants): no org tier, nil returned, Release is a no-op.
//
// When the org already has a bucket and the caller brings DIFFERENT rates
// (plan change, admin override, a later session that saw fresher quota), the
// existing bucket is hot-swapped rather than replaced — replacing it would
// leave the sessions already holding the old pointer limiting against a
// bucket nobody else shares, which is exactly the org-wide cap failing open.
func (r *OrgRegistry) Acquire(orgID, sustainedBps, peakBps int64) *Limiter {
	if r == nil || orgID <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.m[orgID]
	if s == nil {
		s = &orgSlot{lim: New(sustainedBps, peakBps), sustained: sustainedBps, peak: peakBps}
		r.m[orgID] = s
	} else if s.sustained != sustainedBps || s.peak != peakBps {
		s.lim.SetRate(sustainedBps, peakBps)
		s.sustained, s.peak = sustainedBps, peakBps
	}
	s.refs++
	return s.lim
}

// Release drops one reference and frees the bucket when the last one goes.
func (r *OrgRegistry) Release(orgID int64) {
	if r == nil || orgID <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.m[orgID]
	if s == nil {
		return
	}
	s.refs--
	if s.refs <= 0 {
		delete(r.m, orgID)
	}
}

// Len reports how many orgs currently hold a bucket. Tests use it to prove
// the map does not leak; an exporter could use it as a gauge.
func (r *OrgRegistry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}
