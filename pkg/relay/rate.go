package relay

import (
	"sync/atomic"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// Rate limiting, injected from outside.
//
// The relay forwards ciphertext by node key and must not link the control
// plane (deps_test.go). So it does not decide rates, look up plans, or own a
// token bucket: it takes a decision function and calls it. The platform edge
// injects one built from quota-svc's numbers; a self-hosted relay injects
// nothing and behaves exactly as before.
//
// WHY THE SEAM IS "Allow", NOT "Wait"
//
// A relay that waits is a relay that buffers, and buffering is the failure
// this data path is shaped around: WireGuard is a datagram tunnel, the TCP
// inside it reacts to LOSS and not to delay, so bytes held back to make a
// rate look smooth just grow a queue while the sender keeps accelerating.
// sendq.go opens with the measurement — 12.9 ms idle, 5,730 ms under load,
// 0% loss, 2.7 Mbit/s. A refused frame is dropped on the spot, which is the
// one signal the inner TCP will actually act on.

// RateLimiter decides whether bytes may be forwarded to one link.
//
// Allow is on the per-packet forwarding path and MUST NOT block. It either
// takes the whole n bytes' worth of allowance and returns true, or takes
// nothing and returns false.
type RateLimiter interface {
	Allow(n int) bool
}

// A RateLimiter that holds something shared — an org-wide bucket several links
// draw from — may implement Close to give it back. The hub calls it when the
// link goes away, and when a re-auth replaces the limiter.
//
// Optional because the common case has nothing to release: a per-link bucket
// dies with the link. Making it part of RateLimiter would force every trivial
// implementation to carry an empty method.
type closableRateLimiter interface{ Close() }

func closeLimiter(l RateLimiter) {
	if c, ok := l.(closableRateLimiter); ok {
		c.Close()
	}
}

// RateLimiterFor resolves the limiter for one link, once the grant has proved
// which meshnet (org) it belongs to. meshnet is 0 when the relay runs with
// auth off — a self-hosted, single-tenant posture where there is nobody to
// meter against, so returning nil (no limit) is the right answer there.
//
// Called at most twice per connection (on add, and again if a live link
// re-authenticates), never per packet.
type RateLimiterFor func(meshnet int64, key meshproto.NodeKey) RateLimiter

// WithRateLimiter installs the resolver. nil (the default) means no limiting
// anywhere, which is what a self-hosted relay and every existing deployment
// get until an operator wires one.
func (h *Hub) WithRateLimiter(f RateLimiterFor) *Hub {
	h.limiterFor = f
	return h
}

// limiterBox lets a client's limiter be swapped atomically on re-auth without
// putting a mutex on the forwarding path. A nil box, or a box holding nil,
// both mean "no limit".
type limiterBox struct{ l RateLimiter }

// resolveLimiter (re)computes a link's limiter from its current meshnet and
// releases whatever it replaces. Safe to call whenever the meshnet changes;
// a no-op when no resolver is wired.
//
// MUST NOT be called while holding h.mu: the resolver is the operator's code
// and on the platform it asks quota-svc.
func (h *Hub) resolveLimiter(c *client) {
	if h.limiterFor == nil {
		return
	}
	fresh := h.limiterFor(c.usage.meshnet.Load(), c.key)
	if old := c.limiter.Swap(&limiterBox{l: fresh}); old != nil {
		closeLimiter(old.l)
	}
}

// releaseLimiter hands back whatever the link held. Called once, when the link
// is gone. Without it a limiter holding a shared org bucket would keep that
// bucket (and its map entry) alive for the life of the process — invisible
// until a relay that has served many orgs has been up for weeks.
func (h *Hub) releaseLimiter(c *client) {
	if old := c.limiter.Swap(nil); old != nil {
		closeLimiter(old.l)
	}
}

// allow reports whether n ciphertext bytes may be forwarded to this link.
// A link with no limiter always allows, so the un-wired path costs one atomic
// load and a nil check.
func (c *client) allow(n int) bool {
	box := c.limiter.Load()
	if box == nil || box.l == nil {
		return true
	}
	return box.l.Allow(n)
}

// refused counts frames this relay declined to forward because the
// destination's limiter said no.
//
// It is deliberately SEPARATE from sendq's Dropped: a frame dropped there
// waited too long behind a slow reader (a path problem), one refused here
// never got the chance (a quota decision). Folding them together would make
// "is this link congested or is this org over its rate" unanswerable from the
// counters, which is exactly the question an operator has when a customer
// reports mesh throughput.
type refusedCounter struct{ n atomic.Uint64 }

func (r *refusedCounter) add(n uint64) { r.n.Add(n) }

// RefusedFrames returns how many frames this hub has refused on rate grounds
// since it started.
func (h *Hub) RefusedFrames() uint64 { return h.refused.n.Load() }
