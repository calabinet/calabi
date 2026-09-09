package derp

import (
	"net"
	"sync"
	"time"
)

// Adaptive sizing for the kernel send buffer behind a relay link.
//
// OFF BY DEFAULT. Enable with CALABI_MESH_RELAY_SNDBUF=adaptive.
//
// Not parked out of caution -- parked because the field measurement came back
// and the case for it did not survive. Kept because the reasoning below is
// sound, the tests hold it up, and the next link that needs it will not want
// this rebuilt from scratch. What the measurement said, on the 3 Mbit/s home
// leg this was written for:
//
//   - The queue it was meant to bound was a STARTUP TRANSIENT, not a standing
//     one. Overlay RTT climbed 1001 -> 1268 ms over the first eleven seconds of
//     a transfer, then dropped to 30 ms in a single step and held 88-193 ms for
//     the rest of it, with throughput unchanged throughout. That step is BBR's
//     PROBE_RTT draining its own STARTUP overshoot on a ten-second cadence: the
//     sender fixes this without our help.
//   - The big win was already taken. The same path used to sit at 5,730 ms
//     under load; the frame queue's deadline (sendq.go) is what moved it to
//     88-193 ms. What remained for this controller was the transient above.
//   - The price is permanent. Setting SO_SNDBUF sets SOCK_SNDBUF_LOCK and turns
//     off Linux's own send-buffer auto-tuning for the life of the socket -- and
//     that auto-tuning sizes from cwnd, which is a real BDP estimator measuring
//     the real path. Giving that up to shave a self-healing transient is a bad
//     trade.
//
// KNOWN GAP, for whoever turns this on. The bootstrap in applyLocked uses
// maxSockBuf (4 MB) as its first ceiling, and on a slow link that is DEEPER than
// what the kernel had auto-tuned to on its own: the field capture's queue topped
// out near 390 KB. So the bootstrap window can be worse than doing nothing until
// the first real measurement lands. The fix is to read the socket's CURRENT
// SO_SNDBUF with getsockopt and start from that -- finite, so it still breaks
// the measurement deadlock, and by construction never worse than the status quo.
// It is not done here because it needs per-platform code (see mesh/sockbuf.go
// for the shape) and the feature did not earn that work.
//
// THE PROBLEM. The queue in sendq.go bounds how long a frame may wait for the
// writer, and that bound is 500 ms. It says nothing about what happens after
// conn.Write returns. On a link the field measured at 3 Mbit/s, the kernel's
// auto-tuned send buffer swallowed 8 MB in one go -- 21 SECONDS of queue sitting
// behind a 500 ms promise. The deadline was not wrong; it was being enforced on
// the smaller of the two queues.
//
// WHY NOT A CONSTANT. Twice now. A fixed 128 KB was set here on the reasoning
// that it "carries 78 Mbit/s at 13 ms", which silently assumed a link with
// 78 Mbit/s in it; on the 3 Mbit/s link that is 700 ms of queue. A fixed byte
// budget is a different amount of TIME at every rate, and the rate is the thing
// we do not know in advance. Removing it was right. Putting a different constant
// back would be the same mistake a third time.
//
// WHAT THIS DOES INSTEAD. Size the buffer in TIME and let the bytes follow:
//
//	delay  = max(targetQueueDelay, rttMargin x minRTT)
//	target = clamp(maxRate x delay, minSockBuf, maxSockBuf)
//
// Both inputs come off the live link with no extra traffic: maxRate from bytes
// the writer already counts, minRTT from the keepalive Ping/Pong the pool
// already sends.
//
// WHY MAX ON THE RATE, MIN ON THE RTT. They are not symmetric, and the asymmetry
// is the whole design:
//
//   - The rate filter takes the MAXIMUM over rateMemory. A buffer sized for a
//     momentary dip would throttle the link the instant it recovered, and the
//     measurement that would prove it recovered has to travel through the very
//     buffer we shrank. So a fast sample raises the target IMMEDIATELY, and a
//     slow one lowers it only once every faster sample has aged out. Grow fast,
//     shrink slow.
//
//   - The RTT filter takes the MINIMUM over rttMemory, and that is what makes
//     the whole thing safe. Our keepalive shares the socket with bulk traffic,
//     so a Ping sent while the buffer is full measures the buffer, not the path.
//     But that contamination only ever pushes RTT UP, never down. The minimum of
//     upward-contaminated samples is therefore still an upper bound on the true
//     path RTT -- and an over-estimated RTT yields a LARGER buffer, which is the
//     harmless direction. A measurement polluted by the thing it controls would
//     normally be a fatal objection; here it fails safe.
//
// WHY THE RTT TERM EXISTS AT ALL. Without it the loop has a death spiral: shrink
// below the bandwidth-delay product, throughput falls because the buffer can no
// longer hold a round trip's worth of data in flight, the rate samples fall with
// it, and the lower rate justifies shrinking further. rttMargin x RTT is a floor
// the spiral cannot get under -- at 4x the BDP the buffer is never the limiter.
// A flat byte floor cannot do this job: 128 KB is four round trips at 20 ms and
// 18 Mbit/s, but a third of one on a 180 ms intercontinental leg.
//
// ONE-WAY DOOR. Setting SO_SNDBUF sets SOCK_SNDBUF_LOCK and permanently disables
// Linux's own auto-tuning on that socket -- the auto-tuning that sizes from
// cwnd, i.e. a real BDP estimator measuring the real path. The first apply gives
// up a good mechanism, so this controller has to be at least as good for the
// rest of the connection's life. That is why it keeps adapting rather than
// deciding once, and why it does not touch the socket at all until it has both
// inputs.
const (
	// targetQueueDelay is how much queue we aim to hold behind conn.Write, as
	// time. Well under the 500 ms the frame queue allows, so the two bounds
	// compose instead of one hiding the other, and far under the 5,730 ms this
	// whole path exists to prevent.
	targetQueueDelay = 250 * time.Millisecond

	// rttMargin is how many round trips the buffer must hold no matter what the
	// delay target says. Four, not one: one BDP is the throughput break-even, and
	// sitting on the break-even means every estimation error costs throughput.
	rttMargin = 4

	// minSockBuf and maxSockBuf clamp the result. The floor keeps very slow links
	// out of the region where per-skb overhead makes the setting unpredictable;
	// the ceiling bounds memory per link (4 MB is already 250 ms of a 130 Mbit/s
	// leg, so it binds only where the delay target is met anyway).
	minSockBuf = 128 << 10
	maxSockBuf = 4 << 20

	// rateWindow is one measurement window for the writer's throughput.
	rateWindow = time.Second

	// rateMemory is how long a rate sample keeps counting toward the maximum --
	// i.e. how long the link has to stay slow before the buffer follows it down.
	rateMemory = 10 * time.Second

	// rttMemory is how long an RTT sample keeps counting toward the minimum. Long
	// because the keepalive is 15 s apart and because a path's propagation floor
	// does not move; it is the loaded samples we are trying to see past.
	rttMemory = 2 * time.Minute

	// applyRatio is how far the target must move before we touch the socket
	// again. Re-applying every window would add syscall churn and, worse, keep
	// perturbing the very buffer whose drain rate is the input.
	applyRatio = 1.5

	// linkLimitedFrac is how much of a window the writer must have spent inside
	// conn.Write for that window's throughput to be a measurement of the LINK.
	// Below it the writer was keeping up, so the number measures whatever the
	// application happened to offer -- see observeWindow.
	linkLimitedFrac = 0.1
)

// stamped is one measurement and when it was taken.
type stamped struct {
	at time.Time
	v  float64
}

// sndbufCtl holds the samples and decides the buffer size. One per link.
type sndbufCtl struct {
	// set applies a size to the socket. Injected so the decision logic is
	// testable without a socket, and nil when the conn is not TCP -- in which
	// case this whole controller quietly does nothing.
	set func(int) error
	now func() time.Time

	mu      sync.Mutex
	rates   []stamped // bytes/second
	rtts    []stamped // seconds
	applied int       // what we last asked for; 0 = never touched the socket
}

func newSndbufCtl(conn net.Conn) *sndbufCtl {
	c := &sndbufCtl{}
	if tc, ok := conn.(*net.TCPConn); ok {
		c.set = tc.SetWriteBuffer
	}
	return c
}

func (c *sndbufCtl) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// observeRTT records one keepalive round trip.
func (c *sndbufCtl) observeRTT(d time.Duration) {
	if d <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	c.rtts = prune(append(c.rtts, stamped{at: now, v: d.Seconds()}), now, rttMemory)
}

// observeWindow records one window of writer throughput and re-decides the size.
//
// linkLimited says whether the number measures the LINK or the application. A
// window in which the writer was never blocked and had nothing queued measured
// how much traffic happened to be offered, which on an idle link is nearly zero
// -- and sizing a buffer from that would shrink it to the floor just in time for
// the next transfer to need it. Discarding app-limited samples is the rule BBR
// applies to its own bandwidth filter, and the rule the Overview throughput
// chart got wrong by averaging idle seconds into a rate.
func (c *sndbufCtl) observeWindow(bytes uint64, elapsed time.Duration, linkLimited bool) {
	if elapsed <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	if bytes > 0 && linkLimited {
		c.rates = prune(append(c.rates, stamped{at: now, v: float64(bytes) / elapsed.Seconds()}), now, rateMemory)
	} else {
		c.rates = prune(c.rates, now, rateMemory)
	}
	c.rtts = prune(c.rtts, now, rttMemory)
	c.applyLocked()
}

// applyLocked recomputes the target and applies it if it has moved enough.
func (c *sndbufCtl) applyLocked() {
	if c.set == nil {
		return
	}
	want, ok := c.targetLocked()
	switch {
	case !ok:
		// BOOTSTRAP, and the reason it has to exist.
		//
		// With no rate sample there is nothing to size from -- but waiting for one
		// is a deadlock. The rate is only measured from windows where the writer
		// was blocked; the writer only blocks when the send buffer is full; and
		// the kernel's auto-tuning keeps growing the buffer so it never is.
		//
		// Measured in the field on the exact link this controller exists for:
		// 30 s of saturating traffic produced 102 ms of blocking and not one
		// usable sample, while the buffer sat at the 8 MB the kernel had grown it
		// to. The mechanism was inert precisely where it was needed.
		//
		// Any FINITE ceiling breaks it, because a buffer that cannot grow must
		// eventually fill. maxSockBuf is the one already on hand: it is the memory
		// bound anyway, it is 250 ms of a 130 Mbit/s link so it cannot throttle
		// anything this side of that, and the first real measurement replaces it a
		// window or two later. An RTT sample is still required first -- not for
		// the arithmetic, which does not use it here, but because opening the
		// one-way door on a link we have heard nothing back from buys nothing.
		if c.applied != 0 || len(c.rtts) == 0 {
			return
		}
		want = maxSockBuf
	case c.applied != 0:
		r := float64(want) / float64(c.applied)
		if r < applyRatio && r > 1/applyRatio {
			return
		}
	}
	if err := c.set(want); err != nil {
		return // a platform that refuses keeps whatever it had
	}
	c.applied = want
}

// targetLocked is the size the current samples justify. ok is false while either
// input is missing: with no rate there is nothing to size from, and with no RTT
// there is no floor to stop a shrink from spiralling. What happens in that state
// is applyLocked's decision, not this one's -- see the bootstrap there.
func (c *sndbufCtl) targetLocked() (int, bool) {
	if len(c.rates) == 0 || len(c.rtts) == 0 {
		return 0, false
	}
	maxRate := c.rates[0].v
	for _, s := range c.rates[1:] {
		if s.v > maxRate {
			maxRate = s.v
		}
	}
	minRTT := c.rtts[0].v
	for _, s := range c.rtts[1:] {
		if s.v < minRTT {
			minRTT = s.v
		}
	}
	delay := targetQueueDelay.Seconds()
	if f := rttMargin * minRTT; f > delay {
		delay = f
	}
	switch want := maxRate * delay; {
	case want < minSockBuf:
		return minSockBuf, true
	case want > maxSockBuf:
		return maxSockBuf, true
	default:
		return int(want), true
	}
}

// Applied is the size currently asked of the kernel; 0 means the socket has been
// left alone. Reported in stats: a datapath that silently resizes its own
// buffers is exactly the kind of thing that has to be visible when it is wrong.
func (c *sndbufCtl) Applied() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applied
}

// Rate is the windowed-maximum send rate in bytes/second, or 0 while no sample
// has been taken.
func (c *sndbufCtl) Rate() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var max float64
	for _, s := range c.rates {
		if s.v > max {
			max = s.v
		}
	}
	return max
}

// prune drops samples older than memory. Samples are kept in arrival order, so
// the expired ones are always a prefix.
func prune(s []stamped, now time.Time, memory time.Duration) []stamped {
	cut := now.Add(-memory)
	i := 0
	for i < len(s) && !s[i].at.After(cut) {
		i++
	}
	if i == 0 {
		return s
	}
	return append(s[:0], s[i:]...)
}
