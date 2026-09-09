package derp

import (
	"testing"
	"time"
)

// testCtl builds a controller with a fake clock and a recording setter, so the
// decision logic can be exercised without a socket.
func testCtl() (c *sndbufCtl, applied *[]int, clock *time.Time) {
	var sizes []int
	now := time.Unix(1_700_000_000, 0)
	c = &sndbufCtl{}
	c.set = func(n int) error { sizes = append(sizes, n); return nil }
	c.now = func() time.Time { return now }
	return c, &sizes, &now
}

// feed drives n one-second windows at bytesPerSec, advancing the fake clock.
func feed(c *sndbufCtl, clock *time.Time, n int, bytesPerSec float64) {
	for i := 0; i < n; i++ {
		*clock = clock.Add(rateWindow)
		c.observeWindow(uint64(bytesPerSec*rateWindow.Seconds()), rateWindow, true)
	}
}

func last(sizes []int) int {
	if len(sizes) == 0 {
		return 0
	}
	return sizes[len(sizes)-1]
}

const (
	rate18Mbit  = 2_250_000  // bytes/sec
	rate100Mbit = 12_500_000 // bytes/sec
)

// A link that speeds up must get its buffer back IMMEDIATELY.
//
// This is the half of the filter that cannot be allowed to lag. The buffer is
// what lets data be in flight; if it stays sized for the slow minute after the
// link recovers, throughput stays down — and the only measurement that could
// prove the link recovered has to travel through the buffer we are refusing to
// grow. The loop would hold itself down.
func TestBufferGrowsImmediatelyWhenTheLinkSpeedsUp(t *testing.T) {
	c, applied, clock := testCtl()
	c.observeRTT(20 * time.Millisecond)

	feed(c, clock, 3, rate18Mbit)
	slow := last(*applied)
	if slow == 0 {
		t.Fatal("nothing applied after three good windows")
	}

	// ONE fast window is enough.
	before := len(*applied)
	feed(c, clock, 1, rate100Mbit)
	if len(*applied) == before {
		t.Fatalf("a 5.5x jump in link rate did not resize the buffer (still %d B)", slow)
	}
	if got, want := last(*applied), int(rate100Mbit*targetQueueDelay.Seconds()); got < want*9/10 {
		t.Errorf("after the speed-up buffer = %d B, want about %d B", got, want)
	}
}

// A link that slows down must NOT drag the buffer down with it until every
// faster sample has aged out. A dip lasting a few seconds is the normal texture
// of a shared link; resizing for it would mean the recovery is throttled by the
// dip that preceded it.
func TestBufferOnlyShrinksAfterTheFastSamplesAgeOut(t *testing.T) {
	c, applied, clock := testCtl()
	c.observeRTT(20 * time.Millisecond)

	feed(c, clock, 2, rate100Mbit)
	fast := last(*applied)
	if fast == 0 {
		t.Fatal("nothing applied on the fast link")
	}

	// Slow for less than rateMemory: the maximum still remembers the fast samples.
	feed(c, clock, int(rateMemory/rateWindow)-3, rate18Mbit)
	if got := last(*applied); got != fast {
		t.Errorf("buffer shrank to %d B during a dip shorter than rateMemory (was %d B)", got, fast)
	}

	// Keep it slow until every fast sample has expired, and now it must follow.
	feed(c, clock, 5, rate18Mbit)
	if got := last(*applied); got >= fast {
		t.Errorf("buffer stayed at %d B after the link stayed slow past rateMemory", got)
	}
}

// THE SAFETY INVARIANT. The buffer must never be sized below the bandwidth-delay
// product, or throughput falls, the rate samples fall with it, and the lower
// rate justifies shrinking further — a spiral that ends at the floor with the
// link throttled by its own controller.
//
// The 250 ms delay target alone does NOT protect a long path: on a 180 ms
// intercontinental leg it is barely one round trip. This is what the RTT term is
// for, and this test is the reason it exists.
func TestBufferNeverSizedBelowTheBandwidthDelayProduct(t *testing.T) {
	const rtt = 180 * time.Millisecond
	c, applied, clock := testCtl()
	c.observeRTT(rtt)
	feed(c, clock, 4, rate18Mbit)

	bdp := int(rate18Mbit * rtt.Seconds())
	got := last(*applied)
	if got < bdp {
		t.Fatalf("buffer %d B is under one BDP (%d B) — the controller can throttle its own link", got, bdp)
	}
	if got < rttMargin*bdp {
		t.Errorf("buffer %d B is under %dx BDP (%d B); sitting near break-even makes every estimate error cost throughput",
			got, rttMargin, rttMargin*bdp)
	}
	// And the RTT term, not the delay target, is what produced it.
	if byDelay := int(rate18Mbit * targetQueueDelay.Seconds()); got <= byDelay {
		t.Errorf("buffer %d B equals the plain %v target (%d B); the RTT floor did not bind on a %v path",
			got, targetQueueDelay, byDelay, rtt)
	}
}

// An idle link measures the application, not the link. Sizing from those windows
// would shrink the buffer to the floor precisely while nothing is using it — so
// the next transfer starts throttled and has to climb back out.
//
// This is the same error the Overview throughput chart made by averaging idle
// seconds into a rate, and the same one BBR's app-limited flag exists to avoid.
func TestAppLimitedWindowsDoNotShrinkTheBuffer(t *testing.T) {
	c, applied, clock := testCtl()
	c.observeRTT(20 * time.Millisecond)
	feed(c, clock, 3, rate100Mbit)
	fast := last(*applied)

	// A long quiet stretch: bytes are still trickling out, but the writer was
	// never blocked and never had a backlog.
	for i := 0; i < int(rateMemory/rateWindow)+5; i++ {
		*clock = clock.Add(rateWindow)
		c.observeWindow(1_000, rateWindow, false)
	}
	if got := last(*applied); got != fast {
		t.Errorf("buffer moved to %d B on app-limited windows (was %d B)", got, fast)
	}
}

// Setting SO_SNDBUF is a one-way door: it disables the kernel's own auto-tuning
// for the life of the socket. Walking through it on a link we have heard nothing
// back from buys nothing, so an RTT sample is the entry price.
func TestNothingIsAppliedBeforeTheLinkHasAnsweredOnce(t *testing.T) {
	c, applied, clock := testCtl()
	feed(c, clock, 5, rate18Mbit) // rate only, never a Pong
	if len(*applied) != 0 {
		t.Errorf("resized to %v with no RTT sample: the link has not answered once", *applied)
	}
}

// THE DEADLOCK THIS BOOTSTRAP EXISTS FOR, as it actually happened.
//
// The rate is measured only from windows where the writer was blocked. The
// writer blocks only when the send buffer is full. The kernel's auto-tuning
// keeps growing the buffer, so on the slow link this controller was written for
// it never filled: 30 seconds of saturating traffic produced 102 ms of blocking,
// no usable sample, and a controller that never touched the socket at all. It
// was inert exactly where it was needed, and `mesh status` said so all along
// with "kernel auto-tuned (no cap applied)" while the link crawled.
//
// The earlier version of this test asserted the opposite — that nothing is
// applied without a rate sample — which is how the bug shipped: the test pinned
// the behaviour instead of the requirement.
func TestABufferThatNeverBlocksTheWriterStillGetsCapped(t *testing.T) {
	c, applied, clock := testCtl()
	c.observeRTT(20 * time.Millisecond)

	// Traffic is flowing, but the writer keeps up every single window because the
	// buffer in front of it is enormous. This is the field capture.
	for i := 0; i < 30; i++ {
		*clock = clock.Add(rateWindow)
		c.observeWindow(uint64(rate18Mbit), rateWindow, false)
	}

	if len(*applied) == 0 {
		t.Fatal("30 windows of traffic and the socket was never capped; the controller cannot ever get a rate sample from here")
	}
	if got := last(*applied); got != maxSockBuf {
		t.Errorf("bootstrapped to %d B, want the %d B ceiling", got, maxSockBuf)
	}
	// And it is a ONE-time bootstrap, not a repeated resize.
	if n := len(*applied); n != 1 {
		t.Errorf("socket resized %d times during bootstrap, want once", n)
	}
}

// Once the ceiling has forced the writer to block, the real measurement must
// take over and shrink it. This is the second half of the bootstrap: a ceiling
// that never gets replaced is just a smaller constant.
func TestBootstrapIsReplacedByTheFirstRealMeasurement(t *testing.T) {
	c, applied, clock := testCtl()
	c.observeRTT(20 * time.Millisecond)
	feed2 := func(n int, bps float64, limited bool) {
		for i := 0; i < n; i++ {
			*clock = clock.Add(rateWindow)
			c.observeWindow(uint64(bps*rateWindow.Seconds()), rateWindow, limited)
		}
	}
	feed2(2, rate18Mbit, false) // bootstrap to the ceiling
	if last(*applied) != maxSockBuf {
		t.Fatalf("expected the ceiling first, got %d", last(*applied))
	}

	// Now the buffer is finite, so the writer starts blocking and the windows
	// become measurements of the link: 3 Mbit/s, the field's throttled leg.
	feed2(3, 375_000, true)
	got := last(*applied)
	if got == maxSockBuf {
		t.Fatal("the ceiling was never replaced by a measurement")
	}
	if got != minSockBuf {
		t.Errorf("settled at %d B; 375 kB/s x %v is under the floor, so %d B is expected",
			got, targetQueueDelay, minSockBuf)
	}
}

// Re-applying on every window would churn syscalls and, worse, keep perturbing
// the buffer whose drain rate is the controller's own input.
func TestSmallMovesDoNotResizeTheSocket(t *testing.T) {
	c, applied, clock := testCtl()
	c.observeRTT(20 * time.Millisecond)
	feed(c, clock, 3, rate18Mbit)
	n := len(*applied)

	feed(c, clock, 3, rate18Mbit*1.2) // 20% — well inside applyRatio
	if len(*applied) != n {
		t.Errorf("a 20%% move resized the socket (%v); applyRatio is %v", *applied, applyRatio)
	}
}

func TestTargetIsClampedBothWays(t *testing.T) {
	slow, appliedSlow, clockSlow := testCtl()
	slow.observeRTT(5 * time.Millisecond)
	feed(slow, clockSlow, 3, 10_000) // 80 kbit/s
	if got := last(*appliedSlow); got != minSockBuf {
		t.Errorf("very slow link got %d B, want the %d B floor", got, minSockBuf)
	}

	fast, appliedFast, clockFast := testCtl()
	fast.observeRTT(5 * time.Millisecond)
	feed(fast, clockFast, 3, 500_000_000) // 4 Gbit/s
	if got := last(*appliedFast); got != maxSockBuf {
		t.Errorf("very fast link got %d B, want the %d B ceiling", got, maxSockBuf)
	}
}

// RTT samples taken while the buffer is full measure the buffer, not the path.
// The MINIMUM over the window is what makes that harmless: contamination only
// pushes a sample up, so the minimum stays an upper bound on the true RTT, and
// an over-estimated RTT yields a larger buffer — the safe direction.
func TestRTTFilterTakesTheMinimumSoLoadedSamplesCannotShrinkTheBuffer(t *testing.T) {
	c, applied, clock := testCtl()
	c.observeRTT(200 * time.Millisecond) // clean, on an idle link
	feed(c, clock, 3, rate18Mbit)
	clean := last(*applied)

	// Now a run of loaded samples, all inflated by our own queue.
	for _, d := range []time.Duration{900 * time.Millisecond, 1200 * time.Millisecond, 700 * time.Millisecond} {
		c.observeRTT(d)
	}
	feed(c, clock, 3, rate18Mbit)
	if got := last(*applied); got != clean {
		t.Errorf("loaded RTT samples moved the buffer from %d B to %d B; the filter is not taking the minimum",
			clean, got)
	}
}
