package derp

import (
	"net"
	"sync"
	"testing"
	"time"
)

// The point of the queue is a bounded WAIT, not a bounded rate. The first thing
// to pin is therefore the negative: on a link that keeps up, nothing is dropped.
// A queue that sheds packets on a healthy path would be exactly the "deliberate
// throttling" this is not.
func TestSendQueueDropsNothingWhenTheWriterKeepsUp(t *testing.T) {
	q := newSendQueue()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	closed := make(chan struct{})
	defer close(closed)
	go q.run(client, &sync.Mutex{}, closed, nil)

	const n = 200
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // a reader that never falls behind
		defer wg.Done()
		buf := make([]byte, 64)
		for i := 0; i < n; i++ {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()
	for i := 0; i < n; i++ {
		q.enqueue([]byte{byte(i)})
	}
	wg.Wait()

	if got := q.Dropped(); got != 0 {
		t.Errorf("dropped %d on a link that kept up, want 0", got)
	}
}

// And the positive: a packet that has waited longer than the deadline is
// discarded rather than sent late. This is the congestion signal — the thing a
// TCP relay otherwise swallows, leaving the tunnelled TCP to fill seconds of
// queue because it reacts to loss and never to delay.
func TestSendQueueDropsWhatWaitedTooLong(t *testing.T) {
	q := newSendQueue()
	// A clock we control: the enqueue happens at T, the drain at T+2×deadline.
	var mu sync.Mutex
	now := time.Now()
	q.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	q.enqueue([]byte("stale"))
	q.enqueue([]byte("stale"))
	mu.Lock()
	now = now.Add(2 * maxQueueDelay)
	mu.Unlock()

	closed := make(chan struct{})
	defer close(closed)
	go q.run(client, &sync.Mutex{}, closed, nil)

	// Nothing must reach the wire. A read that succeeds means a stale frame was
	// sent; the deadline is short, so a brief wait is enough to prove it.
	_ = server.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, 64)
	if n, err := server.Read(buf); err == nil {
		t.Fatalf("sent %d stale bytes (%q); the deadline should have dropped them", n, buf[:n])
	}
	if got := q.Dropped(); got != 2 {
		t.Errorf("dropped %d, want 2", got)
	}
}

// The deadline has to clear ORDINARY LOSS RECOVERY, not just a round trip.
//
// This pins the correction to the mistake that made this queue a throttle. The
// number was first argued against relay RTT — "100 ms is well above 13 ms, so
// there is sevenfold margin" — but the writer is not waiting for a round trip.
// It is waiting for the relay link's TCP to return its send buffer, and on a
// lossy path that wait is dominated by retransmission timeouts. Linux's minimum
// RTO is 200 ms, so the old deadline expired TWICE OVER inside a single ordinary
// recovery, discarding a queue's worth of traffic each time. Measured effect on
// one real link: 3.3 Mbit/s delivered and 71% shed, where plain iperf3 over the
// same path in the same minute got 18.9 Mbit/s.
//
// An arithmetic check on a constant cannot catch a wrong premise — the old test
// here proved 128 KB was "enough" for a link that did not exist. What this one
// asserts is the relationship that was missing: the deadline is compared against
// the recovery it has to survive, not against propagation delay.
func TestDeadlineClearsOrdinaryLossRecovery(t *testing.T) {
	// Linux net/ipv4/tcp.h: TCP_RTO_MIN is HZ/5.
	const linuxMinRTO = 200 * time.Millisecond
	if maxQueueDelay <= linuxMinRTO {
		t.Errorf("maxQueueDelay %v does not outlast a single Linux RTO (%v): every "+
			"retransmission timeout on the relay link would shed the whole queue",
			maxQueueDelay, linuxMinRTO)
	}
	// And it must stay a backstop, not become the bufferbloat it guards against.
	// The failure it exists to prevent measured 5,730 ms.
	if maxQueueDelay >= 2*time.Second {
		t.Errorf("maxQueueDelay %v is long enough to be the bufferbloat it guards against", maxQueueDelay)
	}
}

// The override, including the escape hatch that turns age-shedding off entirely
// so a link can be measured without it. Garbage must not take the datapath down.
func TestMaxQueueDelayOverride(t *testing.T) {
	if got := resolveMaxQueueDelay(""); got != maxQueueDelay {
		t.Errorf("unset = %v, want the default %v", got, maxQueueDelay)
	}
	if got := resolveMaxQueueDelay("800ms"); got != 800*time.Millisecond {
		t.Errorf(`"800ms" = %v, want 800ms`, got)
	}
	if got := resolveMaxQueueDelay("0"); got != 0 {
		t.Errorf(`"0" = %v, want 0 (shedding by age disabled)`, got)
	}
	for _, bad := range []string{"500", "-1s", "soon"} {
		if got := resolveMaxQueueDelay(bad); got != maxQueueDelay {
			t.Errorf("%q = %v, want the default %v", bad, got, maxQueueDelay)
		}
	}
}

// A zero deadline means "never shed by age" — the measurement mode. Without this
// the escape hatch would silently behave as "shed everything", which is the
// opposite of what someone reaching for it wants.
func TestZeroDeadlineSendsEvenAncientFrames(t *testing.T) {
	q := newSendQueue()
	q.deadline = 0
	var mu sync.Mutex
	now := time.Now()
	q.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	q.enqueue([]byte("ancient"))
	mu.Lock()
	now = now.Add(time.Hour)
	mu.Unlock()

	closed := make(chan struct{})
	defer close(closed)
	go q.run(client, &sync.Mutex{}, closed, nil)

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("an hour-old frame was dropped with the deadline disabled: %v", err)
	}
	if string(buf[:n]) != "ancient" {
		t.Errorf("read %q, want %q", buf[:n], "ancient")
	}
	if got := q.Dropped(); got != 0 {
		t.Errorf("dropped %d with the deadline disabled, want 0", got)
	}
}

// Overflow drops too, and is counted. This is the backstop for a writer that has
// stopped entirely — without it, enqueue would block and push the backlog up
// into WireGuard and then the tun, which is how the unbounded buffering that
// started all this came about.
func TestSendQueueOverflowIsCounted(t *testing.T) {
	q := newSendQueue() // nothing draining it
	const extra = 50
	for i := 0; i < sendQueueDepth+extra; i++ {
		q.enqueue([]byte{1})
	}
	if got := q.Dropped(); got != extra {
		t.Errorf("dropped %d, want %d (queue depth %d)", got, extra, sendQueueDepth)
	}
}

// The kernel's send buffer is the kernel's business by default.
//
// This replaces a test that asserted the opposite and passed while the setting
// was wrong. It computed 128 KB × 8 / 13 ms = 78 Mbit/s and concluded there was
// headroom — true only on a link that already had 78 Mbit/s in it. The link in
// the field had 3, where the same 128 KB (256 KB, since Linux stores double) is
// 700 ms of standing queue. The test checked the arithmetic of a number against
// an assumed rate; it could not check the assumption, and the assumption was the
// thing that was wrong.
//
// Setting SO_SNDBUF also disables Linux's send-buffer auto-tuning, which sizes
// itself from the connection's congestion window — a BDP estimator that measures
// the real path. There is no constant that beats it at every speed.
// The DEFAULT is to leave the socket alone. Setting SO_SNDBUF at all is a
// one-way door -- it turns off Linux's auto-tuning for the life of the socket,
// and that auto-tuning sizes from the congestion window, i.e. it is a real BDP
// estimator on the real path. The adaptive controller measured out worse than
// that trade on the link it was written for (see sndbuf.go), so it is opt-in.
//
// This test previously asserted the opposite. It is inverted deliberately, not
// by accident: an experiment that turns itself on for every user by default is
// the failure this pins shut.
func TestSendBufferPolicyDefaultsToLeavingTheKernelAlone(t *testing.T) {
	pol := resolveSendBufPolicy("")
	if pol.adaptive || pol.pinned != 0 {
		t.Errorf("unset = %+v, want neither adaptive nor pinned", pol)
	}
}

// "0" says the same thing explicitly, and must keep working as the way to write
// it down in a unit file.
func TestSendBufferPolicyZeroMeansLeaveTheKernelAlone(t *testing.T) {
	pol := resolveSendBufPolicy("0")
	if pol.adaptive || pol.pinned != 0 {
		t.Errorf(`"0" = %+v, want neither adaptive nor pinned`, pol)
	}
}

// And there has to be a way to turn the controller ON, or the code below is
// dead rather than parked.
func TestSendBufferPolicyAdaptiveIsOptIn(t *testing.T) {
	pol := resolveSendBufPolicy("adaptive")
	if !pol.adaptive || pol.pinned != 0 {
		t.Errorf(`"adaptive" = %+v, want the controller on and nothing pinned`, pol)
	}
}

// A pinned value bisects a suspected controller bug against a constant.
func TestSendBufferPolicyPinsAnExplicitSize(t *testing.T) {
	pol := resolveSendBufPolicy("262144")
	if pol.adaptive || pol.pinned != 262144 {
		t.Errorf(`"262144" = %+v, want pinned 262144 and not adaptive`, pol)
	}
}

// A typo must not take the datapath down: this is a knob on a live relay link,
// and refusing to carry traffic over a malformed environment variable would be
// far worse than ignoring it. It falls back to the DEFAULT, which is now "leave
// the socket alone" -- so a stray character in a unit file cannot enable an
// experiment on someone's datapath either.
func TestSendBufferPolicyFallsBackOnGarbage(t *testing.T) {
	for _, bad := range []string{"128k", "-1", "lots", "1.5", " 4096", "Adaptive", "auto"} {
		pol := resolveSendBufPolicy(bad)
		if pol.adaptive || pol.pinned != 0 {
			t.Errorf("%q = %+v, want the do-nothing default", bad, pol)
		}
	}
}

// The writer loop decides whether each window MEASURED THE LINK or measured the
// application, and that single boolean gates the whole adaptive controller: a
// window wrongly marked link-limited sizes the buffer from an idle link, and one
// wrongly marked app-limited means the controller never engages at all. The
// decision logic in sndbuf.go is tested against synthetic windows; this pins the
// wiring that produces them.
//
// Rate() is the probe: it is non-zero only once a window arrived with bytes AND
// the link-limited flag set, so it reads the flag without the datapath needing a
// test-only hook in it.
func TestWriterMarksWindowsLinkLimitedOnlyWhenTheLinkIsTheLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("spans real rateWindow ticks")
	}

	t.Run("a blocked writer produces link-limited windows", func(t *testing.T) {
		q := newSendQueue()
		q.deadline = 0 // shedding is not what is under test here
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		ctl := &sndbufCtl{set: func(int) error { return nil }}
		closed := make(chan struct{})
		defer close(closed)
		go q.run(client, &sync.Mutex{}, closed, ctl)

		// A reader that drains slowly, so the writer spends its time inside Write.
		go func() {
			buf := make([]byte, 64)
			for {
				if _, err := server.Read(buf); err != nil {
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()

		stop := time.After(2*rateWindow + rateWindow/2)
		for done := false; !done; {
			select {
			case <-stop:
				done = true
			default:
				q.enqueue(make([]byte, 64))
			}
		}
		if ctl.Rate() == 0 {
			t.Error("no link-limited window recorded while the writer was blocked on a slow reader")
		}
	})

	// THE CASE THE PREDICATE EXISTS FOR: traffic IS flowing, but the writer keeps
	// up with it, so the window measured how much the application felt like
	// sending. A trickle on a fast link is the everyday shape of this — an idle
	// window is caught by the bytes > 0 guard instead and proves nothing about
	// the flag.
	t.Run("a writer that keeps up produces none despite traffic", func(t *testing.T) {
		q := newSendQueue()
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		ctl := &sndbufCtl{set: func(int) error { return nil }}
		closed := make(chan struct{})
		defer close(closed)
		go q.run(client, &sync.Mutex{}, closed, ctl)

		go func() { // drains as fast as it arrives
			buf := make([]byte, 64)
			for {
				if _, err := server.Read(buf); err != nil {
					return
				}
			}
		}()

		deadline := time.Now().Add(2*rateWindow + rateWindow/2)
		for time.Now().Before(deadline) {
			q.enqueue(make([]byte, 64))
			time.Sleep(50 * time.Millisecond)
		}
		if r := ctl.Rate(); r != 0 {
			t.Errorf("rate %v B/s recorded from windows the writer kept up with; that number is the application's, not the link's", r)
		}
	})

	t.Run("an idle writer produces none", func(t *testing.T) {
		q := newSendQueue()
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		ctl := &sndbufCtl{set: func(int) error { return nil }}
		closed := make(chan struct{})
		defer close(closed)
		go q.run(client, &sync.Mutex{}, closed, ctl)

		time.Sleep(2*rateWindow + rateWindow/2)
		if r := ctl.Rate(); r != 0 {
			t.Errorf("rate %v recorded on a queue that never had anything to send", r)
		}
	})
}

// The policy table decides a value; this pins what that value DOES. The default
// must not even construct a controller, because a controller is the thing that
// eventually walks through the one-way door and turns off the kernel's
// auto-tuning. "It defaults to a policy that means do nothing" and "it does
// nothing by default" are not the same claim, and only the second one matters.
func TestDefaultPolicyBuildsNoController(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	if ctl := applySendBufPolicy(client, resolveSendBufPolicy("")); ctl != nil {
		t.Error("unset built a send-buffer controller")
	}
	if ctl := applySendBufPolicy(client, resolveSendBufPolicy("0")); ctl != nil {
		t.Error(`"0" built a send-buffer controller`)
	}
	if ctl := applySendBufPolicy(client, resolveSendBufPolicy("262144")); ctl != nil {
		t.Error("a pinned size built a controller; pinned means pinned, not adapted")
	}
	if ctl := applySendBufPolicy(client, resolveSendBufPolicy("adaptive")); ctl == nil {
		t.Error(`"adaptive" built no controller; the opt-in does nothing`)
	}
}
