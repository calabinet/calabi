package relay

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// How fast can the relay actually forward?
//
// Nobody had ever asked. The relay was built and tested for CORRECTNESS — the
// right bytes reach the right key — and every test used net.Pipe, which is a
// synchronous in-memory channel with no send buffer and no MTU: it cannot show
// a throughput problem, because it has no throughput to lose. Meanwhile a real
// deployment measured 20 Mbit/s on each leg to the relay host and ~3 Mbit/s
// through the relay itself, and there was no way to tell whether that was the
// network or this code.
//
// This runs the real hub over a real loopback TCP socket with two real framed
// clients, so the answer is about the code and not about a pipe. It asserts a
// deliberately LOW floor: loopback should manage hundreds of Mbit/s, so a floor
// of 50 catches "something here is structurally slow" without turning into a
// flaky benchmark on a loaded CI box.
//
// The sender PACES ITSELF against what the receiver has read, never more than
// maxInFlight frames ahead. It used to write all 20,000 as fast as the socket
// would take them and allow up to 2% to be shed, on the theory that more would
// mean the writer could not keep up with the reader. What that measured was the
// scheduler. Both sides of the destination's queue run at nearly the same rate
// — the hub reading the sender, the writer feeding the receiver — so its depth
// wanders; 512 slots are a few milliseconds at loopback speed, and whether it
// overflowed was decided by whether the OS kept the writing side off a CPU for
// longer than that. Unchanged code shed anywhere from 0 to 1,170 frames and
// failed up to half its runs on a loaded 12-core box, at the same rate before
// the rate limiter went into forward() as after; on two cores with -race, the
// shape of a small CI runner, it shed a quarter of the stream or more, every
// time (2026-09-28). A check that is red that often on correct code says
// nothing when it goes red.
//
// Paced, the queue can never fill, so what is left to assert depends on the
// code alone: every frame arrives, and at loopback speed. Shedding under
// overload is pinned where it is deterministic, by a peer that never reads
// (headofline_test.go).
func TestRelayForwardingThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput test")
	}
	const (
		packets = 20000
		payload = 1280 // a WireGuard transport packet at the mesh's 1280 MTU
		floor   = 50.0 // Mbit/s
		// A quarter of the queue, so the frames sent and not yet read can never
		// outnumber its slots, however the goroutines are scheduled.
		maxInFlight = sendQueueDepth / 4
	)

	h := NewHub(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})), AuthConfig{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h.Serve(conn)
		}
	}()

	keyA, keyB := key(1), key(2)
	sender := dialFramed(t, ln.Addr().String(), keyA)
	receiver := dialFramed(t, ln.Addr().String(), keyB)
	waitConnected(t, h, keyA)
	waitConnected(t, h, keyB)
	q := h.lookup(keyB).sendq

	// Drain the receiver in its own goroutine: a receiver that stops reading is
	// measuring its own back-pressure, not the hub. Each frame it reads wakes the
	// sender, and it notes when the last one landed.
	var frames, got, lastArrival atomic.Int64
	progress := make(chan struct{}, 1)
	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		for frames.Load() < packets {
			_, p, err := meshproto.ReadDERPFrame(receiver)
			if err != nil {
				return
			}
			got.Add(int64(len(p) - meshproto.KeyLen))
			lastArrival.Store(int64(time.Since(start)))
			frames.Add(1)
			select {
			case progress <- struct{}{}:
			default: // the sender is already awake
			}
		}
	}()

	deadline := time.After(60 * time.Second)
	body := make([]byte, payload)
	for i := 0; i < packets; i++ {
		for int64(i)-frames.Load() >= maxInFlight {
			select {
			case <-progress:
			case <-deadline:
				t.Fatalf("stalled: sent %d, received %d, shed %d", i, frames.Load(), q.Dropped())
			}
		}
		if err := meshproto.WriteDERPFrame(sender, meshproto.DERPFrameSendPacket,
			meshproto.EncodePacket(keyB, body)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	// Everything should arrive. If some of it never will, stop once arrivals do,
	// so the check below says how much was lost instead of the deadline saying
	// only that something was.
	last, quiet := frames.Load(), 0
	for quiet < 4 {
		select {
		case <-done:
			quiet = 4
		case <-deadline:
			t.Fatalf("stalled: received %d of %d frames, shed %d", frames.Load(), packets, q.Dropped())
		case <-time.After(100 * time.Millisecond):
			if n := frames.Load(); n == last {
				quiet++
			} else {
				last, quiet = n, 0
			}
		}
	}
	// Timed to the last arrival, not to the end of the wait above. Dividing by a
	// window that included the wait for silence is how runs that moved at ~750
	// Mbit/s came to be reported as ~250.
	elapsed := time.Duration(lastArrival.Load())

	delivered := got.Load()
	shed := q.Dropped()
	mbps := float64(delivered) * 8 / elapsed.Seconds() / 1e6
	t.Logf("relayed %d of %d packets (%d B each) in %v — %.1f Mbit/s, %.0f pkt/s, %d shed",
		delivered/payload, packets, payload, elapsed.Round(time.Millisecond), mbps,
		float64(delivered/payload)/elapsed.Seconds(), shed)
	if mbps < floor {
		t.Errorf("forwarding throughput %.1f Mbit/s is below the %.0f Mbit/s floor — on LOOPBACK, "+
			"which means the cost is in this code, not the network", mbps, floor)
	}
	// The queue had room for this whole stream, so no frame of it was the
	// backstop's to shed. Counted by what ARRIVED rather than by Dropped(): a
	// frame the forwarding path loses without counting it is lost all the same.
	if n := frames.Load(); n != packets {
		t.Errorf("delivered %d of %d frames (%d counted as shed) with never more than %d in flight — "+
			"the %d-slot queue had room for every one, so the forwarding path lost them",
			n, packets, shed, maxInFlight, sendQueueDepth)
	}
}

func dialFramed(t *testing.T, addr string, k meshproto.NodeKey) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFrameClientInfo, k[:]); err != nil {
		t.Fatalf("client info: %v", err)
	}
	return conn
}

func waitConnected(t *testing.T, h *Hub, k meshproto.NodeKey) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !h.Connected(k) {
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for client registration")
		}
		time.Sleep(time.Millisecond)
	}
}

// The same measurement with LATENCY in the path.
//
// The loopback number above is ~338 Mbit/s, which says the forwarding core is
// not structurally slow — but loopback has no round-trip time, and that is
// exactly the dimension a real relay lives in. A design that is fine at 0 ms and
// collapses at 20 ms is a design whose throughput is bounded by a window rather
// than by work, and no amount of loopback testing would ever show it.
//
// Each direction is passed through a delay line with effectively unlimited
// bandwidth, so the only thing being added is time.
func TestRelayForwardingThroughputWithLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput test")
	}
	for _, oneWay := range []time.Duration{time.Millisecond, 5 * time.Millisecond, 20 * time.Millisecond} {
		t.Run(oneWay.String(), func(t *testing.T) {
			mbps, dropped := relayThroughput(t, 4000, 1280, oneWay)
			t.Logf("one-way %v (RTT %v): %.1f Mbit/s delivered, %d frames shed", oneWay, 2*oneWay, mbps, dropped)
		})
	}
}

// relayThroughput forwards `packets` payloads of `payload` bytes through a real
// hub whose client links carry `oneWay` of latency. It returns the DELIVERED
// throughput in Mbit/s and how many frames the relay shed.
//
// It does not wait for every byte, and must not: the hub sheds a backlog it
// cannot deliver within maxQueueDelay (sendq.go), so on a destination link
// slower than the sender — which this harness's delay line is — some frames are
// dropped on purpose. Waiting for a byte count that will never arrive is how
// this test failed when the queue landed. What is worth measuring here is what
// gets THROUGH, so the run ends when the stream goes quiet after the sender has
// finished.
//
// And it is timed to the last frame that arrived, not to when the quiet was
// noticed. With the wait for silence in the denominator, every run that shed a
// frame reported about 30 Mbit/s — at 20 ms one-way, the very collapse this
// test is here to rule out — while runs that shed nothing showed 450 to 630.
func relayThroughput(t *testing.T, packets, payload int, oneWay time.Duration) (float64, uint64) {
	t.Helper()
	h := NewHub(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})), AuthConfig{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h.Serve(conn)
		}
	}()

	keyA, keyB := key(1), key(2)
	sender := dialDelayed(t, ln.Addr().String(), keyA, oneWay)
	receiver := dialDelayed(t, ln.Addr().String(), keyB, oneWay)
	waitConnected(t, h, keyA)
	waitConnected(t, h, keyB)

	var got, lastArrival atomic.Int64
	done := make(chan struct{})
	var once sync.Once
	start := time.Now()
	go func() {
		defer once.Do(func() { close(done) })
		for {
			_, p, err := meshproto.ReadDERPFrame(receiver)
			if err != nil {
				return
			}
			lastArrival.Store(int64(time.Since(start)))
			if got.Add(int64(len(p)-meshproto.KeyLen)) >= int64(packets)*int64(payload) {
				return
			}
		}
	}()

	body := make([]byte, payload)
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for i := 0; i < packets; i++ {
			if err := meshproto.WriteDERPFrame(sender, meshproto.DERPFrameSendPacket,
				meshproto.EncodePacket(keyB, body)); err != nil {
				return
			}
		}
	}()

	deadline := time.After(120 * time.Second)
	select {
	case <-sent:
	case <-done:
	case <-deadline:
		t.Fatalf("sender stalled: relayed %d of %d bytes", got.Load(), int64(packets)*int64(payload))
	}
	// Everything offered is now in the pipe. Give it time to drain, and stop once
	// arrivals stop: whatever has not shown up by then was shed, which is the
	// design and not a failure.
	last, quiet := got.Load(), 0
	for quiet < 4 {
		select {
		case <-done:
			quiet = 4
		case <-deadline:
			t.Fatalf("stalled while draining: relayed %d of %d bytes", got.Load(), int64(packets)*int64(payload))
		case <-time.After(250 * time.Millisecond):
			if n := got.Load(); n == last {
				quiet++
			} else {
				last, quiet = n, 0
			}
		}
	}
	elapsed := time.Duration(lastArrival.Load())
	var dropped uint64
	if c := h.lookup(keyB); c != nil {
		dropped = c.sendq.Dropped()
	}
	if got.Load() == 0 {
		t.Fatal("nothing was relayed at all")
	}
	return float64(got.Load()) * 8 / elapsed.Seconds() / 1e6, dropped
}

// dialDelayed connects to addr through a delay line that holds every byte for
// `oneWay` in each direction.
func dialDelayed(t *testing.T, addr string, k meshproto.NodeKey, oneWay time.Duration) net.Conn {
	t.Helper()
	mine, proxySide := net.Pipe()
	up, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = up.Close(); _ = mine.Close() })
	go delayCopy(up, proxySide, oneWay)
	go delayCopy(proxySide, up, oneWay)
	if err := meshproto.WriteDERPFrame(mine, meshproto.DERPFrameClientInfo, k[:]); err != nil {
		t.Fatalf("client info: %v", err)
	}
	return mine
}

// delayCopy copies src→dst, holding each chunk for `delay`. The queue is deep
// enough to be effectively unlimited bandwidth: the only thing added is time.
func delayCopy(dst io.Writer, src io.Reader, delay time.Duration) {
	type chunk struct {
		b  []byte
		at time.Time
	}
	ch := make(chan chunk, 8192)
	go func() {
		defer close(ch)
		buf := make([]byte, 64<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				ch <- chunk{b, time.Now().Add(delay)}
			}
			if err != nil {
				return
			}
		}
	}()
	for c := range ch {
		if d := time.Until(c.at); d > 0 {
			time.Sleep(d)
		}
		if _, err := dst.Write(c.b); err != nil {
			return
		}
	}
}
