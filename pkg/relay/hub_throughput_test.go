package relay

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
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
func TestRelayForwardingThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput test")
	}
	const (
		packets = 20000
		payload = 1280 // a WireGuard transport packet at the mesh's 1280 MTU
		floor   = 50.0 // Mbit/s
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

	// Drain the receiver in its own goroutine: a receiver that stops reading is
	// measuring its own back-pressure, not the hub.
	var got atomic.Int64
	done := make(chan struct{})
	var once sync.Once
	go func() {
		defer once.Do(func() { close(done) })
		for {
			_, p, err := meshproto.ReadDERPFrame(receiver)
			if err != nil {
				return
			}
			if got.Add(int64(len(p)-meshproto.KeyLen)) >= int64(packets)*payload {
				return
			}
		}
	}()

	body := make([]byte, payload)
	start := time.Now()
	for i := 0; i < packets; i++ {
		if err := meshproto.WriteDERPFrame(sender, meshproto.DERPFrameSendPacket,
			meshproto.EncodePacket(keyB, body)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	// Stop when everything has arrived OR when arrivals stop. Waiting for the full
	// byte count was wrong: this hub sheds on purpose (sendq.go), and a 20,000-frame
	// blast at line rate can overrun a 512-slot queue during one scheduler hiccup —
	// 35 frames of 20,000 in the run that caught this. The test passed for a while
	// because that had not happened yet, which is the least useful kind of green.
	deadline := time.After(60 * time.Second)
	last, quiet := got.Load(), 0
	for quiet < 4 {
		select {
		case <-done:
			quiet = 4
		case <-deadline:
			t.Fatalf("stalled: relayed %d of %d bytes", got.Load(), int64(packets)*payload)
		case <-time.After(100 * time.Millisecond):
			if n := got.Load(); n == last {
				quiet++
			} else {
				last, quiet = n, 0
			}
		}
	}
	elapsed := time.Since(start)

	delivered := got.Load()
	shed := h.lookup(keyB).sendq.Dropped()
	mbps := float64(delivered) * 8 / elapsed.Seconds() / 1e6
	t.Logf("relayed %d of %d packets (%d B each) in %v — %.1f Mbit/s, %.0f pkt/s, %d shed",
		delivered/payload, packets, payload, elapsed.Round(time.Millisecond), mbps,
		float64(delivered/payload)/elapsed.Seconds(), shed)
	if mbps < floor {
		t.Errorf("forwarding throughput %.1f Mbit/s is below the %.0f Mbit/s floor — on LOOPBACK, "+
			"which means the cost is in this code, not the network", mbps, floor)
	}
	// Shedding a little under a full-rate blast is the depth backstop doing its
	// job; shedding a lot would mean the writer cannot keep up with the reader on
	// loopback, which would be a defect in the forwarding path itself.
	if shed > uint64(packets)/50 {
		t.Errorf("shed %d of %d frames on loopback (>2%%) — the writer is not keeping up with the reader",
			shed, packets)
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

	var got atomic.Int64
	done := make(chan struct{})
	var once sync.Once
	go func() {
		defer once.Do(func() { close(done) })
		for {
			_, p, err := meshproto.ReadDERPFrame(receiver)
			if err != nil {
				return
			}
			if got.Add(int64(len(p)-meshproto.KeyLen)) >= int64(packets)*int64(payload) {
				return
			}
		}
	}()

	body := make([]byte, payload)
	start := time.Now()
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
	elapsed := time.Since(start)
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
