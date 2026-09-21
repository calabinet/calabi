package relay

import (
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// serveHub starts a hub on a loopback listener and returns its address.
func serveHub(t *testing.T) (*Hub, string) {
	t.Helper()
	h := NewHub(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})), AuthConfig{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h.Serve(conn)
		}
	}()
	return h, ln.Addr().String()
}

// The defect this pins: forward() used to write to the destination inline, on
// the SOURCE's read goroutine. A destination that stopped reading therefore
// stopped the relay from reading its source at all — so one stalled peer took
// down that source's traffic to every OTHER peer with it.
//
// In the field this presented as the sender being throttled to 3.3 Mbit/s on a
// 20 Mbit/s link and shedding 70% of its packets, with the relay and the far end
// both reporting no loss of their own. Nothing looked broken anywhere; the
// sender was simply never allowed to write.
func TestOneStalledPeerDoesNotStallTheSourcesOtherTraffic(t *testing.T) {
	h, addr := serveHub(t)
	keyA, keyStalled, keyLive := key(1), key(2), key(3)

	src := dialFramed(t, addr, keyA)
	stalled := dialFramed(t, addr, keyStalled) // connects and then never reads
	live := dialFramed(t, addr, keyLive)
	waitConnected(t, h, keyA)
	waitConnected(t, h, keyStalled)
	waitConnected(t, h, keyLive)

	// Far more than any socket buffer on either side will hold, so the relay
	// genuinely cannot write it all to the stalled peer.
	const flood = 4000
	payload := make([]byte, 1280)
	for i := 0; i < flood; i++ {
		if err := meshproto.WriteDERPFrame(src, meshproto.DERPFrameSendPacket,
			meshproto.EncodePacket(keyStalled, payload)); err != nil {
			t.Fatalf("write %d to the stalled peer: %v", i, err)
		}
	}

	// The point of the test: with the stalled peer's queue full, traffic from the
	// SAME source to a healthy peer must still get through.
	marker := []byte("still moving")
	if err := meshproto.WriteDERPFrame(src, meshproto.DERPFrameSendPacket,
		meshproto.EncodePacket(keyLive, marker)); err != nil {
		t.Fatalf("write to the live peer: %v", err)
	}

	_ = live.SetReadDeadline(time.Now().Add(5 * time.Second))
	typ, got, err := meshproto.ReadDERPFrame(live)
	if err != nil {
		t.Fatalf("the live peer received nothing while another peer was stalled: %v", err)
	}
	if typ != meshproto.DERPFrameRecvPacket {
		t.Fatalf("frame type %v, want RecvPacket", typ)
	}
	_, ciphertext, err := meshproto.SplitPacket(got)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if string(ciphertext) != string(marker) {
		t.Errorf("live peer got %q, want %q", ciphertext, marker)
	}

	// And the stalled peer's backlog was shed rather than held: this is the
	// congestion signal, and it is what keeps the memory bounded.
	if n := h.lookup(keyStalled).sendq.Dropped(); n == 0 {
		t.Error("nothing was dropped for a peer that never read; the backlog is being held somewhere")
	}
	_ = stalled
}

// The negative, and the one that matters most: on a destination that keeps up,
// NOTHING is dropped. A relay that shed packets on a healthy link would be a
// rate limit wearing a congestion-control costume.
//
// The sender PACES ITSELF against what the destination has acknowledged, and
// that is the whole difference between this test measuring the relay and it
// measuring the machine. Writing all n frames as fast as the source socket
// accepts them does not make the destination "keep up" — it makes it race the
// hub's read goroutine for a CPU. Lose that race for sendQueueDepth frames in
// a row and the queue overflows, which is the relay doing exactly what it is
// designed to do. On a 2-core shared CI runner that is not a remote
// possibility: it is what happened, 70 frames of 3000 (2026-09-20).
//
// Staying a few hundred frames behind the reader keeps the queue from ever
// filling, so a drop here means the forwarding path dropped something it had
// room for — which is the only thing this test was ever meant to catch.
func TestForwardDropsNothingWhenTheDestinationKeepsUp(t *testing.T) {
	h, addr := serveHub(t)
	keyA, keyB := key(1), key(2)

	src := dialFramed(t, addr, keyA)
	dst := dialFramed(t, addr, keyB)
	waitConnected(t, h, keyA)
	waitConnected(t, h, keyB)

	const n = 3000
	// Well under sendQueueDepth (512): the queue must never be the thing that
	// gives way, or the test is back to timing the scheduler.
	const maxInFlight = 128

	payload := make([]byte, 1280)
	var received atomic.Int64
	progress := make(chan struct{}, 1)
	done := make(chan int, 1)
	go func() {
		count := 0
		_ = dst.SetReadDeadline(time.Now().Add(30 * time.Second))
		for count < n {
			if _, _, err := meshproto.ReadDERPFrame(dst); err != nil {
				break
			}
			count++
			received.Store(int64(count))
			select {
			case progress <- struct{}{}:
			default: // the sender is already awake; nothing to report
			}
		}
		done <- count
	}()

	for i := 0; i < n; i++ {
		// Wait for the reader to come within maxInFlight before offering more.
		for int64(i)-received.Load() >= maxInFlight {
			select {
			case <-progress:
			case <-time.After(30 * time.Second):
				t.Fatalf("destination stopped reading at %d of %d", received.Load(), n)
			}
		}
		if err := meshproto.WriteDERPFrame(src, meshproto.DERPFrameSendPacket,
			meshproto.EncodePacket(keyB, payload)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	if got := <-done; got != n {
		t.Errorf("destination received %d of %d frames", got, n)
	}
	if dropped := h.lookup(keyB).sendq.Dropped(); dropped != 0 {
		t.Errorf("dropped %d frames to a destination that kept up, want 0", dropped)
	}
	// The rate limiter is another way to lose a frame on a healthy link, and it
	// is wired into the same forward(). An un-configured hub must refuse
	// nothing — if this ever trips, a limiter is being applied where no
	// allowance was ever installed.
	if refused := h.RefusedFrames(); refused != 0 {
		t.Errorf("refused %d frames with no rate limiter wired, want 0", refused)
	}
}

// Usage is credited for what was written, not for what was offered. Relayed
// bytes are billed (usage.go), and now that the relay drops on purpose, billing
// a dropped frame would charge for bandwidth nobody used.
func TestDroppedFramesAreNotBilled(t *testing.T) {
	h, addr := serveHub(t)
	keyA, keyStalled := key(1), key(2)

	src := dialFramed(t, addr, keyA)
	_ = dialFramed(t, addr, keyStalled) // never reads
	waitConnected(t, h, keyA)
	waitConnected(t, h, keyStalled)

	const flood = 4000
	payload := make([]byte, 1280)
	for i := 0; i < flood; i++ {
		if err := meshproto.WriteDERPFrame(src, meshproto.DERPFrameSendPacket,
			meshproto.EncodePacket(keyStalled, payload)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	// WAIT for the hub to catch up, rather than reading straight after our own
	// writes. `WriteDERPFrame` returning only means the bytes reached the SOURCE
	// socket's send buffer; the hub's reader goroutine has still to pick them up
	// and enqueue them before any drop can be recorded. Reading Dropped() here
	// asserted a state that had not been established yet, and on a loaded 2-core
	// CI runner the reader lagged far enough that it was still 0 — the test went
	// red on a machine, not on a defect.
	//
	// Settling (no change across consecutive polls) rather than just "> 0", so
	// `dropped` and the usage read below describe the same moment: the billing
	// bound is computed from both.
	dropped := waitDropsSettle(t, h.lookup(keyStalled).sendq)
	if dropped == 0 {
		t.Fatal("expected drops to a peer that never read")
	}

	var out uint64
	for _, d := range h.TakeUsage() {
		if d.Key == keyStalled {
			out = d.BytesOut
		}
	}
	if maxBilled := uint64(flood-int(dropped)) * uint64(len(payload)); out > maxBilled {
		t.Errorf("billed %d egress bytes for the stalled peer but only %d frames were written (max %d bytes)",
			out, flood-int(dropped), maxBilled)
	}
}

// waitDropsSettle returns the queue's drop count once it has stopped moving —
// the hub has read what we wrote and the send queue has shed what it will shed.
// It gives up after the deadline and returns what it has, so a genuine "no
// drops at all" still reaches the caller's assertion instead of timing out into
// an unrelated failure.
func waitDropsSettle(t *testing.T, q *sendQueue) uint64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	last, stable := q.Dropped(), 0
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		n := q.Dropped()
		if n == last && n > 0 {
			if stable++; stable == 3 {
				return n
			}
			continue
		}
		last, stable = n, 0
	}
	return q.Dropped()
}

// The Ping echo is a load-bearing contract, not just a keepalive.
//
// `calabi mesh relaytest` drives one leg of the relay path by bouncing
// full-size frames off this handler: it is the only way to measure a single
// segment's capacity without a second node, WireGuard and a tun in the way. That
// makes two properties of this echo part of the protocol rather than an
// implementation detail — an arbitrary payload comes back BYTE-IDENTICAL, and a
// mesh-sized one is not refused. The existing coverage only ever echoed the
// 8-byte keepalive, which would not have caught either.
func TestPingEchoesFullSizePayloadsIntact(t *testing.T) {
	h, addr := serveHub(t)
	k := key(1)
	conn := dialFramed(t, addr, k)
	waitConnected(t, h, k)

	for _, size := range []int{8, 1200, 8192} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i * 7)
		}
		if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFramePing, payload); err != nil {
			t.Fatalf("ping %d B: %v", size, err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		typ, got, err := meshproto.ReadDERPFrame(conn)
		if err != nil {
			t.Fatalf("pong %d B: %v", size, err)
		}
		if typ != meshproto.DERPFramePong {
			t.Fatalf("frame type %v for a %d B ping, want Pong", typ, size)
		}
		if len(got) != size {
			t.Fatalf("pong is %d B for a %d B ping", len(got), size)
		}
		for i := range got {
			if got[i] != payload[i] {
				t.Fatalf("pong differs at byte %d for a %d B ping — the echo is not verbatim, "+
					"so a round-trip measurement built on it would be measuring something else", i, size)
			}
		}
	}
}
