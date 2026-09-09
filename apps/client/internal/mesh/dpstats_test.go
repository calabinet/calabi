package mesh

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// The inbound queue's overflow drop is the one place this datapath discards
// traffic of its own accord. It spent its whole life as a bare `default:` with a
// comment claiming WireGuard would retransmit — it does not, for transport data —
// so every packet lost there was a hole the inner TCP had to find by timeout,
// and nothing anywhere counted it. This pins that it is counted, because an
// uncounted drop makes the entire datapath unfalsifiable: "is this us or the
// network?" had no answer.
func TestQueueOverflowIsCounted(t *testing.T) {
	b := newMeshBind(meshproto.NodeKey{}, nil)
	// Never Opened, so nothing drains: the queue fills to capacity and every
	// packet after that must be counted as dropped.
	const sent = 400
	for i := 0; i < sent; i++ {
		b.enqueue(&meshEndpoint{b: b}, []byte{1, 2, 3})
	}

	var st DatapathStats
	b.stats(&st)
	if st.QueueCap == 0 {
		t.Fatal("queue cap reported as 0")
	}
	if st.QueueDepth != st.QueueCap {
		t.Errorf("queue depth %d, want it full at %d", st.QueueDepth, st.QueueCap)
	}
	if want := uint64(sent - st.QueueCap); st.QueueDropped != want {
		t.Errorf("dropped %d, want %d (sent %d into a queue of %d)",
			st.QueueDropped, want, sent, st.QueueCap)
	}
}

// Inbound is split by transport so a stream carried over BOTH — which is what a
// flickering direct path does, and what reorders a TCP stream badly enough to
// collapse it — is visible as a number rather than only as reordering in a
// capture.
func TestInboundIsSplitByTransport(t *testing.T) {
	b := newMeshBind(meshproto.NodeKey{}, nil)
	b.deliver(meshproto.NodeKey{}, []byte{1})
	b.deliver(meshproto.NodeKey{}, []byte{2})
	b.deliverDirect(netip.MustParseAddrPort("192.0.2.1:1234"), []byte{3})

	var st DatapathStats
	b.stats(&st)
	if st.RxRelay != 2 || st.RxDirect != 1 {
		t.Errorf("rx direct=%d relay=%d, want 1 and 2", st.RxDirect, st.RxRelay)
	}
}

// The ladder exists because the platforms disagree about an over-large request:
// Linux clamps and reports success, the BSDs refuse outright and leave the old
// value. On a BSD a single large SetReadBuffer therefore does NOTHING, silently,
// on exactly the platform that needs it most — so the walk has to keep stepping
// down until one sticks, and stop at the first that does.
func TestSocketBufferLadderStopsAtTheFirstAcceptedSize(t *testing.T) {
	const cap = 1 << 20
	calls := 0
	got := applyLadder(func(n int) error {
		calls++
		if n > cap {
			return errors.New("ENOBUFS")
		}
		return nil
	})
	if got != cap {
		t.Errorf("settled on %d, want %d", got, cap)
	}
	// One call per rung above the cap, plus the one that succeeded.
	want := 1
	for _, n := range sockBufLadder {
		if n > cap {
			want++
		}
	}
	if calls != want {
		t.Errorf("made %d calls, want %d (it must stop at the first success)", calls, want)
	}
}

func TestSocketBufferLadderReportsTotalFailure(t *testing.T) {
	if got := applyLadder(func(int) error { return errors.New("nope") }); got != 0 {
		t.Errorf("got %d, want 0 when every size is refused", got)
	}
}

// The getsockopt shim is per-OS (sockbuf_unix.go / sockbuf_windows.go) and its
// only job is to return a real number. A zero here means the platform build is
// wrong and every buffer would be reported as "?" — which reads as "we don't
// know" and would quietly retire the one line that explains kernel-level loss.
func TestReadSocketBuffersReturnsRealSizes(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Skipf("no UDP socket available: %v", err)
	}
	defer c.Close()

	// Deliberately NOT asserting that tuning made it bigger: on a stock Linux box
	// net.core.rmem_max equals the default receive buffer, so the raise is a no-op
	// there and the same assertion would pass on macOS and fail in CI. A test
	// whose verdict is decided by the host's sysctls is not testing this code.
	got := tuneSocketBuffers(c, nil)
	if got.Read <= 0 || got.Write <= 0 {
		t.Errorf("buffer sizes read back as rx=%d tx=%d, want both > 0", got.Read, got.Write)
	}
}

// The socket counters live on the magicSock, which is REBUILT on every
// control-plane reconnect. The bind's are not. A live daemon was seen reporting
// rx_direct 369,320 against sock_rx_packets 112,427 — impossible, and it makes
// the whole "sender sent N, receiver's socket saw M" comparison worthless right
// when someone needs it. Absolute totals that walk backwards are worse than no
// totals, because nothing about them looks wrong.
func TestSocketCountersSurviveASocketRebuild(t *testing.T) {
	b := newMeshBind(meshproto.NodeKey{}, nil)

	first, err := newMagicSock(DiscoPrivateKey{}, nil)
	if err != nil {
		t.Skipf("no UDP socket available: %v", err)
	}
	defer first.Close()
	b.attachDirect(first, nil)
	first.rxPackets.Add(100)
	first.txPackets.Add(70)

	var before DatapathStats
	b.stats(&before)
	if before.SockRxPackets != 100 || before.SockTxPackets != 70 {
		t.Fatalf("live socket: rx=%d tx=%d, want 100 and 70", before.SockRxPackets, before.SockTxPackets)
	}

	// A reconnect: brand-new socket, counters back at zero.
	second, err := newMagicSock(DiscoPrivateKey{}, nil)
	if err != nil {
		t.Skipf("no second UDP socket: %v", err)
	}
	defer second.Close()
	b.attachDirect(second, nil)
	second.rxPackets.Add(5)

	var after DatapathStats
	b.stats(&after)
	if after.SockRxPackets != 105 {
		t.Errorf("after rebuild: sock_rx_packets = %d, want 105 (100 retired + 5 live)", after.SockRxPackets)
	}
	if after.SockTxPackets != 70 {
		t.Errorf("after rebuild: sock_tx_packets = %d, want 70 carried over", after.SockTxPackets)
	}
	// The invariant that broke in the field: what we handed to WireGuard can
	// never exceed what the socket read.
	if after.RxDirect > after.SockRxPackets {
		t.Errorf("rx_direct %d > sock_rx_packets %d — the impossible state is back",
			after.RxDirect, after.SockRxPackets)
	}
}
