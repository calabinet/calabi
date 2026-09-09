package relay

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Why a relay must not write on the goroutine that reads.
//
// forward() used to write the packet to its destination inline, on the source
// link's read goroutine:
//
//	read a frame from A  ->  write it to B  ->  read the next frame from A
//
// That makes B's speed A's speed. When B's socket buffer fills, the write
// blocks, the relay stops reading from A, A's TCP window closes, and A's sender
// is throttled to whatever B can absorb — for ALL of A's peers, not just B.
// A field measurement of one such link: the sender offered 10 Mbit/s, wrote
// 4,971 frames in 15 s (3.3 Mbit/s) and shed 11,446 as stale, while the relay
// and the receiver together lost 33. None of the loss was the network's. The
// sender was simply not allowed to write faster, and the reason was here.
//
// So each destination gets its own writer and its own queue, and the queue is
// bounded by TIME.
//
// A byte bound cannot be right at more than one speed: 200 KB is 16 ms of a
// 100 Mbit/s path and 600 ms of a 2.7 Mbit/s one, and a relay has no idea which
// of those its clients are on. A deadline is the same rule at every speed. A
// frame that has waited longer than maxQueueDelay is dropped, because sending it
// now is worse than not sending it: the TCP inside the tunnel gave up on it long
// ago, it still costs the relay's bandwidth, and carrying it is precisely what
// hides the congestion signal that would have slowed the sender down.
//
// On a link with room the queue drains as fast as it fills and nothing is ever
// dropped. This is not a rate limit — it bounds how long a frame may WAIT, not
// how fast frames may go.
//
// This mirrors the client's apps/client/internal/mesh/derp/sendq.go. The two are
// separate copies because pkg/relay is its own module and depends on nothing but
// pkg/mesh-proto and the standard library, which is what lets a user run the
// relay on their own VPS. The policy is deliberately identical; if one deadline
// changes the other should be revisited.
// WHAT THE DEADLINE MUST CLEAR
//
// It was 100 ms, argued against the RTT of a relay link. RTT is the wrong
// quantity: the writer is waiting for TCP to hand its send buffer back, and on a
// lossy path that wait is loss recovery, not propagation. Linux's minimum RTO is
// 200 ms — twice the deadline that was meant to have margin.
//
// Measured on the client side of a real link: plain iperf3 moved 18.9 Mbit/s
// over a path with 16.5% loss, while this queue's twin delivered 3.3 Mbit/s and
// shed 71%, because iperf3's bytes wait for recovery and ours were discarded
// mid-recovery for being 100 ms old. A deadline layered over a transport already
// doing reliable recovery must not throw that recovery away.
//
// So: a backstop against multi-second bufferbloat, sized to clear ordinary loss
// recovery. It is NOT a fairness mechanism — a bulk transfer still adds its
// queue to an interactive flow's latency, and only per-flow queueing fixes that.
const (
	// maxQueueDelay is how long a frame may sit before it is not worth sending.
	// 500 ms clears a Linux RTO and a backed-off second one, and stays an order of
	// magnitude below the bufferbloat it guards against.
	maxQueueDelay = 500 * time.Millisecond

	// sendQueueDepth bounds MEMORY for a peer that has stopped reading, and that
	// is all it is for: the deadline does the latency work.
	//
	// It is not "deep enough to absorb a scheduler hiccup", which an earlier
	// comment claimed. At the ~100k frames/s this hub forwards on loopback, 512
	// slots is about 5 ms of grace, and a 20,000-frame blast overruns it during
	// one ordinary scheduling gap. That is the backstop working — the drops are
	// counted — but a fixed depth is a different amount of time at every rate, so
	// on a fast link it, not the deadline, is what binds. Deepening it would cost
	// real memory on a relay holding many links, so it stays, and Dropped() is
	// what will say if it ever matters in the field.
	sendQueueDepth = 512
)

// queuedFrame is one encoded frame waiting for its destination's writer.
type queuedFrame struct {
	frame []byte
	at    time.Time
	// credit is the ciphertext byte count to bill once the frame is actually
	// written. Usage is counted on success only — a frame we chose to drop cost
	// the platform nothing, and now that dropping is deliberate that distinction
	// matters more, not less (see usage.go).
	credit uint64
}

// sendQueue feeds one destination link from any number of source goroutines.
type sendQueue struct {
	ch      chan queuedFrame
	dropped atomic.Uint64
	now     func() time.Time // overridable in tests; nil means time.Now
}

func newSendQueue() *sendQueue { return &sendQueue{ch: make(chan queuedFrame, sendQueueDepth)} }

func (q *sendQueue) clock() time.Time {
	if q.now != nil {
		return q.now()
	}
	return time.Now()
}

// enqueue offers a frame to the destination's writer. It never blocks: blocking
// here would put the head-of-line stall back on the source's read goroutine,
// which is the whole thing this exists to remove.
func (q *sendQueue) enqueue(frame []byte, credit uint64) {
	select {
	case q.ch <- queuedFrame{frame: frame, at: q.clock(), credit: credit}:
	default:
		q.dropped.Add(1)
	}
}

// run drains the queue onto the link until a write fails or the link closes.
// Writes take wmu because control frames (a Pong, an auth challenge) are written
// synchronously from other goroutines and must not interleave with a data frame
// — two concurrent Writes on one TCP connection may each be split, and a split
// that interleaves corrupts the framing for good.
func (q *sendQueue) run(conn net.Conn, wmu *sync.Mutex, usage *usageCounter, closed <-chan struct{}) {
	for {
		select {
		case <-closed:
			return
		case it := <-q.ch:
			// Checked on the way OUT, not the way in: how long the frame actually
			// waited is only known here. A queue that has fallen behind sheds its
			// backlog on this line.
			if q.clock().Sub(it.at) > maxQueueDelay {
				q.dropped.Add(1)
				continue
			}
			wmu.Lock()
			_, err := conn.Write(it.frame)
			wmu.Unlock()
			if err != nil {
				return // link is dead; Serve's read loop sees it too and cleans up
			}
			if usage != nil {
				usage.out.Add(it.credit)
			}
		}
	}
}

// Dropped is how many frames this link discarded rather than deliver late. A
// deliberate drop is the last thing that should be invisible: if maxQueueDelay
// is wrong, this is the number that will say so.
func (q *sendQueue) Dropped() uint64 { return q.dropped.Load() }
