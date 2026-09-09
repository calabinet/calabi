package derp

import (
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// The relay send queue — and why a VPN's relay must be allowed to DROP.
//
// WireGuard is a datagram tunnel. The TCP inside it discovers the path's
// capacity the only way TCP knows how: by losing a packet. The direct path
// gives it that for free — when a UDP socket's buffer fills, the kernel
// discards, and the inner TCP backs off.
//
// The relay is TCP, so it never loses anything. Every byte the sender offers is
// buffered somewhere and eventually delivered. That sounds like a feature and is
// the opposite: with nothing bounding the buffering, a sender that outruns the
// path just keeps filling. A live link was measured at 12.9 ms idle and
// 5,730 ms under load, 0% packet loss — nearly 2 MB of a bulk transfer sitting
// in queues, while the inner TCP, which reacts to loss and not to delay, kept
// adding more. Throughput 2.7 Mbit/s and latency five and a half seconds: both
// ends of the trade lost at once.
//
// So the queue is bounded, and the bound is TIME, not bytes.
//
// A byte bound cannot be right at more than one speed: 200 KB is 16 ms of a
// 100 Mbit/s path and 600 ms of a 2.7 Mbit/s one, and the whole problem is that
// we do not know which we are on. A deadline is the same rule at every speed —
// a packet that has waited longer than maxQueueDelay is dropped, because
// delivering it now is worse than not delivering it: the inner TCP gave up on
// it long ago, it still costs bandwidth, and carrying it is what hides the
// congestion signal that would have stopped the sender.
//
// On a path with room the queue drains as fast as it fills, no packet ever
// reaches the deadline, and nothing is dropped. This is not a rate limit. It
// bounds how long a packet may WAIT, not how fast packets may go.
//
// # WHAT THE DEADLINE MUST CLEAR, and what it was first sized against
//
// The first version of this used 100 ms, argued as "well above the RTT of any
// relay worth using (a bad one measured 13 ms)". RTT is the wrong quantity. The
// writer is not waiting for a round trip; it is waiting for the RELAY LINK'S TCP
// to hand back its send buffer, and on a lossy path that wait is dominated by
// loss recovery, not by propagation. Linux's minimum RTO is 200 ms — twice the
// deadline that was supposed to have sevenfold margin.
//
// Measured on a real link (home uplink to a Chengdu relay, same path, same
// minute): plain iperf3 moved 33.8 MB in 15 s (18.9 Mbit/s) with 3,965
// retransmissions — 16.5% loss, cwnd pinned at 30-50 KB, a first-second burst of
// 62.8 Mbit/s collapsing to zero. A policed, badly lossy path. Through the SAME
// path this queue delivered 3.3 Mbit/s and shed 71% of what it was handed, with
// the writer blocked inside conn.Write for 14.7 of 15 seconds.
//
// The difference was not the path. iperf3's bytes wait however long recovery
// takes; ours were thrown away for being 100 ms old while the outer TCP was
// still working on them. Every recovery event cost a queue's worth of traffic,
// and the inner TCP then had to rediscover the same loss over the same stalling
// connection. Layering a deadline this short over a transport already doing its
// own reliable recovery discards the recovery instead of benefiting from it.
//
// So the deadline is a BACKSTOP against multi-second bufferbloat, not a
// fairness mechanism. It has to clear ordinary loss recovery and still sit an
// order of magnitude below the 5,730 ms this file exists to prevent.
//
// One thing this does NOT fix: a bulk transfer sharing the link still adds its
// whole queue to somebody's SSH latency. Protecting interactive traffic from a
// bulk flow needs per-flow queueing, which this does not have and a deadline
// cannot substitute for. Pretending otherwise is what produced the 100 ms.
const (
	// maxQueueDelay is how long a packet may sit before it is not worth sending.
	// 500 ms clears a Linux RTO (200 ms) and a backed-off second one, and is 11x
	// below the bufferbloat it guards against. Override in the field with
	// maxQueueDelayEnv rather than guessing at a better constant here.
	maxQueueDelay = 500 * time.Millisecond

	// sendQueueDepth caps the packets in flight to the writer. It is a backstop,
	// not the mechanism: the deadline does the work. Deep enough to absorb a
	// scheduler hiccup at a high packet rate, shallow enough that the memory is
	// uninteresting.
	sendQueueDepth = 512
)

// sendSockBufEnv decides the kernel send-buffer policy for every relay link.
// Four-way, and the DEFAULT IS TO DO NOTHING:
//
//	unset       leave the socket alone; the kernel auto-tunes  (default)
//	"0"         the same, said explicitly
//	"adaptive"  the controller in sndbuf.go
//	N           pin to N bytes and do not adapt
//
// Off by default on measured evidence, not caution -- see the header of
// sndbuf.go for the numbers. The short version: the queue this was built to
// bound turned out to be an ~11 s transient that BBR drains by itself, the
// steady state was already 88-193 ms, and the big win (5,730 ms -> that) had
// already been taken by the frame queue's deadline. A mechanism that disables
// the kernel's own BDP estimator for the life of every socket has to earn it,
// and on the link it was written for it did not.
const sendSockBufEnv = "CALABI_MESH_RELAY_SNDBUF"

// maxQueueDelayEnv overrides maxQueueDelay (a Go duration, e.g. "800ms", "2s").
// This number has now been wrong once because it was reasoned about instead of
// measured; the knob is here so the next correction costs a restart rather than
// a release. "0" disables shedding by age entirely, leaving only the depth
// backstop — useful for proving what the deadline is costing on a given path.
const maxQueueDelayEnv = "CALABI_MESH_RELAY_MAXDELAY"

// resolveMaxQueueDelay reads the override. Garbage or a negative value falls
// back to the default: a typo in an environment variable must not take the
// datapath down, for the same reason as resolveSendSockBuf.
func resolveMaxQueueDelay(env string) time.Duration {
	if env == "" {
		return maxQueueDelay
	}
	d, err := time.ParseDuration(env)
	if err != nil || d < 0 {
		return maxQueueDelay
	}
	return d
}

// queued is one frame waiting for the writer, with the time it was handed over.
type queued struct {
	frame []byte
	at    time.Time
}

// sendQueue hands frames to a writer goroutine, dropping what has waited too
// long. Both the enqueue side (any goroutine) and the drain side (one writer)
// are lock-free apart from the channel.
type sendQueue struct {
	ch      chan queued
	dropped atomic.Uint64
	// blocked is the cumulative time the writer has spent inside conn.Write.
	//
	// It answers the one question the drop count cannot: is the writer BLOCKED or
	// STARVED? Both look identical from outside — frames offered, frames shed,
	// low throughput — and they point at opposite investigations. Blocked for
	// most of the wall clock means the writer was waiting on the relay's TCP; it
	// does NOT say whether the link is slow or merely in loss recovery, and
	// reading it as the former is how the deadline above stayed wrong for a whole
	// round of measurements. Near zero means the writer sat idle while frames
	// were being dropped, which would mean the throttle is upstream of here and
	// nothing about this queue is the cause.
	blocked atomic.Int64
	now     func() time.Time // overridable in tests; nil means time.Now
	// deadline is maxQueueDelay after the environment has had its say. Resolved
	// once per link rather than read per packet. Zero disables shedding by age.
	deadline time.Duration
}

func newSendQueue() *sendQueue {
	return &sendQueue{
		ch:       make(chan queued, sendQueueDepth),
		deadline: resolveMaxQueueDelay(os.Getenv(maxQueueDelayEnv)),
	}
}

func (q *sendQueue) clock() time.Time {
	if q.now != nil {
		return q.now()
	}
	return time.Now()
}

// enqueue offers a frame to the writer. It never blocks: a full queue drops,
// exactly as a full UDP socket buffer does on the direct path. Blocking here
// would push the backlog one layer up into WireGuard and then into the tun,
// which is how the unbounded buffering happened in the first place.
func (q *sendQueue) enqueue(frame []byte) {
	select {
	case q.ch <- queued{frame: frame, at: q.clock()}:
	default:
		q.dropped.Add(1)
	}
}

// run drains the queue onto conn until a write fails or the link closes.
//
// It also measures itself: bytes out and time spent blocked, bucketed into
// windows and handed to ctl (nil = no adaptive sizing) so the kernel send buffer
// behind this socket can be sized from what the link actually does.
// sndbuf.go for why that measurement belongs here -- this loop is the only place
// that knows both how much went out and how hard it was to get it out.
func (q *sendQueue) run(conn net.Conn, wmu *sync.Mutex, closed <-chan struct{}, ctl *sndbufCtl) {
	tick := time.NewTicker(rateWindow)
	defer tick.Stop()
	var (
		winBytes   uint64
		winBlocked time.Duration
	)
	winStart := q.clock()
	for {
		select {
		case <-closed:
			return
		case <-tick.C:
			now := q.clock()
			if ctl != nil {
				elapsed := now.Sub(winStart)
				// The window measured the LINK if the writer was waiting on it for a
				// meaningful slice of the window, or if there is still a backlog it
				// has not reached. Otherwise the writer kept up and the number
				// measures how much the application felt like sending, which must not
				// be allowed to shrink the buffer -- see observeWindow.
				linkLimited := elapsed > 0 &&
					(winBlocked.Seconds() >= linkLimitedFrac*elapsed.Seconds() || len(q.ch) > 0)
				ctl.observeWindow(winBytes, elapsed, linkLimited)
			}
			winBytes, winBlocked, winStart = 0, 0, now
		case it := <-q.ch:
			// The deadline is checked on the way OUT, not on the way in: what
			// matters is how long the packet actually waited, which is only known
			// here. A queue that has fallen behind sheds its backlog on this line.
			if q.deadline > 0 && q.clock().Sub(it.at) > q.deadline {
				q.dropped.Add(1)
				continue
			}
			// Under wmu: control frames (Ping, an auth answer) are written
			// synchronously from other goroutines and must never interleave with a
			// data frame. Two concurrent Writes on one TCP connection may each be
			// split, and a split that interleaves desynchronises the framing for
			// the life of the link.
			wmu.Lock()
			t0 := time.Now()
			n, err := conn.Write(it.frame)
			blocked := time.Since(t0)
			q.blocked.Add(int64(blocked))
			wmu.Unlock()
			winBytes += uint64(n)
			winBlocked += blocked
			if err != nil {
				return // link is dead; Close/readLoop will clean up
			}
		}
	}
}

// Dropped is how many frames this link discarded rather than send late. It is
// reported (see DatapathStats): a drop we chose is exactly the kind of thing
// that must not be invisible, and if maxQueueDelay is wrong this is the number
// that will say so.
func (q *sendQueue) Dropped() uint64 { return q.dropped.Load() }

// Blocked is the cumulative time the writer has spent inside conn.Write.
func (q *sendQueue) Blocked() time.Duration { return time.Duration(q.blocked.Load()) }

// sendBufPolicy is what sendSockBufEnv says to do with the kernel send buffer.
// Exactly one of adaptive / pinned / neither is in force.
type sendBufPolicy struct {
	adaptive bool
	pinned   int // bytes; 0 = not pinned
}

// resolveSendBufPolicy reads the override. Anything unparseable falls back to
// the DEFAULT rather than failing: this is a knob on a data path, and refusing
// to carry traffic because an environment variable has a typo in it would be a
// far worse outcome than ignoring the typo. The default being "leave the socket
// alone" also means a typo cannot silently enable an experiment.
func resolveSendBufPolicy(env string) sendBufPolicy {
	switch env {
	case "":
		return sendBufPolicy{}
	case "adaptive":
		return sendBufPolicy{adaptive: true}
	}
	n, err := strconv.Atoi(env)
	if err != nil || n <= 0 {
		return sendBufPolicy{}
	}
	return sendBufPolicy{pinned: n}
}

// applySendBufPolicy sets a pinned buffer size if one was asked for, and returns
// the controller that will keep sizing it (nil when the policy is not adaptive).
func applySendBufPolicy(conn net.Conn, pol sendBufPolicy) *sndbufCtl {
	if pol.pinned > 0 {
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetWriteBuffer(pol.pinned)
		}
		return nil
	}
	if !pol.adaptive {
		return nil
	}
	return newSndbufCtl(conn)
}
