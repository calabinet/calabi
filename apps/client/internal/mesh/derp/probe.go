package derp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Driving ONE LEG of the relay path over a link that is already authenticated.
//
// `calabi mesh relaytest` originally opened its own connection to the relay with
// an ephemeral node key. That works only against a relay that does not require a
// coordinator grant, and the first real relay it met did require one: an
// ephemeral key cannot present a grant, and the node's REAL key cannot be used
// either, because the hub evicts whatever link currently holds a key when a new
// connection claims it — the probe would knock the daemon's own relay link
// offline to measure it.
//
// So the probe runs on the daemon's existing link instead. That is better than
// the workaround it replaces: it measures the connection actually carrying the
// node's traffic, on the real relay, with no second identity involved.
//
// It rides on Ping/Pong, which the relay echoes verbatim, and therefore does NOT
// pass through the send queue — Send() sheds by age, Ping() does not. That is
// deliberate: this measures the LINK and the relay's own loops, so that the
// queue's contribution can be told apart from the path's rather than mixed into
// one number. Under a bulk transfer the probe still waits on the write mutex the
// queue's writer holds, so a large blocked time here during load is real and
// worth reading.

// ProbeOpts configures one leg measurement.
type ProbeOpts struct {
	Size     int
	RateMbps float64 // 0 = as fast as the link takes
	Duration time.Duration
	// OneWay drives the SEND direction alone, with no return traffic at all.
	//
	// The echo mode measures a round trip, and a round trip through this relay
	// includes the relay writing the Pong back INSIDE its read loop — so a slow
	// return direction stops the relay reading, which stops our socket accepting,
	// which looks exactly like a slow send direction. The two need telling apart:
	// one is the network, the other is the relay's serialization.
	//
	// So OneWay sends packet frames addressed to a node key that is not connected.
	// The relay reads them, looks up a destination that does not exist, and drops
	// them (hub.forward) — no write back, no echo loop, nothing on the return
	// path. What is left is how fast this node can push frames INTO the relay.
	// There is no loss figure in this mode, by construction: nothing comes back to
	// count, which is the point.
	OneWay bool
}

// ProbeResult is one leg measurement.
type ProbeResult struct {
	Sent    uint64
	Echoed  uint64
	Bytes   uint64 // payload bytes sent (echoed bytes are the same size)
	Elapsed time.Duration
	Blocked time.Duration // cumulative time inside the send (mutex + write)
	RTTs    []time.Duration
	// OneWay records which mode produced this, so a reader cannot mistake the
	// absent echo for total loss.
	OneWay bool
}

// Loss is the fraction of probes that never came back, in percent.
func (r *ProbeResult) Loss() float64 {
	if r.Sent == 0 {
		return 0
	}
	return float64(r.Sent-r.Echoed) / float64(r.Sent) * 100
}

// Quantile returns the RTT at q (0.1). RTTs must be sorted; Probe sorts them.
//
// NEAREST-RANK, rounding UP. Truncating instead (idx = (n-1)*q) systematically
// under-reports the tail — with five samples it puts p90 on the fourth, so a
// single 900 ms outlier among 40 ms samples disappears. Surfacing that outlier
// is the entire reason to report a p90 rather than a mean, so the rounding has
// to lean the other way.
func (r *ProbeResult) Quantile(q float64) time.Duration {
	if len(r.RTTs) == 0 {
		return 0
	}
	idx := int(math.Ceil(q*float64(len(r.RTTs)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(r.RTTs) {
		idx = len(r.RTTs) - 1
	}
	return r.RTTs[idx]
}

// ErrProbeBusy is returned when a probe is already running on this link. One at
// a time: two would interleave their sequence numbers and both would be wrong.
var ErrProbeBusy = errors.New("derp: a probe is already running on this link")

// probeState is the live probe's collector, installed on the Client while it
// runs and read by the read loop.
type probeState struct {
	start time.Time
	mu    sync.Mutex
	rtts  []time.Duration
	count atomic.Uint64
	bytes atomic.Uint64
}

// observePong is called from the read loop for every Pong. It is a no-op when no
// probe is running, which is the normal case — the cost on the hot path is one
// atomic load.
func (c *Client) observePong(payload []byte) {
	p := c.probe.Load()
	if p == nil || len(payload) < 16 {
		return
	}
	// Nanoseconds since the probe's own start, not a wall-clock instant:
	// reconstructing an instant discards Go's monotonic reading, and the wall
	// clock's granularity is milliseconds on some hosts — enough to report a fast
	// round trip as exactly zero.
	sentAt := time.Duration(binary.BigEndian.Uint64(payload[8:16]))
	p.count.Add(1)
	p.bytes.Add(uint64(len(payload)))
	p.mu.Lock()
	p.rtts = append(p.rtts, time.Since(p.start)-sentAt)
	p.mu.Unlock()
}

// Probe drives the leg for opts.Duration and reports what came back.
func (c *Client) Probe(ctx context.Context, opts ProbeOpts) (*ProbeResult, error) {
	size, rateMbps, dur := opts.Size, opts.RateMbps, opts.Duration
	if size < 16 {
		size = 16
	}
	st := &probeState{start: time.Now()}
	if !c.probe.CompareAndSwap(nil, st) {
		return nil, ErrProbeBusy
	}
	defer c.probe.Store(nil)

	res := &ProbeResult{OneWay: opts.OneWay}
	payload := make([]byte, size)
	var gap time.Duration
	if rateMbps > 0 {
		fps := rateMbps * 1e6 / 8 / float64(size)
		gap = time.Duration(float64(time.Second) / fps)
	}
	deadline := st.start.Add(dur)
	next := st.start
	var seq uint64
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.closed:
			return nil, errors.New("derp: the relay link closed during the probe")
		default:
		}
		seq++
		binary.BigEndian.PutUint64(payload[0:8], seq)
		binary.BigEndian.PutUint64(payload[8:16], uint64(time.Since(st.start)))
		t0 := time.Now()
		if err := c.probeSend(opts.OneWay, payload); err != nil {
			break
		}
		res.Blocked += time.Since(t0)
		res.Sent++
		res.Bytes += uint64(size)
		if gap > 0 {
			next = next.Add(gap)
			if d := time.Until(next); d > 0 {
				timer := time.NewTimer(d)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return nil, ctx.Err()
				}
			}
		}
	}
	res.Elapsed = time.Since(st.start)

	// Let what is still in flight come back before calling it lost, or the tail of
	// every run reads as loss that is not there.
	select {
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
	}

	res.Echoed = st.count.Load()
	st.mu.Lock()
	res.RTTs = append([]time.Duration(nil), st.rtts...)
	st.mu.Unlock()
	sort.Slice(res.RTTs, func(i, j int) bool { return res.RTTs[i] < res.RTTs[j] })
	return res, nil
}

// probeSend puts one probe frame on the wire, synchronously and under the write
// mutex — the same path a keepalive takes, deliberately NOT the send queue,
// which sheds by age and would be measuring itself.
func (c *Client) probeSend(oneWay bool, payload []byte) error {
	if !oneWay {
		return c.Ping(payload)
	}
	// A destination the relay has no link for. It reads the frame, fails the
	// lookup, and drops it: no reply, no echo loop, nothing on the return path.
	// Random rather than all-zero so it cannot collide with a real node key that
	// some future test or fixture happens to use.
	var sink meshproto.NodeKey
	if _, err := rand.Read(sink[:]); err != nil {
		return err
	}
	frame, err := meshproto.EncodeDERPFrame(meshproto.DERPFrameSendPacket, meshproto.EncodePacket(sink, payload))
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err = c.conn.Write(frame)
	return err
}
