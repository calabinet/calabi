package mesh

import (
	"context"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Client-side rate limiting for relayed mesh traffic.
//
// The platform relay enforces the same allowance and will simply drop what it
// will not carry. This exists so the drop never has to happen: a WireGuard
// tunnel is a datagram path, the TCP inside it only notices loss, and loss
// costs a round trip plus a halved congestion window. Slowing the SENDER down
// instead costs nothing.
//
// WHERE THE BRAKE IS, AND WHY IT IS NOT WHERE THE DECISION IS
//
// Only meshBind.send knows whether a packet is going out over the relay or over
// a punched direct path — it picks per packet. But blocking there does not slow
// anything down: wireguard-go's per-peer staging queue drops its oldest batch
// when it fills (device/send.go StagePackets), so the pressure never reaches
// the kernel and we would be back to losing packets, just earlier.
//
// The only place that CAN push back is the tun read: stop reading, and the
// kernel's tun queue fills, and the sending socket's buffer fills, and the
// application's write() blocks. No loss anywhere.
//
// So the two are split. The bind CHARGES (it knows), the tun reader PAYS (it
// can). What crosses between them is a byte count.
//
// Three things fall out of charging at the bind, all of which the earlier
// design had to handle separately:
//
//   - no overlay-IP-to-peer table is needed to tell relayed traffic from
//     direct: the bind already made that choice;
//   - the byte count is CIPHERTEXT, which is exactly what the relay meters, so
//     both ends of the enforcement agree to the byte without a conversion;
//   - handshakes and keepalives are counted too. They never pass through the
//     tun (the device generates them), so a tun-side meter would have missed
//     them — and then the relay's bucket, which does see them, would run out
//     first and drop one. Dropping a handshake costs five seconds.
//
// Paying one batch late is deliberate. A token bucket already tolerates a
// burst; letting the first batch through and settling before the next one is
// within that tolerance, and it keeps the charge off the send path.

// relayBurstSeconds sizes the sustained bucket = peak × this, mirroring
// calabi-edge's DefaultPeakBurstSeconds so a client and the relay that polices
// it agree on how long a burst may last. Drift here shows up as the relay
// dropping frames a client thought it was entitled to send.
const relayBurstSeconds = 300

// relayMinBurstBytes keeps a bucket usable at small rates, and must stay above
// the largest frame we ever charge in one go.
const relayMinBurstBytes = 64 * 1024

// relayRateBytesPerSec converts a coordinator's kbps into the bytes/sec the
// buckets work in. ×1024/8 — the SAME convention calabi-edge's quotaclient uses,
// which is what makes the rate a client paces itself by and the rate the relay
// polices it by the same number rather than a 2.4% argument.
func relayRateBytesPerSec(kbps uint32) int64 { return int64(kbps) * 1024 / 8 }

// relayMeter accumulates relayed ciphertext bytes and makes the tun reader wait
// for them. The zero value is a working no-op: no rate installed = no waiting,
// which is what a client gets from a coordinator that sends no allowance.
type relayMeter struct {
	pending atomic.Int64
	lim     atomic.Pointer[relayBuckets]
	// waited counts how long the tun reader has been held back, in
	// microseconds. Surfaced in dpstats so "my mesh is slow" can be answered
	// with "yes, by us, on purpose" instead of a packet capture.
	waitedMicros atomic.Int64
	charged      atomic.Uint64
}

// relayBuckets is the same dual-bucket shape the edge uses: a sustained rate
// with a large burst, and a peak rate that caps the instantaneous speed.
type relayBuckets struct {
	sustained *rate.Limiter
	peak      *rate.Limiter
	chunk     int
}

// SetRelayRate installs (or with sustainedBps<=0 removes) the client's
// self-imposed cap on relayed traffic. Rates are bytes/sec.
func (m *relayMeter) SetRelayRate(sustainedBps, peakBps int64) {
	if m == nil {
		return
	}
	if sustainedBps <= 0 {
		m.lim.Store(nil)
		return
	}
	sustBurst := int(sustainedBps) * 2
	if peakBps > sustainedBps {
		sustBurst = int(peakBps) * relayBurstSeconds
	}
	if sustBurst < relayMinBurstBytes {
		sustBurst = relayMinBurstBytes
	}
	b := &relayBuckets{
		sustained: rate.NewLimiter(rate.Limit(sustainedBps), sustBurst),
		chunk:     sustBurst,
	}
	if peakBps > sustainedBps {
		b.peak = rate.NewLimiter(rate.Limit(peakBps), relayMinBurstBytes)
		b.chunk = relayMinBurstBytes
	}
	m.lim.Store(b)
}

// charge records ciphertext bytes that just went out over the relay. Called on
// the send path, so it does nothing but add.
func (m *relayMeter) charge(n int) {
	if m == nil || n <= 0 || m.lim.Load() == nil {
		return
	}
	m.pending.Add(int64(n))
	m.charged.Add(uint64(n))
}

// settle blocks until everything charged so far has been paid for. Called by
// the tun reader before it reads the next batch — which is what turns the wait
// into back-pressure on the application instead of a drop.
//
// Takes the whole outstanding amount at once and pays it in bucket-sized
// chunks. On ctx cancellation it returns immediately; the bytes are forgiven
// rather than carried, because the only ctx that cancels here is the datapath
// shutting down.
func (m *relayMeter) settle(ctx context.Context) {
	if m == nil {
		return
	}
	b := m.lim.Load()
	if b == nil {
		return
	}
	owed := m.pending.Swap(0)
	if owed <= 0 {
		return
	}
	start := time.Now()
	for owed > 0 {
		n := int(owed)
		if n > b.chunk {
			n = b.chunk
		}
		if err := b.sustained.WaitN(ctx, n); err != nil {
			return
		}
		if b.peak != nil {
			if err := b.peak.WaitN(ctx, n); err != nil {
				return
			}
		}
		owed -= int64(n)
	}
	if d := time.Since(start); d > 0 {
		m.waitedMicros.Add(d.Microseconds())
	}
}

// stats returns (bytes charged, microseconds the tun reader was held).
func (m *relayMeter) stats() (uint64, int64) {
	if m == nil {
		return 0, 0
	}
	return m.charged.Load(), m.waitedMicros.Load()
}
