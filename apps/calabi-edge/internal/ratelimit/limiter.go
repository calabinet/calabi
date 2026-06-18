// Package ratelimit wraps golang.org/x/time/rate's token bucket with
// io.Reader / io.Writer adapters and a "0 == unlimited" sentinel so
// callers don't have to special-case the no-limit path on every Read.
//
// One Limiter belongs to one session and is shared across all of that
// session's proxies — bandwidth is a per-customer concept, not a per-
// stream one.
//
// Dual tier (2026-06-09 套餐「带宽速度 / 带宽上限」): every byte passes a
// sustained bucket (rate = 速度) AND a peak bucket (rate = 上限). The
// sustained bucket is sized `上限 × DefaultPeakBurstSeconds` so a quiet
// user can transfer at the PEAK rate for that window (~300s) before its
// accumulated tokens drain and throughput falls back to the sustained
// rate. Without a peak tier it degrades to a single sustained bucket with
// a small `2s × rate` headroom.
//
// Math:
//   - rate.Limiter takes events/second + burst capacity in events
//   - "1 event = 1 byte" by convention; users pass byte/sec rates
//   - 0 bytes/sec means unlimited (Reader/Writer become pass-through)
package ratelimit

import (
	"context"
	"io"
	"sync/atomic"

	"golang.org/x/time/rate"
)

// MinBytesPerSecond is the floor we clamp to when a non-zero rate is
// configured below 1 KB/s. x/time/rate's accuracy degrades in tiny
// buckets (it backs sub-Hz tokens with NaN-ish wait times); 1 KB/s is
// the smallest rate where empirical p99 wait stays sane.
const MinBytesPerSecond = 1024

// DefaultBurstSeconds sizes the SINGLE-tier bucket (no separate peak):
// 2s of headroom absorbs HTTP request bodies / TLS handshakes without
// throttling the first fragment.
const DefaultBurstSeconds = 2

// DefaultPeakBurstSeconds sizes the DUAL-tier burst window: a quiet user
// may transfer at the PEAK rate (带宽上限) for this many seconds before
// throughput drains back to the sustained rate (带宽速度). The sustained
// bucket is sized `peak × this` (= the bytes transferable in this window
// at the peak rate). It refills at the sustained rate, so rebuilding a
// full burst takes `(peak × this) / sustained` seconds of idle.
// 2026-06-12: 30 → 300（峰值持续时间由 30s 改 300s）。
const DefaultPeakBurstSeconds = 300

// MinBurstBytes is the floor for the bucket capacity. We want the
// bucket large enough to hold one comfortably-sized syscall (so even at
// the floor rate of 1 KB/s we don't reject WaitN(4096)) but small
// enough that bursts don't double the user's allotted bandwidth on
// short payloads. 4 KB matches the typical http.Read chunk.
const MinBurstBytes = 4 * 1024

// Limiter is the per-session DUAL token bucket (2026-06-09 双档):
//   - sustained: the long-run rate (套餐「带宽速度」). After a quiet user's
//     accumulated tokens drain, throughput is pinned here.
//   - peak: the instantaneous ceiling (套餐「带宽上限」). A quiet user can
//     momentarily transfer at up to this rate (releasing the sustained
//     bucket's accumulated tokens) before settling back to sustained.
//
// Every byte must pass BOTH buckets. peak<=sustained (or peak<=0) means
// "no separate burst tier" → single-bucket behaviour on sustained.
type Limiter struct {
	// sustainedBps / peakBps are the authoritative configured rates;
	// 0 = unlimited (sustained) / no peak tier (peak). Stored atomically
	// for lock-free hot-update.
	sustainedBps atomic.Int64
	peakBps      atomic.Int64

	// chunkBytes is the WaitN chunk size = min of the two bucket bursts,
	// so neither limiter's "WaitN cannot exceed burst" check trips.
	chunkBytes int
	sustained  *rate.Limiter // sustained-rate bucket; nil = unlimited
	peak       *rate.Limiter // peak-rate bucket; nil = no burst tier
}

// New returns a Limiter with a sustained rate and an optional higher peak
// (burst) ceiling, both in bytes/second. sustainedBps<=0 means "no limit"
// (Reader/Writer become passthroughs). peakBps<=sustainedBps disables the
// separate burst tier.
func New(sustainedBps, peakBps int64) *Limiter {
	l := &Limiter{}
	l.set(sustainedBps, peakBps)
	return l
}

// SetRate hot-swaps the configured rates. The underlying x/time/rate
// limiters are rebuilt; bursts in flight at swap time are unaffected
// (they've already pulled their tokens).
func (l *Limiter) SetRate(sustainedBps, peakBps int64) {
	l.set(sustainedBps, peakBps)
}

func (l *Limiter) set(sustainedBps, peakBps int64) {
	if sustainedBps <= 0 {
		l.sustainedBps.Store(0)
		l.peakBps.Store(0)
		l.sustained = nil
		l.peak = nil
		l.chunkBytes = 0
		return
	}
	if sustainedBps < MinBytesPerSecond {
		sustainedBps = MinBytesPerSecond
	}
	l.sustainedBps.Store(sustainedBps)

	// Peak tier only when it's genuinely higher than sustained.
	if peakBps > sustainedBps {
		// Size the SUSTAINED bucket = peak × window, so a quiet user can run
		// at the peak rate for DefaultPeakBurstSeconds before its tokens
		// drain and throughput falls back to the sustained rate (the bucket
		// then refills at `sustained`). The token count is just a counter —
		// large values cost no memory.
		sustBurst := int(peakBps * int64(DefaultPeakBurstSeconds))
		if sustBurst < MinBurstBytes {
			sustBurst = MinBurstBytes
		}
		l.sustained = rate.NewLimiter(rate.Limit(sustainedBps), sustBurst)
		// A small peak bucket (MinBurstBytes) keeps the instantaneous rate
		// tight to the configured peak.
		peakBurst := MinBurstBytes
		l.peakBps.Store(peakBps)
		l.peak = rate.NewLimiter(rate.Limit(peakBps), peakBurst)
		l.chunkBytes = peakBurst // = min(sustBurst, peakBurst); peakBurst is the small one
		return
	}

	// Single tier (no separate burst ceiling): legacy small 2s headroom.
	sustBurst := int(sustainedBps) * DefaultBurstSeconds
	if sustBurst < MinBurstBytes {
		sustBurst = MinBurstBytes
	}
	l.sustained = rate.NewLimiter(rate.Limit(sustainedBps), sustBurst)
	l.peakBps.Store(0)
	l.peak = nil
	l.chunkBytes = sustBurst
}

// Rate returns the sustained bytes/sec; 0 == unlimited.
func (l *Limiter) Rate() int64 { return l.sustainedBps.Load() }

// PeakRate returns the peak (burst-ceiling) bytes/sec; 0 == no separate
// burst tier.
func (l *Limiter) PeakRate() int64 { return l.peakBps.Load() }

// Wait blocks until n tokens are available. n is chunked at the burst
// capacity so we don't trip x/time/rate's "WaitN cannot exceed burst"
// check on large payloads. Returns ctx errors verbatim; otherwise nil.
func (l *Limiter) Wait(ctx context.Context, n int) error {
	if l == nil || l.sustained == nil {
		return nil
	}
	for n > 0 {
		chunk := n
		if chunk > l.chunkBytes {
			chunk = l.chunkBytes
		}
		// Pass BOTH buckets: sustained paces the long-run rate, peak caps
		// the instantaneous rate. Whichever is more constrained right now
		// dominates the wait.
		if err := l.sustained.WaitN(ctx, chunk); err != nil {
			return err
		}
		if l.peak != nil {
			if err := l.peak.WaitN(ctx, chunk); err != nil {
				return err
			}
		}
		n -= chunk
	}
	return nil
}

// Reader wraps r so reads pull tokens before returning bytes upstream.
// Pass-through if the limiter is unconfigured.
func (l *Limiter) Reader(r io.Reader) io.Reader {
	if l == nil || l.sustained == nil {
		return r
	}
	return &limitedReader{l: l, r: r}
}

// Writer wraps w so writes block on Wait before delegating.
func (l *Limiter) Writer(w io.Writer) io.Writer {
	if l == nil || l.sustained == nil {
		return w
	}
	return &limitedWriter{l: l, w: w}
}

// limitedReader is a Reader that throttles by post-throttling read bytes.
// We throttle AFTER reading (not before) because we don't know how many
// bytes the underlying reader will hand us until it does — pre-throttling
// would either over-account (assume max) or under-utilise the bucket.
type limitedReader struct {
	l *Limiter
	r io.Reader
}

func (lr *limitedReader) Read(p []byte) (int, error) {
	n, err := lr.r.Read(p)
	if n > 0 {
		if werr := lr.l.Wait(context.Background(), n); werr != nil {
			return n, werr
		}
	}
	return n, err
}

// limitedWriter throttles before each Write. Pre-throttling is right
// here because we know n up front and any blocking before the syscall
// pushes back-pressure onto the caller correctly.
type limitedWriter struct {
	l *Limiter
	w io.Writer
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if err := lw.l.Wait(context.Background(), len(p)); err != nil {
		return 0, err
	}
	return lw.w.Write(p)
}
