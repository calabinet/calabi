package session

import (
	"io"
	"sync/atomic"
)

// meterWriter wraps an io.Writer, accumulating byte counts and forwarding
// them to onFlush in batches.
//
// Why this exists: pumpTCP used to push byte totals into the status
// tracker only once — after io.Copy returned, i.e. after the connection
// closed. That makes the UI's "流量" column useless for any connection
// that lives longer than a few hundred milliseconds: HTTP/1.1 keep-alive
// idle (~120s in most browsers), SSE, long-poll, and WebSocket all leave
// the user staring at "0 B / 0 B" while gigabytes have actually flowed.
//
// Flush triggers, in priority order:
//
//  1. Inline (hot path): each Write that pushes the running tally to
//     >= flushThreshold drains immediately. For large io.Copy buffers
//     (Go default 32 KB) every Write trips this — bulk transfer reflects
//     in the UI within one buffer roundtrip.
//
//  2. Periodic (slow path): pumpTCP starts a 250 ms ticker that calls
//     Flush() on both directions. Catches small drips below the byte
//     threshold (e.g. a 200-byte request followed by idle) so they
//     surface to the UI within a quarter-second instead of waiting for
//     the connection to die.
//
//  3. Terminal: pumpTCP calls Flush() one more time after io.Copy
//     returns, so any residue smaller than the threshold gets counted.
//
// All three may race; atomic.Swap guarantees no double-counting (one
// caller wins the swap and gets the running total; the others get 0
// and skip onFlush).
type meterWriter struct {
	w       io.Writer
	pending atomic.Int64
	onFlush func(int64) // nil means "count but don't report"
}

// flushThreshold is the byte tally that triggers an inline flush from
// Write. 8 KB is below Go's io.Copy default buffer (32 KB) but above
// typical TCP MTU payloads (~1.4 KB), so bulk transfers flush every
// Write while small request/response pairs accumulate a few hops
// before flushing or wait for the periodic ticker.
const flushThreshold = 8 * 1024

func newMeterWriter(w io.Writer, onFlush func(int64)) *meterWriter {
	return &meterWriter{w: w, onFlush: onFlush}
}

// Write implements io.Writer. Bytes pass through unchanged; only the
// running counter is observed.
func (m *meterWriter) Write(p []byte) (int, error) {
	n, err := m.w.Write(p)
	if n > 0 && m.pending.Add(int64(n)) >= flushThreshold {
		m.Flush()
	}
	return n, err
}

// Flush drains the accumulated pending bytes to onFlush. Safe to call
// concurrently from the io.Copy goroutine, the periodic ticker, and
// the terminal call — at most one caller observes the running tally
// thanks to the atomic swap.
func (m *meterWriter) Flush() {
	if m.onFlush == nil {
		m.pending.Store(0)
		return
	}
	if n := m.pending.Swap(0); n > 0 {
		m.onFlush(n)
	}
}
