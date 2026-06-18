package listener

import (
	"io"
	"sync/atomic"

	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
)

// proxyMeters returns the byte counters this connection's traffic should
// be attributed to. Per-tunnel metering homes the counters on the
// *Proxy so the usage reporter can break usage down by tunnel_id. If the
// proxy can't be resolved — a rare race where the tunnel was unregistered
// between routing and metering, or a standalone edge with no proxy row —
// we fall back to the session-level counters, which the reporter emits
// under tunnel_id=0 so org-level totals never lose bytes.
func proxyMeters(sess *session.Session, proxyID string) (in, out *atomic.Uint64) {
	if px := sess.Proxy(proxyID); px != nil {
		return &px.BytesIn, &px.BytesOut
	}
	return &sess.BytesIn, &sess.BytesOut
}

// bytesMeter wraps an io.Writer and atomically increments a counter on
// each successful Write. Used to make sess.BytesIn / sess.BytesOut update
// *while* bytes are flowing, not only when the proxy direction terminates.
//
// Why this is needed (and not just a post-Copy.Add):
//
// The usage reporter ticks every 60s and publishes deltas of
// sess.BytesIn / sess.BytesOut. If those counters only grow when a
// proxy conn closes, any conn that outlives a tick contributes zero
// to that tick's delta — and HTTP/1.x keep-alive connections sit idle
// for ~120s before the browser closes them, so a steady stream of
// short requests over keep-alive will show as essentially no traffic
// in the "今日/本月流量" cards. SSE, long-poll and WebSocket are even
// worse. The old code also had a "lossy by design" note that only
// the first-to-finish direction was counted — half the bytes were
// dropped on every conn.
//
// No batching threshold here. atomic.Uint64.Add on a per-Write basis
// is cheap (single CAS-free instruction on amd64); io.Copy's default
// 32KB buffer means we're talking O(traffic/32KB) atomic ops, which
// is negligible compared to the socket I/O itself.
type bytesMeter struct {
	w io.Writer
	c *atomic.Uint64
}

func newBytesMeter(w io.Writer, c *atomic.Uint64) *bytesMeter {
	return &bytesMeter{w: w, c: c}
}

func (m *bytesMeter) Write(p []byte) (int, error) {
	n, err := m.w.Write(p)
	if n > 0 {
		m.c.Add(uint64(n))
	}
	return n, err
}
