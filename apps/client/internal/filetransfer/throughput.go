package filetransfer

import (
	"sync"
	"time"
)

// Transport activity is separate from the receiver's durable offset. Sampling
// small reads/writes keeps slow blocks visible without acknowledging them early.
type throughput struct {
	mu            sync.Mutex
	started, last time.Time
	bytes, rate   int64
}

func (m *throughput) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started, m.last, m.bytes, m.rate = time.Time{}, time.Time{}, 0, 0
}

func (m *throughput) current() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rate
}

func (m *throughput) add(now time.Time, n int64) (int64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started.IsZero() {
		m.started, m.last = now, now
		return 0, false
	}
	m.bytes += n
	elapsed := now.Sub(m.started)
	if now.Sub(m.last) < 500*time.Millisecond || elapsed <= 0 {
		return m.rate, false
	}
	rate := int64(float64(m.bytes) / elapsed.Seconds())
	if m.rate > 0 {
		rate = (m.rate + rate) / 2
	}
	m.rate, m.bytes, m.started, m.last = max(1, rate), 0, now, now
	return m.rate, true
}

type transferActivity struct {
	id              string
	rate, remaining int64
	at              time.Time
}
