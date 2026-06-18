package listener

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
)

// Verifies that bytesMeter increments the counter on each Write, not
// only after the writer is closed — this is the exact property the
// usage-reporter regression of "今日/本月流量 几乎不动" turned on.
func TestBytesMeter_IncrementsPerWrite(t *testing.T) {
	var c atomic.Uint64
	var sink bytes.Buffer
	m := newBytesMeter(&sink, &c)

	if _, err := m.Write([]byte("hello")); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if got := c.Load(); got != 5 {
		t.Fatalf("after write 1: got=%d want=5", got)
	}

	if _, err := m.Write([]byte(" world")); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if got := c.Load(); got != 11 {
		t.Fatalf("after write 2: got=%d want=11", got)
	}

	if sink.String() != "hello world" {
		t.Fatalf("bytes not forwarded: %q", sink.String())
	}
}

// Concurrent writers must not lose counts. Runs many goroutines each
// doing a fixed number of 1-byte Writes; the final total must match.
func TestBytesMeter_ConcurrentSafe(t *testing.T) {
	var c atomic.Uint64
	var mu sync.Mutex
	var sink bytes.Buffer
	// wrap sink with a per-write mutex so bytes.Buffer doesn't race —
	// the meter itself is what we're testing for race safety on c.
	w := &lockedWriter{w: &sink, mu: &mu}
	m := newBytesMeter(w, &c)

	const goroutines = 64
	const writes = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < writes; j++ {
				_, _ = m.Write([]byte{'x'})
			}
		}()
	}
	wg.Wait()

	if got := c.Load(); got != uint64(goroutines*writes) {
		t.Fatalf("got=%d want=%d", got, goroutines*writes)
	}
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
