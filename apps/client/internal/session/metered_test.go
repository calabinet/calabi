package session

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
)

func TestMeterWriter_FlushOnThreshold(t *testing.T) {
	var dst bytes.Buffer
	var flushed atomic.Int64
	m := newMeterWriter(&dst, func(n int64) { flushed.Add(n) })

	// Single write below threshold: no inline flush.
	_, err := m.Write(make([]byte, 1024))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if flushed.Load() != 0 {
		t.Fatalf("flushed early: want 0 got %d", flushed.Load())
	}

	// Pile on past 8KB: inline flush should drain everything.
	_, err = m.Write(make([]byte, 8*1024))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := flushed.Load(); got != 9*1024 {
		t.Fatalf("want flush 9216 got %d", got)
	}
	if dst.Len() != 9*1024 {
		t.Fatalf("dst short: %d", dst.Len())
	}
}

func TestMeterWriter_FlushDrainsResidue(t *testing.T) {
	var dst bytes.Buffer
	var flushed atomic.Int64
	m := newMeterWriter(&dst, func(n int64) { flushed.Add(n) })

	_, _ = m.Write([]byte("hello"))
	if flushed.Load() != 0 {
		t.Fatalf("unexpected early flush")
	}
	m.Flush()
	if flushed.Load() != 5 {
		t.Fatalf("want 5 got %d", flushed.Load())
	}
	// Second Flush is a no-op (pending already drained).
	m.Flush()
	if flushed.Load() != 5 {
		t.Fatalf("double-count: %d", flushed.Load())
	}
}

func TestMeterWriter_NilOnFlush(t *testing.T) {
	// nil onFlush should still consume bytes correctly without crashing.
	var dst bytes.Buffer
	m := newMeterWriter(&dst, nil)
	for i := 0; i < 4; i++ {
		_, _ = m.Write(make([]byte, 4*1024))
	}
	m.Flush()
	if dst.Len() != 16*1024 {
		t.Fatalf("dst short: %d", dst.Len())
	}
}

func TestMeterWriter_ConcurrentFlush(t *testing.T) {
	// Pump enough bytes through concurrent flushers and assert the sum
	// reaches the dest size exactly (no double-count, no loss).
	var dst bytes.Buffer
	var dstMu sync.Mutex
	var flushed atomic.Int64
	m := newMeterWriter(writerFunc(func(p []byte) (int, error) {
		dstMu.Lock()
		defer dstMu.Unlock()
		return dst.Write(p)
	}), func(n int64) { flushed.Add(n) })

	const writers = 8
	const perWriter = 1024
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 16; i++ {
				_, _ = m.Write(make([]byte, perWriter))
			}
		}()
	}
	// Concurrent flushers racing the writers.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				m.Flush()
			}
		}
	}()
	wg.Wait()
	close(stop)
	m.Flush() // terminal drain
	want := int64(writers * 16 * perWriter)
	if flushed.Load() != want {
		t.Fatalf("flushed %d want %d", flushed.Load(), want)
	}
	if int64(dst.Len()) != want {
		t.Fatalf("dst len %d want %d", dst.Len(), want)
	}
}

// writerFunc adapts a plain func to io.Writer for the concurrency test.
type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
