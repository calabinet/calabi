package ratelimit

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestNew_ZeroIsUnlimited(t *testing.T) {
	l := New(0, 0)
	if l.Rate() != 0 {
		t.Fatalf("rate: got %d", l.Rate())
	}
	// Reader/Writer should be the passed-through value.
	r := strings.NewReader("hi")
	if wrapped := l.Reader(r); wrapped != r {
		t.Fatal("expected passthrough reader for zero limiter")
	}
	var buf bytes.Buffer
	if wrapped := l.Writer(&buf); wrapped != &buf {
		t.Fatal("expected passthrough writer for zero limiter")
	}
}

func TestNew_BelowFloorClamps(t *testing.T) {
	l := New(100, 0) // way below MinBytesPerSecond
	if l.Rate() != MinBytesPerSecond {
		t.Fatalf("rate: got %d want %d (floor)", l.Rate(), MinBytesPerSecond)
	}
}

func TestWait_NoOpWhenUnlimited(t *testing.T) {
	l := New(0, 0)
	if err := l.Wait(context.Background(), 1<<30); err != nil {
		t.Fatalf("unlimited wait: %v", err)
	}
}

func TestWriter_Throttles(t *testing.T) {
	// 4 KB/s with 2s burst = 8 KB capacity. Writing 16 KB therefore
	// requires at least one ~1s wait after the bucket drains.
	l := New(4096, 0)
	var buf bytes.Buffer
	w := l.Writer(&buf)

	payload := make([]byte, 16*1024)
	start := time.Now()
	n, err := w.Write(payload)
	elapsed := time.Since(start)
	if err != nil || n != len(payload) {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	// 16KB / 4096 B/s = 4s; minus 2s burst = ~2s mandated wait. Allow
	// generous slack on slow CI; we just need to prove it's NOT instant.
	if elapsed < 1500*time.Millisecond {
		t.Fatalf("write returned too fast: %v (expected >= 1.5s for 16KB @ 4KB/s)", elapsed)
	}
}

func TestReader_Throttles(t *testing.T) {
	l := New(4096, 0)
	src := bytes.NewReader(make([]byte, 16*1024))
	r := l.Reader(src)

	start := time.Now()
	buf := make([]byte, 32*1024)
	_, err := io.ReadFull(r, buf[:16*1024])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if d := time.Since(start); d < 1500*time.Millisecond {
		t.Fatalf("read returned too fast: %v", d)
	}
}

func TestWait_ContextCancel(t *testing.T) {
	// Use 1 KB/s so a 100 KB request needs ~100s; cancel after 50ms.
	l := New(1024, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx, 100*1024); err == nil {
		t.Fatal("expected context error, got nil")
	}
}

// TestNew_DualBucket pins the 2026-06-09 双档 behaviour: a peak above
// sustained adds a burst tier (quiet users can momentarily transfer at the
// peak rate), while peak<=sustained disables it.
func TestNew_DualBucket(t *testing.T) {
	l := New(4096, 64*1024) // sustained 4 KB/s, peak 64 KB/s
	if l.Rate() != 4096 {
		t.Fatalf("sustained: got %d want 4096", l.Rate())
	}
	if l.PeakRate() != 64*1024 {
		t.Fatalf("peak: got %d want %d", l.PeakRate(), 64*1024)
	}
	// peak <= sustained ⇒ no separate burst tier.
	if l2 := New(8192, 4096); l2.PeakRate() != 0 {
		t.Fatalf("peak<=sustained should disable burst tier; got %d", l2.PeakRate())
	}
	// 32 KB is 4× the OLD single-tier budget (2s × sustained = 8 KB) but
	// well within the new 30s-window budget (peak × 30 ≈ 1.9 MB), so it
	// rides the PEAK rate (32KB @ 64KB/s ≈ 0.5s) instead of falling back to
	// the sustained rate (which would be 32KB @ 4KB/s ≈ 8s). Proves the 30s
	// burst sizing is in effect.
	var buf bytes.Buffer
	w := l.Writer(&buf)
	start := time.Now()
	if _, err := w.Write(make([]byte, 32*1024)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("32KB burst should ride the peak rate (~0.5s), took %v", d)
	}
}

func TestSetRate_HotSwap(t *testing.T) {
	l := New(4096, 0)
	if l.Rate() != 4096 {
		t.Fatalf("initial: %d", l.Rate())
	}
	l.SetRate(0, 0)
	if l.Rate() != 0 {
		t.Fatalf("after zero: %d", l.Rate())
	}
	// Now unlimited — large wait must be instant.
	start := time.Now()
	_ = l.Wait(context.Background(), 1<<20)
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("post-zero wait was not instant: %v", d)
	}
}
