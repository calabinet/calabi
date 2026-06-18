package protocol

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentWritersReaders exercises codec under -race.
//
// Each writer sends N frames into a pipe; a single reader drains and
// verifies frame integrity. With sync.Mutex around the writer (real
// transports give us in-order single-stream writes), no torn frames
// should ever surface and the race detector should stay quiet.
func TestConcurrentWritersReaders(t *testing.T) {
	const writers = 8
	const perWriter = 256

	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close(); _ = pr.Close() })

	var writeMu sync.Mutex
	var sent atomic.Int64

	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				f := Frame{
					Version:   CurrentMajor,
					Type:      FramePing,
					RequestID: uint64(id)<<32 | uint64(i),
					Payload:   []byte{byte(id), byte(i)},
				}
				writeMu.Lock()
				_, err := WriteFrame(pw, f)
				writeMu.Unlock()
				if err != nil {
					t.Errorf("write: %v", err)
					return
				}
				sent.Add(1)
			}
		}(w)
	}

	go func() {
		wg.Wait()
		_ = pw.Close()
	}()

	var received int64
	for {
		f, err := ReadFrame(pr)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			break
		}
		if err != nil {
			t.Fatalf("read after %d frames: %v", received, err)
		}
		if f.Type != FramePing || len(f.Payload) != 2 {
			t.Fatalf("frame corruption: %+v", f)
		}
		received++
	}
	if received != int64(writers*perWriter) {
		t.Fatalf("received %d, sent %d", received, sent.Load())
	}
}

// TestTransportRaceSkeleton models the 200ms QUIC-vs-yamux race the
// client runs at startup. This is a SKELETON only -- it does not
// actually dial QUIC; it just proves the race-selection pattern compiles
// and never deadlocks. Replace the dialers with real transport calls in
// apps/client/internal/transport.
func TestTransportRaceSkeleton(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	type result struct {
		name string
		err  error
	}
	out := make(chan result, 2)

	dial := func(name string, delay time.Duration) {
		select {
		case <-time.After(delay):
			out <- result{name: name}
		case <-ctx.Done():
			out <- result{name: name, err: ctx.Err()}
		}
	}

	go dial("quic", 50*time.Millisecond)
	go dial("tls-tcp", 250*time.Millisecond) // intentionally slower

	// "200ms head start" rule for QUIC.
	const quicHeadStart = 200 * time.Millisecond
	deadline := time.After(quicHeadStart)

	var winner result
	select {
	case winner = <-out:
		if winner.err != nil {
			t.Fatalf("early winner errored: %v", winner.err)
		}
	case <-deadline:
		// Neither finished within 200ms -- accept whichever wins next.
		winner = <-out
		if winner.err != nil {
			t.Fatalf("late winner errored: %v", winner.err)
		}
	}

	// Drain the loser to avoid leaks.
	go func() { <-out }()

	if winner.name != "quic" {
		t.Fatalf("expected QUIC to win, got %s", winner.name)
	}

	// Smoke-test: encode/decode a frame on the chosen transport
	// (using bytes.Buffer as a stand-in).
	var buf bytes.Buffer
	if _, err := WriteFrame(&buf, Frame{Version: 1, Type: FrameHello}); err != nil {
		t.Fatalf("write on %s: %v", winner.name, err)
	}
	if _, err := ReadFrame(&buf); err != nil {
		t.Fatalf("read on %s: %v", winner.name, err)
	}
}
