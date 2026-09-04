package bffedgeclient

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// TestRunCertRenewalPlatformHoldsUntilCtx locks the namedRunner contract that
// F1 originally broke: RunCertRenewal runs in main's errCh set, where ANY
// runner returning — even nil — trips the shutdown select and stops the whole
// edge. A platform edge (no org SAN, nothing to renew) must therefore BLOCK
// until ctx is cancelled, not return immediately. The original bare `return
// nil` on the skip path shut every platform edge down ~1s after boot (booted
// clean, then vanished with no shutdown log).
func TestRunCertRenewalPlatformHoldsUntilCtx(t *testing.T) {
	// cert == nil ⇒ isBYOI() == false ⇒ the platform (skip) path.
	c := &Conn{holder: &certHolder{}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.RunCertRenewal(ctx, logger) }()

	// It must still be running a beat later — a premature return here is exactly
	// the bug (it would have shut the edge down).
	select {
	case <-done:
		t.Fatal("RunCertRenewal returned before ctx cancel — a nil return from a namedRunner shuts the edge down")
	case <-time.After(100 * time.Millisecond):
	}

	// After ctx cancel it returns promptly, with nil.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil after ctx cancel, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunCertRenewal did not return after ctx cancel")
	}
}

// TestRunCertRenewalNilHolderHoldsUntilCtx covers the other early-return skip
// path (defensive nil holder) with the same contract.
func TestRunCertRenewalNilHolderHoldsUntilCtx(t *testing.T) {
	c := &Conn{} // holder == nil
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.RunCertRenewal(ctx, logger) }()

	select {
	case <-done:
		t.Fatal("RunCertRenewal returned before ctx cancel on the nil-holder path")
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil after ctx cancel, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunCertRenewal did not return after ctx cancel (nil-holder path)")
	}
}
