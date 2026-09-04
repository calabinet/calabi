package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testMeshConfig() meshConfig {
	return meshConfig{Coord: "coord:7014", Relay: "relay:3340", AuthKey: "tk_test"}
}

// A coordinator blip must not touch the data plane.
//
// The regression this pins: one function used to own both halves of a session,
// so a netmap stream error tore down and rebuilt the tun device, the WireGuard
// device, MagicDNS and every relay link. On Windows that destroys and recreates
// the wintun adapter, which resets every TCP connection bound to the overlay
// address — a control-plane hiccup would kill the remote desktop the meshnet
// exists to carry. Nothing about the data plane is invalidated by the stream
// dropping: same keys, same peers, still passing traffic.
func TestMeshRunnerKeepsTheDataPlaneAcrossControlPlaneRetries(t *testing.T) {
	var starts, stops, sessions atomic.Int32
	const wantSessions = 5
	reached := make(chan struct{})

	r := newMeshRunner(quietLogger(), testMeshConfig())
	r.tune = meshLoopTuning{
		minBackoff:     time.Millisecond,
		maxBackoff:     time.Millisecond,
		healthySession: time.Hour, // never "healthy": keeps the backoff out of this test
		startDP: func() (*meshDataPlane, error) {
			starts.Add(1)
			return &meshDataPlane{stop: func() { stops.Add(1) }}, nil
		},
		runCP: func(context.Context, *meshDataPlane) error {
			if sessions.Add(1) == wantSessions {
				close(reached)
			}
			return errors.New("stream ended")
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatalf("only %d control-plane sessions ran", sessions.Load())
	}
	r.Stop()

	if got := starts.Load(); got != 1 {
		t.Fatalf("data plane built %d times across %d control-plane retries; want exactly 1 — a coordinator blip must not rebuild the tun device",
			got, sessions.Load())
	}
	if got := stops.Load(); got != 1 {
		t.Fatalf("data plane stopped %d times, want exactly 1 (only on shutdown)", got)
	}
}

// A session that stood up for a while resets the backoff.
//
// The regression: the delay only ever doubled, so a node enrolled for hours paid
// the 30s cap for a one-second hiccup — the retry loop could not tell a crash
// loop from an otherwise-healthy connection that blipped.
func TestMeshRunnerResetsBackoffAfterAHealthySession(t *testing.T) {
	const healthy = 60 * time.Millisecond

	var mu sync.Mutex
	var delays []time.Duration
	sessions := 0
	done := make(chan struct{})

	r := newMeshRunner(quietLogger(), testMeshConfig())
	r.tune = meshLoopTuning{
		minBackoff:     time.Millisecond,
		maxBackoff:     8 * time.Millisecond,
		healthySession: healthy,
		startDP: func() (*meshDataPlane, error) {
			return &meshDataPlane{stop: func() {}}, nil
		},
		runCP: func(context.Context, *meshDataPlane) error {
			mu.Lock()
			sessions++
			n := sessions
			mu.Unlock()
			if n == 4 {
				time.Sleep(2 * healthy) // this one worked before it dropped
			}
			return errors.New("stream ended")
		},
		// Record the delay instead of waiting it out; false ends the loop.
		sleep: func(_ context.Context, d time.Duration) bool {
			mu.Lock()
			delays = append(delays, d)
			n := len(delays)
			mu.Unlock()
			if n == 4 {
				close(done)
				return false
			}
			return true
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the retry loop never reached the fourth session")
	}
	r.Stop()

	mu.Lock()
	got := append([]time.Duration(nil), delays...)
	mu.Unlock()
	want := []time.Duration{1 * time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond, 1 * time.Millisecond}
	if len(got) != len(want) {
		t.Fatalf("delays = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delays = %v, want %v (the fourth session lasted past healthySession, so its retry should be back at the minimum)", got, want)
		}
	}
}

// A data plane that cannot come up is retried, and the control plane is not run
// against a nil one.
func TestMeshRunnerRetriesAFailingDataPlane(t *testing.T) {
	var attempts, sessions atomic.Int32
	reached := make(chan struct{})

	r := newMeshRunner(quietLogger(), testMeshConfig())
	r.tune = meshLoopTuning{
		minBackoff:     time.Millisecond,
		maxBackoff:     time.Millisecond,
		healthySession: time.Hour,
		startDP: func() (*meshDataPlane, error) {
			if n := attempts.Add(1); n < 3 {
				return nil, errors.New("wintun missing")
			}
			close(reached)
			return &meshDataPlane{stop: func() {}}, nil
		},
		runCP: func(ctx context.Context, d *meshDataPlane) error {
			if d == nil {
				t.Error("control plane ran against a data plane that never started")
			}
			sessions.Add(1)
			<-ctx.Done() // hold the session open, like a live netmap stream
			return ctx.Err()
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatalf("data plane was attempted %d times, never succeeded", attempts.Load())
	}
	r.Stop()

	if got := attempts.Load(); got != 3 {
		t.Fatalf("data plane attempts = %d, want 3 (two failures then success)", got)
	}
	if got := sessions.Load(); got != 1 {
		t.Fatalf("control-plane sessions = %d, want 1", got)
	}
}
