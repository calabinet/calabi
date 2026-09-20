package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

// deniedByCoord is exactly the chain a refusal arrives through: coord answers
// Unauthenticated (from GetRegisterChallenge or RegisterNode — CoordClient.Register
// returns either one unwrapped) and Controller.Run wraps it once.
func deniedByCoord() error {
	return fmt.Errorf("mesh: register: %w", status.Error(codes.Unauthenticated, "auth key denied"))
}

// runMeshLoop drives the retry loop through the given session outcomes, one per
// session, and returns the delays it chose after each.
func runMeshLoop(t *testing.T, r *meshRunner, outcomes []error) []time.Duration {
	t.Helper()
	var mu sync.Mutex
	var delays []time.Duration
	var sessions atomic.Int32
	done := make(chan struct{})
	r.tune = meshLoopTuning{
		minBackoff:     time.Millisecond,
		maxBackoff:     64 * time.Millisecond,
		healthySession: time.Hour, // never "healthy": only the refresh may reset the backoff
		startDP: func() (*meshDataPlane, error) {
			return &meshDataPlane{stop: func() {}}, nil
		},
		runCP: func(context.Context, *meshDataPlane) error {
			return outcomes[sessions.Add(1)-1]
		},
		sleep: func(_ context.Context, d time.Duration) bool {
			mu.Lock()
			delays = append(delays, d)
			n := len(delays)
			mu.Unlock()
			if n == len(outcomes) {
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
		t.Fatalf("the retry loop stalled after %d sessions", sessions.Load())
	}
	r.Stop()
	mu.Lock()
	defer mu.Unlock()
	return append([]time.Duration(nil), delays...)
}

func sameDelays(got, want []time.Duration) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// A refused credential is refreshed once and retried straight away.
//
// The regression: a signed-in daemon's mesh sent the same expired access token on
// every retry, forever — nothing refreshes a login session while the edge session
// stays up and no console is open.
func TestMeshRunnerRefreshesARefusedCredentialAndRetriesAtOnce(t *testing.T) {
	var refreshes atomic.Int32
	r := newMeshRunner(quietLogger(), testMeshConfig())
	r.refreshFn = func(context.Context) string {
		refreshes.Add(1)
		return "jwt-fresh"
	}

	ended := errors.New("stream ended")
	got := runMeshLoop(t, r, []error{ended, ended, deniedByCoord(), deniedByCoord()})

	if n := refreshes.Load(); n != 1 {
		t.Fatalf("refreshed %d times, want 1 — the second refusal falls inside the cooldown", n)
	}
	// Two ordinary failures back off 1ms, 2ms. The refusal that got a fresh token
	// retries at the minimum; the next one (cooldown, no refresh) resumes doubling.
	want := []time.Duration{time.Millisecond, 2 * time.Millisecond, time.Millisecond, 2 * time.Millisecond}
	if !sameDelays(got, want) {
		t.Fatalf("delays = %v, want %v", got, want)
	}
}

// A refresh that yields nothing — an API key, a session that is itself dead —
// must not buy an immediate retry: the next attempt would be refused the same way.
func TestMeshRunnerKeepsBackingOffWhenRefreshYieldsNothing(t *testing.T) {
	var refreshes atomic.Int32
	r := newMeshRunner(quietLogger(), testMeshConfig())
	r.refreshFn = func(context.Context) string {
		refreshes.Add(1)
		return ""
	}

	ended := errors.New("stream ended")
	got := runMeshLoop(t, r, []error{ended, ended, deniedByCoord()})

	if n := refreshes.Load(); n != 1 {
		t.Fatalf("refreshed %d times, want 1", n)
	}
	want := []time.Duration{time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond}
	if !sameDelays(got, want) {
		t.Fatalf("delays = %v, want %v — nothing changed, so the backoff must keep growing", got, want)
	}
}

// Only a refusal is worth a refresh. Network and server failures are not about
// the credential, and spending a rotation on each would be pure churn.
func TestMeshRunnerOnlyRefreshesOnARefusal(t *testing.T) {
	var refreshes atomic.Int32
	r := newMeshRunner(quietLogger(), testMeshConfig())
	r.refreshFn = func(context.Context) string {
		refreshes.Add(1)
		return "jwt-fresh"
	}

	runMeshLoop(t, r, []error{
		errors.New("stream ended"),
		fmt.Errorf("coordinator dial: %w", errors.New("connection refused")),
		fmt.Errorf("mesh: register: %w", status.Error(codes.Unavailable, "connection reset")),
		fmt.Errorf("mesh: register: %w", status.Error(codes.PermissionDenied, "node disabled")),
	})
	if n := refreshes.Load(); n != 0 {
		t.Fatalf("refreshed %d times on failures that were not a refused credential", n)
	}
}

// An API key the coordinator refuses is revoked or wrong; no refresh can fix it,
// and a service's creds file may still hold an old sign-in that must not be
// rotated on its behalf.
func TestMeshRefreshOnlyForASignIn(t *testing.T) {
	var hits atomic.Int32
	srv := refreshServer(t, "usr_r0", func() { hits.Add(1) })
	useRefreshCreds(t, srv, &creds.Config{AccessToken: "jwt-0", RefreshToken: "usr_r0"})
	t.Setenv("CALABI_API_KEY", "tk_service")
	t.Setenv("CALABI_TOKEN", "")
	prev := inServiceManager
	t.Cleanup(func() { inServiceManager = prev })

	inServiceManager = true // a service running on its API key
	if got := meshRefreshForLogin(context.Background()); got != "" || hits.Load() != 0 {
		t.Fatalf("service on an API key: refresh returned %q after %d request(s), want none", got, hits.Load())
	}

	inServiceManager = false // an interactive daemon: the sign-in is the credential
	if got := meshRefreshForLogin(context.Background()); got != "jwt-1" {
		t.Fatalf("signed-in daemon: refresh returned %q, want jwt-1", got)
	}
}
