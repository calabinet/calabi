package creds

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func useTempCreds(t *testing.T, c *Config) {
	t.Helper()
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	if err := Save(c); err != nil {
		t.Fatal(err)
	}
}

// rotating stands in for identity-svc: a refresh token is good for ONE
// exchange; it is rotated on use and a replay is refused.
type rotating struct {
	mu      sync.Mutex
	current string
	n       int
	delay   time.Duration
	calls   atomic.Int32
}

func (r *rotating) exchange(_ context.Context, rt string) (string, string, error) {
	r.calls.Add(1)
	time.Sleep(r.delay)
	r.mu.Lock()
	defer r.mu.Unlock()
	if rt != r.current {
		return "", "", errors.New("session not found")
	}
	r.n++
	r.current = fmt.Sprintf("usr_r%d", r.n)
	return fmt.Sprintf("jwt-%d", r.n), r.current, nil
}

// The local console polls several endpoints at once, so when the access token
// expires they are refused together. One exchange has to serve all of them —
// before, the first refreshed and the rest reported "login required", which sent
// the console to its login screen while the session was fine.
func TestRefreshSessionServesSimultaneousRefusalsWithOneExchange(t *testing.T) {
	useTempCreds(t, &Config{AccessToken: "jwt-0", RefreshToken: "usr_r0"})
	srv := &rotating{current: "usr_r0", delay: 30 * time.Millisecond}

	got := make([]string, 8)
	var wg sync.WaitGroup
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i] = RefreshSession(context.Background(), "jwt-0", srv.exchange)
		}()
	}
	wg.Wait()
	for i, g := range got {
		if g != "jwt-1" {
			t.Fatalf("caller %d got %q, want jwt-1 (all: %q)", i, g, got)
		}
	}
	if n := srv.calls.Load(); n != 1 {
		t.Fatalf("%d exchanges for one expired token, want 1", n)
	}
}

// Someone else (the mesh, edge discovery, a sign-in) already replaced the
// refused token: hand over what is on disk, don't spend the refresh token.
func TestRefreshSessionReturnsANewerTokenWithoutExchanging(t *testing.T) {
	useTempCreds(t, &Config{AccessToken: "jwt-5", RefreshToken: "usr_r5"})
	srv := &rotating{current: "usr_r5"}

	if got := RefreshSession(context.Background(), "jwt-4", srv.exchange); got != "jwt-5" {
		t.Fatalf("got %q, want the newer jwt-5 already on disk", got)
	}
	if n := srv.calls.Load(); n != 0 {
		t.Fatalf("%d exchanges, want 0", n)
	}
}

// A dead session backs off instead of hitting identity-svc on every proxied
// request — and the backoff ends.
func TestRefreshSessionBacksOffAfterAFailure(t *testing.T) {
	old := failCooldown
	failCooldown = 80 * time.Millisecond
	t.Cleanup(func() { failCooldown = old })
	useTempCreds(t, &Config{AccessToken: "jwt-0", RefreshToken: "usr_dead"})
	srv := &rotating{current: "usr_r0"} // usr_dead is refused

	if got := RefreshSession(context.Background(), "jwt-0", srv.exchange); got != "" {
		t.Fatalf("got %q from a dead session", got)
	}
	if got := RefreshSession(context.Background(), "jwt-0", srv.exchange); got != "" || srv.calls.Load() != 1 {
		t.Fatalf("inside the backoff: got %q after %d exchanges, want \"\" after 1", got, srv.calls.Load())
	}
	time.Sleep(100 * time.Millisecond)
	RefreshSession(context.Background(), "jwt-0", srv.exchange)
	if n := srv.calls.Load(); n != 2 {
		t.Fatalf("%d exchanges once the backoff ended, want 2", n)
	}
}

// Signing in again replaces the session. The old session's failure must not
// hold the new one back.
func TestRefreshSessionFailureDoesNotBlockANewSession(t *testing.T) {
	useTempCreds(t, &Config{AccessToken: "jwt-0", RefreshToken: "usr_dead"})
	srv := &rotating{current: "usr_r0"}
	RefreshSession(context.Background(), "jwt-0", srv.exchange) // fails, backs off usr_dead

	c, _ := Load()
	c.AccessToken, c.RefreshToken = "jwt-0b", "usr_r0" // a fresh sign-in
	if err := Save(c); err != nil {
		t.Fatal(err)
	}
	if got := RefreshSession(context.Background(), "jwt-0b", srv.exchange); got != "jwt-1" {
		t.Fatalf("got %q for the new session, want jwt-1", got)
	}
}

// A caller that went away (the browser dropped its request) says nothing about
// the session and must not make the next caller wait out a backoff.
func TestRefreshSessionCancelledCallerDoesNotStartTheBackoff(t *testing.T) {
	useTempCreds(t, &Config{AccessToken: "jwt-0", RefreshToken: "usr_r0"})
	srv := &rotating{current: "usr_r0"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	RefreshSession(ctx, "jwt-0", func(ctx context.Context, _ string) (string, string, error) {
		return "", "", ctx.Err()
	})
	if got := RefreshSession(context.Background(), "jwt-0", srv.exchange); got != "jwt-1" {
		t.Fatalf("got %q after a cancelled caller, want jwt-1", got)
	}
}
