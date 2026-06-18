package ratelimit

import (
	"errors"
	"testing"
	"time"
)

func TestRateLimiter_Unlimited(t *testing.T) {
	// defaultPerMin 0 + no SetRate → every Allow passes.
	l := NewRateLimiter(0)
	for i := 0; i < 1000; i++ {
		if err := l.Allow(99); err != nil {
			t.Fatalf("unlimited org should never deny: %v", err)
		}
	}
	// SetRatePerMin(0) is also "unlimited for this org".
	l.SetRatePerMin(7, 0)
	for i := 0; i < 1000; i++ {
		if err := l.Allow(7); err != nil {
			t.Fatalf("rate=0 org should never deny: %v", err)
		}
	}
}

func TestRateLimiter_EnforcesPerMinuteCap(t *testing.T) {
	// 60/min = 1/s, burst = max(60/6, minRateBurst) = 10. A same-instant
	// flood drains the burst then gets denied; total allowed must be far
	// below the flood size and at least the burst's worth.
	l := NewRateLimiter(0)
	l.SetRatePerMin(7, 60)

	allowed := 0
	for i := 0; i < 200; i++ {
		if err := l.Allow(7); err == nil {
			allowed++
		}
	}
	if allowed < 1 {
		t.Errorf("expected at least the burst to pass, allowed=%d", allowed)
	}
	if allowed > 15 {
		// burst 10 + a tiny refill during the loop; 15 is generous head-room.
		t.Errorf("flood of 200 should be throttled near the burst (10), allowed=%d", allowed)
	}
}

func TestRateLimiter_NegativeRateIsUnlimited(t *testing.T) {
	// A -1 (unlimited sentinel) from quota must map to "no cap", not a
	// zero-rate bucket that denies everything.
	l := NewRateLimiter(0)
	l.SetRatePerMin(7, -1)
	if got := l.RatePerMin(7); got != 0 {
		t.Errorf("RatePerMin after SetRatePerMin(-1) = %d, want 0 (unlimited)", got)
	}
	for i := 0; i < 100; i++ {
		if err := l.Allow(7); err != nil {
			t.Fatalf("unlimited (-1) org should never deny: %v", err)
		}
	}
}

func TestRateLimiter_SetRateInvalidatesCache(t *testing.T) {
	l := NewRateLimiter(0)
	l.SetRatePerMin(8, 60) // 1/s, burst 10
	// Drain the burst.
	for i := 0; i < 50; i++ {
		_ = l.Allow(8)
	}
	if err := l.Allow(8); !errors.Is(err, ErrRateLimitExceeded) {
		t.Fatalf("after draining burst, Allow should deny; got %v", err)
	}
	// Bump the rate way up → cached limiter is dropped, fresh bucket starts
	// full so the next Allow passes immediately.
	l.SetRatePerMin(8, 6000) // 100/s, burst 1000
	time.Sleep(2 * time.Millisecond)
	if err := l.Allow(8); err != nil {
		t.Errorf("after SetRatePerMin(6000), Allow should pass: %v", err)
	}
}
