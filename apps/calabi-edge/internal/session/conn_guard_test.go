package session

import (
	"errors"
	"testing"

	"github.com/calabi/calabi/apps/calabi-edge/internal/ratelimit"
)

// A session with no ConnGuard installed (dev / standalone / static-token)
// must let everything through: AcquireConn returns a usable no-op release
// and the rate gates never deny.
func TestSession_NoConnGuard_PassesThrough(t *testing.T) {
	s := &Session{}

	release, err := s.AcquireConn()
	if err != nil {
		t.Fatalf("unguarded AcquireConn err = %v, want nil", err)
	}
	if release == nil {
		t.Fatal("unguarded AcquireConn release must be non-nil (callers defer it)")
	}
	release() // must not panic

	if err := s.AllowHTTPConn(); err != nil {
		t.Errorf("unguarded AllowHTTPConn = %v, want nil", err)
	}
	if err := s.AllowTCPConn(); err != nil {
		t.Errorf("unguarded AllowTCPConn = %v, want nil", err)
	}
}

// With a guard installed, the concurrent cap is enforced and releasing a
// slot frees capacity for the next Acquire.
func TestSession_ConnGuard_EnforcesConcurrentCap(t *testing.T) {
	const org = int64(42)
	conns := ratelimit.NewConnLimiter(0)
	conns.SetCap(org, 2)
	s := &Session{}
	s.SetConnGuard(&ConnGuard{OrgID: org, Conns: conns})

	r1, err := s.AcquireConn()
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	if _, err := s.AcquireConn(); err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	if _, err := s.AcquireConn(); !errors.Is(err, ratelimit.ErrConnLimitExceeded) {
		t.Fatalf("acquire 3 should hit cap; got %v", err)
	}
	r1() // free one
	if _, err := s.AcquireConn(); err != nil {
		t.Fatalf("acquire after release should succeed: %v", err)
	}
}

// With a guard installed, the per-minute connection-rate gates enforce
// (TCP + HTTP buckets are independent).
func TestSession_ConnGuard_EnforcesRateGates(t *testing.T) {
	const org = int64(7)
	tcpRate := ratelimit.NewRateLimiter(0)
	httpRate := ratelimit.NewRateLimiter(0)
	tcpRate.SetRatePerMin(org, 60) // burst ~10
	s := &Session{}
	s.SetConnGuard(&ConnGuard{OrgID: org, TCPRate: tcpRate, HTTPRate: httpRate})

	tcpDenied := false
	for i := 0; i < 200; i++ {
		if err := s.AllowTCPConn(); errors.Is(err, ratelimit.ErrRateLimitExceeded) {
			tcpDenied = true
			break
		}
	}
	if !tcpDenied {
		t.Error("TCP rate gate never denied under a 60/min cap + flood")
	}
	// HTTP bucket was left unlimited (no SetRatePerMin) → never denies.
	for i := 0; i < 200; i++ {
		if err := s.AllowHTTPConn(); err != nil {
			t.Fatalf("HTTP gate (unlimited) denied: %v", err)
		}
	}
}
