package ratelimit

import "testing"

func TestGlobalLimiter_Unlimited(t *testing.T) {
	g := NewGlobalLimiter(0, 0)
	if g.Configured() {
		t.Error("0/0 limiter should report not configured")
	}
	for i := 0; i < 1000; i++ {
		if !g.AllowAccept() {
			t.Fatal("unlimited accept must never deny")
		}
		rel, ok := g.AcquireConn()
		if !ok || rel == nil {
			t.Fatal("unlimited acquire must always succeed with a usable release")
		}
		rel()
	}
}

func TestGlobalLimiter_NilSafe(t *testing.T) {
	var g *GlobalLimiter // nil
	if !g.AllowAccept() {
		t.Error("nil limiter AllowAccept must return true")
	}
	rel, ok := g.AcquireConn()
	if !ok || rel == nil {
		t.Error("nil limiter AcquireConn must succeed with a no-op release")
	}
	rel() // must not panic
	if g.Active() != 0 || g.Configured() {
		t.Error("nil limiter Active/Configured must be 0/false")
	}
}

func TestGlobalLimiter_ConcurrentCap(t *testing.T) {
	g := NewGlobalLimiter(3, 0)
	if !g.Configured() {
		t.Error("maxConns>0 should report configured")
	}
	rels := make([]func(), 0, 3)
	for i := 0; i < 3; i++ {
		rel, ok := g.AcquireConn()
		if !ok {
			t.Fatalf("acquire %d should succeed under cap 3", i)
		}
		rels = append(rels, rel)
	}
	if _, ok := g.AcquireConn(); ok {
		t.Error("4th acquire must be denied at cap 3")
	}
	if g.Active() != 3 {
		t.Errorf("Active = %d, want 3", g.Active())
	}
	rels[0]() // free one
	if _, ok := g.AcquireConn(); !ok {
		t.Error("acquire after release should succeed")
	}
}

func TestGlobalLimiter_AcceptRate(t *testing.T) {
	// 10/sec, burst = 10. A same-instant flood passes the burst then denies.
	g := NewGlobalLimiter(0, 10)
	allowed := 0
	for i := 0; i < 100; i++ {
		if g.AllowAccept() {
			allowed++
		}
	}
	if allowed < 1 || allowed > 15 {
		t.Errorf("flood of 100 at 10/s should pass ~burst(10), allowed=%d", allowed)
	}
}
