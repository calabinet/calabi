package ratelimit

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestConnLimiter_EnforcesCap(t *testing.T) {
	l := NewConnLimiter(100)
	l.SetCap(7, 3)

	rels := make([]func(), 0, 3)
	for i := 0; i < 3; i++ {
		rel, err := l.Acquire(7)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		rels = append(rels, rel)
	}
	if _, err := l.Acquire(7); !errors.Is(err, ErrConnLimitExceeded) {
		t.Errorf("4th acquire: err = %v, want ErrConnLimitExceeded", err)
	}
	// Release one → next acquire should succeed.
	rels[0]()
	if _, err := l.Acquire(7); err != nil {
		t.Errorf("after release: %v", err)
	}
}

func TestConnLimiter_UnlimitedOrg(t *testing.T) {
	l := NewConnLimiter(2)
	l.SetCap(99, 0) // unlimited

	for i := 0; i < 100; i++ {
		if _, err := l.Acquire(99); err != nil {
			t.Fatalf("unlimited orgs shouldn't error at %d: %v", i, err)
		}
	}
	if l.Active(99) != 100 {
		t.Errorf("Active = %d, want 100", l.Active(99))
	}
}

func TestConnLimiter_DefaultCapApplies(t *testing.T) {
	l := NewConnLimiter(2)
	// org 5 has no explicit SetCap — gets default 2.
	_, err1 := l.Acquire(5)
	_, err2 := l.Acquire(5)
	_, err3 := l.Acquire(5)
	if err1 != nil || err2 != nil {
		t.Fatalf("first two acquires must succeed: %v %v", err1, err2)
	}
	if !errors.Is(err3, ErrConnLimitExceeded) {
		t.Errorf("3rd acquire should hit default cap; got %v", err3)
	}
}

func TestConnLimiter_ConcurrentRace(t *testing.T) {
	// 1000 goroutines racing on cap=100 → exactly 100 must succeed.
	l := NewConnLimiter(0)
	l.SetCap(42, 100)
	var ok, denied int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Acquire(42); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			} else {
				mu.Lock()
				denied++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 100 {
		t.Errorf("ok=%d, want exactly 100 (cap)", ok)
	}
	if ok+denied != 1000 {
		t.Errorf("ok+denied = %d, want 1000", ok+denied)
	}
}

func TestQPSLimiter_EnforcesCap(t *testing.T) {
	l := NewQPSLimiter(0)
	l.SetRate(7, 5) // 5 QPS

	allowed := 0
	for i := 0; i < 20; i++ {
		if err := l.Allow(7); err == nil {
			allowed++
		}
	}
	if allowed < 1 || allowed > 6 {
		t.Errorf("first burst allowed=%d, want ~5 (burst); rate=5", allowed)
	}
}

func TestQPSLimiter_Unlimited(t *testing.T) {
	l := NewQPSLimiter(0)
	for i := 0; i < 1000; i++ {
		if err := l.Allow(99); err != nil {
			t.Fatalf("unlimited org should never deny: %v", err)
		}
	}
}

func TestQPSLimiter_SetRateInvalidatesCache(t *testing.T) {
	l := NewQPSLimiter(0)
	l.SetRate(8, 1)
	if err := l.Allow(8); err != nil {
		t.Fatal("first call should pass burst")
	}
	if err := l.Allow(8); err == nil {
		t.Fatal("second call same-tick should deny at rate=1")
	}

	l.SetRate(8, 1000) // upgrade
	// After bumping rate, next Allow should succeed even at the same instant.
	// Give the limiter a tick to materialize the new bucket.
	time.Sleep(2 * time.Millisecond)
	if err := l.Allow(8); err != nil {
		t.Errorf("after SetRate(1000), Allow should succeed: %v", err)
	}
}
