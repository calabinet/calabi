package ratelimit

import (
	"errors"
	"testing"
	"time"
)

func TestDailyCounter_UnderAndOverCap(t *testing.T) {
	d := NewDailyCounter(0)
	d.SetLimit(7, 3)
	for i := 0; i < 3; i++ {
		if err := d.Allow(7); err != nil {
			t.Fatalf("event %d under cap should pass, got %v", i, err)
		}
	}
	if err := d.Allow(7); !errors.Is(err, ErrDailyLimitExceeded) {
		t.Fatalf("4th event over cap should be rejected, got %v", err)
	}
	// Rejected events don't grow the count past the limit.
	if got := d.Count(7); got != 3 {
		t.Fatalf("count should pin at limit 3, got %d", got)
	}
}

func TestDailyCounter_UnlimitedAlwaysAllows(t *testing.T) {
	d := NewDailyCounter(0)
	// limit 0 (default) and -1 both mean unlimited.
	d.SetLimit(9, -1)
	for i := 0; i < 100000; i++ {
		if err := d.Allow(9); err != nil {
			t.Fatalf("unlimited org should never be capped, got %v at %d", err, i)
		}
	}
	if err := d.Allow(123); err != nil { // no SetLimit → default 0 → unlimited
		t.Fatalf("org with no limit set should be unlimited, got %v", err)
	}
}

func TestDailyCounter_ResetsAtUTCDayBoundary(t *testing.T) {
	d := NewDailyCounter(0)
	d.SetLimit(7, 2)
	// Pin the clock to a fixed instant, then roll to the next UTC day.
	day1 := time.Date(2026, 6, 12, 23, 59, 0, 0, time.UTC)
	cur := day1
	d.now = func() time.Time { return cur }

	if err := d.Allow(7); err != nil {
		t.Fatalf("day1 #1: %v", err)
	}
	if err := d.Allow(7); err != nil {
		t.Fatalf("day1 #2: %v", err)
	}
	if err := d.Allow(7); !errors.Is(err, ErrDailyLimitExceeded) {
		t.Fatalf("day1 #3 should be capped, got %v", err)
	}

	// Cross UTC midnight → counter resets.
	cur = day1.Add(2 * time.Minute) // 2026-06-13 00:01 UTC
	if err := d.Allow(7); err != nil {
		t.Fatalf("day2 #1 after rollover should pass, got %v", err)
	}
	if got := d.Count(7); got != 1 {
		t.Fatalf("day2 count should be 1 after reset, got %d", got)
	}
}

func TestDailyCounter_SetLimitHotUpdate(t *testing.T) {
	d := NewDailyCounter(0)
	d.SetLimit(7, 5)
	for i := 0; i < 5; i++ {
		_ = d.Allow(7)
	}
	if err := d.Allow(7); !errors.Is(err, ErrDailyLimitExceeded) {
		t.Fatalf("should be capped at 5, got %v", err)
	}
	// Raise the cap mid-day → unblocks immediately (existing count preserved).
	d.SetLimit(7, 10)
	if err := d.Allow(7); err != nil {
		t.Fatalf("after raising cap, should pass, got %v", err)
	}
}
