package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/calabi/calabi/apps/client/internal/status"
)

func TestUsageMeter_AccumulatesResetsAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	m := newUsageMeter(path)
	now := time.Now()

	// First sample: tunnel 1 at 100 bytes total → +100.
	m.sample([]status.TunnelInfo{{TunnelID: 1, BytesIn: 60, BytesOut: 40}}, now)
	if got := m.TodayBytes(); got != 100 {
		t.Fatalf("first sample: TodayBytes=%d want 100", got)
	}
	// Grows to 250 → +150 (delta, not absolute).
	m.sample([]status.TunnelInfo{{TunnelID: 1, BytesIn: 150, BytesOut: 100}}, now)
	if got := m.TodayBytes(); got != 250 {
		t.Fatalf("growth: TodayBytes=%d want 250", got)
	}
	// Reconnect: counter resets to 30 (< 250) → count the new run from 0 (+30).
	m.sample([]status.TunnelInfo{{TunnelID: 1, BytesIn: 20, BytesOut: 10}}, now)
	if got := m.TodayBytes(); got != 280 {
		t.Fatalf("after reset: TodayBytes=%d want 280", got)
	}

	// Survives restart (reload from disk) and rolls up into the month.
	m2 := newUsageMeter(path)
	if got := m2.TodayBytes(); got != 280 {
		t.Fatalf("reloaded TodayBytes=%d want 280", got)
	}
	if got := m2.MonthBytes(); got != 280 {
		t.Fatalf("MonthBytes=%d want 280", got)
	}
}

func TestUsageMeter_DailyBytes(t *testing.T) {
	m := newUsageMeter(filepath.Join(t.TempDir(), "usage.json"))
	now := time.Now()
	today := now.Format("2006-01-02")
	twoAgo := now.AddDate(0, 0, -2).Format("2006-01-02")
	m.days[today] = 500
	m.days[twoAgo] = 200

	got := m.DailyBytes(7)
	if len(got) != 7 {
		t.Fatalf("DailyBytes(7) len=%d want 7", len(got))
	}
	// Oldest→newest: last bucket is today, [4] is two days ago, gaps are 0.
	if got[6].Date != today || got[6].Bytes != 500 {
		t.Errorf("today bucket = %+v, want {%s 500}", got[6], today)
	}
	if got[4].Date != twoAgo || got[4].Bytes != 200 {
		t.Errorf("two-days-ago bucket = %+v, want {%s 200}", got[4], twoAgo)
	}
	if got[5].Bytes != 0 {
		t.Errorf("gap day bucket bytes = %d, want 0", got[5].Bytes)
	}
}
