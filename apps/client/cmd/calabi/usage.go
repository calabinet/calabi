package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/client/internal/localweb"
	"github.com/calabi/calabi/apps/client/internal/status"
)

// usageMeter is the standalone substitute for the platform's metering-svc: it
// accumulates total transferred bytes into per-day buckets (local date) by
// sampling the daemon's live per-tunnel byte counters, and persists them to disk
// so the console's "today" / "this month" traffic survive reconnects/restarts.
//
// Sampling deltas (not absolute totals) keeps it correct across the per-session
// counter resets that happen on every reconnect: when a tunnel's cumulative
// bytes drop (a fresh session started at 0), we count the new run from 0.
type usageMeter struct {
	path string
	mu   sync.Mutex
	days map[string]int64 // "2006-01-02" (local) -> bytes that day
	last map[int64]int64  // tunnel id -> last sampled cumulative bytes
}

func newUsageMeter(path string) *usageMeter {
	m := &usageMeter{path: path, days: map[string]int64{}, last: map[int64]int64{}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m.days) // best-effort; a corrupt file just starts fresh
		if m.days == nil {
			m.days = map[string]int64{}
		}
	}
	return m
}

// sample books the byte delta since the previous sample into today's bucket.
func (m *usageMeter) sample(tunnels []status.TunnelInfo, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := make(map[int64]bool, len(tunnels))
	var delta int64
	for _, t := range tunnels {
		if t.TunnelID == 0 {
			continue
		}
		seen[t.TunnelID] = true
		cur := t.BytesIn + t.BytesOut
		if prev := m.last[t.TunnelID]; cur >= prev {
			delta += cur - prev
		} else {
			delta += cur // counter reset (reconnect) — count the new run from 0
		}
		m.last[t.TunnelID] = cur
	}
	for id := range m.last { // forget closed tunnels (their bytes are already booked)
		if !seen[id] {
			delete(m.last, id)
		}
	}
	if delta > 0 {
		m.days[now.Format("2006-01-02")] += delta
		m.persistLocked()
	}
}

func (m *usageMeter) persistLocked() {
	if m.path == "" {
		return
	}
	if b, err := json.Marshal(m.days); err == nil {
		_ = os.WriteFile(m.path, b, 0o600)
	}
}

// TodayBytes / MonthBytes implement localweb.UsageSource.
func (m *usageMeter) TodayBytes() int64 {
	key := time.Now().Format("2006-01-02")
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.days[key]
}

func (m *usageMeter) MonthBytes() int64 {
	prefix := time.Now().Format("2006-01") // "2026-06"
	m.mu.Lock()
	defer m.mu.Unlock()
	var sum int64
	for day, n := range m.days {
		if strings.HasPrefix(day, prefix) {
			sum += n
		}
	}
	return sum
}

// DailyBytes returns the last n days (oldest→newest), each day's total bytes,
// filling days with no traffic as 0 so the chart shows a continuous 7-day span.
func (m *usageMeter) DailyBytes(n int) []localweb.UsageDay {
	if n <= 0 {
		n = 7
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]localweb.UsageDay, 0, n)
	for i := n - 1; i >= 0; i-- {
		key := now.AddDate(0, 0, -i).Format("2006-01-02")
		out = append(out, localweb.UsageDay{Date: key, Bytes: m.days[key]})
	}
	return out
}

// run samples the live byte counters on a ticker until ctx is done.
func (m *usageMeter) run(ctx context.Context, state *status.State, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.sample(state.SnapshotNow().Tunnels, time.Now()) // final flush
			return
		case <-t.C:
			m.sample(state.SnapshotNow().Tunnels, time.Now())
		}
	}
}
