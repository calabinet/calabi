package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// meshUsageMeter is the Connect (mesh) counterpart of usageMeter: it books mesh
// PEER traffic into per-day buckets by sampling MeshStatus's byte counters, and
// persists them so the overview's mesh usage (today / this month) and the 7-day
// chart's second series survive restarts.
//
// It runs in BOTH editions and is always LOCAL — mesh traffic is never metered
// server-side per machine, unlike tunnels (whose daily history the platform
// pulls from metering-svc). So the daemon serves /v1/usage/mesh from this meter
// directly rather than proxying it.
//
// Each day is split by transport — relay (via a DERP relay) vs direct (a
// hole-punched peer-to-peer path) — so the overview can show 中继 / 直连 apart:
// direct traffic never touches a platform node and is never billed, while relay
// traffic is billed when the relay is a platform one. The split can't come from
// the server (it never sees direct at all), so both halves live here.
//
// Deltas keyed by peer public key: a peer's rx+tx is a cumulative WireGuard
// counter that resets to 0 on every mesh reconnect, so a drop is a fresh run
// counted from 0 — the same treatment usageMeter gives a tunnel reset.
type meshUsageMeter struct {
	path string
	mu   sync.Mutex
	days map[string]*dayBytes // "2006-01-02" (local) -> that day's relay/direct split
	last map[string]int64     // peer public key -> last sampled cumulative rx+tx
}

// meshPathDirect mirrors mesh.PathDirect (internal/mesh/status.go). Kept as a
// literal so this dual-edition file need not import internal/mesh. Anything that
// is NOT this exact value — "relay", or an unknown/empty path — books into the
// relay bucket, the conservative choice since relay is the billed one.
const meshPathDirect = "direct"

// dayBytes is one day's mesh bytes split by transport. Relay is (potentially)
// billed; Direct never is.
type dayBytes struct {
	Relay  int64 `json:"relay"`
	Direct int64 `json:"direct"`
}

// meshPeerBytes is one peer's cumulative rx+tx plus the transport its traffic is
// taking right now. It decouples the meter from the two MeshStatus shapes
// (localweb / statusapi), so each daemon extracts its own.
type meshPeerBytes struct {
	Key   string
	Bytes int64
	Path  string // "direct" | "relay" | "" (unknown); see meshPathDirect
}

func newMeshUsageMeter(path string) *meshUsageMeter {
	m := &meshUsageMeter{path: path, days: map[string]*dayBytes{}, last: map[string]int64{}}
	if b, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(b, &m.days) != nil {
			// Pre-split on-disk shape was flat {"date": bytes}. Migrate every day
			// into the relay bucket — the old meter couldn't tell relay from
			// direct, and relay is the billed (conservative) bucket.
			m.days = map[string]*dayBytes{}
			var flat map[string]int64
			if json.Unmarshal(b, &flat) == nil {
				for d, n := range flat {
					m.days[d] = &dayBytes{Relay: n}
				}
			}
		}
		if m.days == nil {
			m.days = map[string]*dayBytes{}
		}
	}
	return m
}

// dayLocked returns a day's bucket, creating it if absent or nil (a null entry
// can survive a hand-edited / partially-written file).
func (m *meshUsageMeter) dayLocked(key string) *dayBytes {
	d := m.days[key]
	if d == nil {
		d = &dayBytes{}
		m.days[key] = d
	}
	return d
}

// sample books the byte delta since the previous sample into today's bucket,
// attributing each peer's delta to relay or direct by its CURRENT path. The path
// is the transport the next packet would take, applied to the whole interval's
// delta — an approximation good enough for a display split, since a peer rarely
// flips transport mid-interval.
func (m *meshUsageMeter) sample(peers []meshPeerBytes, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := make(map[string]bool, len(peers))
	var relay, direct int64
	for _, p := range peers {
		if p.Key == "" {
			continue
		}
		seen[p.Key] = true
		var d int64
		if prev := m.last[p.Key]; p.Bytes >= prev {
			d = p.Bytes - prev
		} else {
			d = p.Bytes // counter reset (mesh reconnect) — count the new run from 0
		}
		m.last[p.Key] = p.Bytes
		if p.Path == meshPathDirect {
			direct += d
		} else {
			relay += d
		}
	}
	for k := range m.last { // forget peers that left (their bytes are already booked)
		if !seen[k] {
			delete(m.last, k)
		}
	}
	if relay > 0 || direct > 0 {
		day := m.dayLocked(now.Format("2006-01-02"))
		day.Relay += relay
		day.Direct += direct
		m.persistLocked()
	}
}

func (m *meshUsageMeter) persistLocked() {
	if m.path == "" {
		return
	}
	if b, err := json.Marshal(m.days); err == nil {
		_ = os.WriteFile(m.path, b, 0o600)
	}
}

func (m *meshUsageMeter) today() dayBytes {
	key := time.Now().Format("2006-01-02")
	m.mu.Lock()
	defer m.mu.Unlock()
	if d := m.days[key]; d != nil {
		return *d
	}
	return dayBytes{}
}

func (m *meshUsageMeter) month() dayBytes {
	prefix := time.Now().Format("2006-01")
	m.mu.Lock()
	defer m.mu.Unlock()
	var sum dayBytes
	for day, d := range m.days {
		if d != nil && strings.HasPrefix(day, prefix) {
			sum.Relay += d.Relay
			sum.Direct += d.Direct
		}
	}
	return sum
}

type meshUsageDay struct {
	Date   string `json:"date"`
	Relay  int64  `json:"relay"`
	Direct int64  `json:"direct"`
}

// daily returns the last n days (oldest→newest), gaps filled with 0 so the chart
// shows a continuous span aligned with the tunnel series.
func (m *meshUsageMeter) daily(n int) []meshUsageDay {
	if n <= 0 {
		n = 7
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]meshUsageDay, 0, n)
	for i := n - 1; i >= 0; i-- {
		key := now.AddDate(0, 0, -i).Format("2006-01-02")
		d := m.days[key]
		if d == nil {
			d = &dayBytes{}
		}
		out = append(out, meshUsageDay{Date: key, Relay: d.Relay, Direct: d.Direct})
	}
	return out
}

// handleMeshUsage serves GET /v1/usage/mesh?days=N →
//
//	{"today":{relay,direct},"month":{relay,direct},"daily":[{date,relay,direct}...]}
//
// Read-only; registered on the status server's mux in package main (both
// editions) so it never rides the platform's server-side usage proxy.
func (m *meshUsageMeter) handleMeshUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 && d <= 90 {
			n = d
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"today": m.today(),
		"month": m.month(),
		"daily": m.daily(n),
	})
}

// run samples the mesh peers on a ticker until ctx is done. sampler returns the
// current per-peer byte totals (nil/empty when the mesh is down — a no-op).
func (m *meshUsageMeter) run(ctx context.Context, sampler func() []meshPeerBytes, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.sample(sampler(), time.Now()) // final flush
			return
		case <-t.C:
			m.sample(sampler(), time.Now())
		}
	}
}
