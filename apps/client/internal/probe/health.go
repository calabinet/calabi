// health.go — per-tunnel reachability checks.
//
// The bug we're solving: "the tunnel shows green in the console but
// visitors are getting 502s." Cause: the local upstream (dev server,
// db, etc.) crashed but the calabi client itself is still happily
// dialing on each incoming connection — neither side knows until the
// next connection attempt fails.
//
// This package runs a background loop that probes every registered
// tunnel's LocalAddr at a regular cadence and exposes the rolling
// status via a snapshot map. The status server surfaces it under
// /v1/probe/health so the UI can decorate the tunnel rows with a
// health badge.
//
// Lifecycle:
//
//   m := health.New(logger)
//   m.SetSources(registry)  // pulls live tunnel list from anywhere
//   ctx, cancel := context.WithCancel(...)
//   go m.Run(ctx)            // loops until ctx cancels
//
//   // From the HTTP handler:
//   m.Snapshot() -> map[proxy_id]Result
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TunnelSource is the small interface the health monitor uses to
// discover what to probe. Daemon mode passes the tracking registry;
// tests pass a static slice via SliceSource.
type TunnelSource interface {
	// LiveTunnels returns the current set: proxy_id → (type, local_addr).
	// Implementations should snapshot inside the call (no locks held
	// after return).
	LiveTunnels() []TunnelTarget
}

// TunnelTarget is the minimum a probe needs.
type TunnelTarget struct {
	ProxyID   string
	Type      string // "http" | "https" | "tcp" | "udp" | "sni"
	LocalAddr string
}

// SliceSource adapts a static []TunnelTarget for tests / one-shot
// snapshots. Goroutine-safe via the embedded mutex.
type SliceSource struct {
	mu   sync.RWMutex
	rows []TunnelTarget
}

// Set replaces the slice atomically.
func (s *SliceSource) Set(rows []TunnelTarget) {
	s.mu.Lock()
	s.rows = append([]TunnelTarget(nil), rows...)
	s.mu.Unlock()
}

// LiveTunnels implements TunnelSource.
func (s *SliceSource) LiveTunnels() []TunnelTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]TunnelTarget(nil), s.rows...)
}

// Result is what we publish per tunnel. Healthy=false + Error filled
// means the probe failed; ConsecutiveBad ramps so the UI can show
// "1 missed check" vs "5 in a row" (the latter is when we ring the
// notification bell).
type Result struct {
	ProxyID         string `json:"proxy_id"`
	Healthy         bool   `json:"healthy"`
	CheckedAt       string `json:"checked_at"`
	LatencyMs       int64  `json:"latency_ms"`
	Error           string `json:"error,omitempty"`
	ConsecutiveBad  int    `json:"consecutive_bad"`
	ConsecutiveGood int    `json:"consecutive_good"`
}

// Monitor runs the periodic probe loop and stores results.
type Monitor struct {
	logger   *slog.Logger
	interval time.Duration

	mu      sync.RWMutex
	source  TunnelSource
	results map[string]Result
}

// New constructs a Monitor with a 30s interval (matching the "config
// freshness" SLA most upstreams set).
func New(logger *slog.Logger) *Monitor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Monitor{
		logger:   logger.With("component", "client.health"),
		interval: 30 * time.Second,
		results:  make(map[string]Result),
	}
}

// SetInterval lets tests crank the loop faster.
func (m *Monitor) SetInterval(d time.Duration) {
	m.mu.Lock()
	m.interval = d
	m.mu.Unlock()
}

// SetSource installs the live-tunnels lookup. Safe to call before or
// after Run starts.
func (m *Monitor) SetSource(s TunnelSource) {
	m.mu.Lock()
	m.source = s
	m.mu.Unlock()
}

// Run loops until ctx cancels. Each tick: snapshot the live tunnels,
// probe each in parallel (bounded), update the results map. Stale
// proxy_ids (tunnels that disappeared) get GC'd.
func (m *Monitor) Run(ctx context.Context) {
	// Initial probe — don't make the user wait 30s to see the first row.
	m.tick(ctx)
	t := time.NewTicker(m.snapshotInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.tick(ctx)
		}
	}
}

func (m *Monitor) snapshotInterval() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.interval
}

func (m *Monitor) tick(ctx context.Context) {
	m.mu.RLock()
	src := m.source
	m.mu.RUnlock()
	if src == nil {
		return
	}
	targets := src.LiveTunnels()

	// Probe in parallel with bounded fanout.
	type slot struct {
		id  string
		res Result
	}
	out := make(chan slot, len(targets))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, t := range targets {
		t := t
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res := probeOne(ctx, t)
			out <- slot{id: t.ProxyID, res: res}
		}()
	}
	wg.Wait()
	close(out)

	// Merge under write lock; preserve consecutive counters across ticks.
	m.mu.Lock()
	live := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		live[t.ProxyID] = struct{}{}
	}
	for s := range out {
		prev := m.results[s.id]
		merged := s.res
		merged.ProxyID = s.id
		if merged.Healthy {
			merged.ConsecutiveGood = prev.ConsecutiveGood + 1
			merged.ConsecutiveBad = 0
		} else {
			merged.ConsecutiveBad = prev.ConsecutiveBad + 1
			merged.ConsecutiveGood = 0
		}
		m.results[s.id] = merged
		// Log on flip — useful when investigating "why did the badge go red"
		if prev.Healthy && !merged.Healthy {
			m.logger.Warn("local upstream went down", "proxy_id", s.id, "err", merged.Error)
		} else if !prev.Healthy && merged.Healthy && prev.ConsecutiveBad > 0 {
			m.logger.Info("local upstream recovered", "proxy_id", s.id, "after", prev.ConsecutiveBad)
		}
	}
	// GC: drop results whose proxy_id is no longer in the live set.
	for id := range m.results {
		if _, ok := live[id]; !ok {
			delete(m.results, id)
		}
	}
	m.mu.Unlock()
}

// Snapshot returns the current results map as a slice (ordered by
// proxy_id for stable JSON output).
func (m *Monitor) Snapshot() []Result {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Result, 0, len(m.results))
	for _, r := range m.results {
		out = append(out, r)
	}
	return out
}

// probeOne picks the probe flavour based on tunnel type. HTTP tunnels
// get an HTTP GET / (because a TCP connect succeeds for any process
// that's listening, but a real HTTP backend may be hung); TCP/UDP
// tunnels get a TCP dial only (UDP "connect" succeeds without round
// trip, so it's not informative).
func probeOne(ctx context.Context, t TunnelTarget) Result {
	checkedAt := time.Now().UTC().Format(time.RFC3339)
	if t.LocalAddr == "" {
		return Result{Healthy: false, CheckedAt: checkedAt, Error: "no local_addr"}
	}
	ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	start := time.Now()

	switch strings.ToLower(t.Type) {
	case "http", "https":
		// One small HTTP GET; we accept any non-5xx as "alive" since
		// 404 / 401 just means the path isn't there, not that the
		// process is dead.
		scheme := "http"
		if t.Type == "https" {
			scheme = "https"
		}
		req, _ := http.NewRequestWithContext(ctx2, "GET", scheme+"://"+t.LocalAddr+"/", nil)
		client := &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				// Don't follow into the network; we only want loopback.
				DisableKeepAlives:   true,
				TLSHandshakeTimeout: 1 * time.Second,
				// Skip TLS verify -- this probe runs against the user's
				// LOCAL upstream (Home Assistant, dev server, internal
				// device on the LAN). Self-signed + expired certs are
				// the norm there; MITM on a loopback / private-network
				// dial isn't the threat we're defending against. The
				// previous code claimed to skip verify in the comment
				// but never set TLSClientConfig, so strict verify won
				// silently and every HTTPS probe failed with x509 errors.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			return Result{Healthy: false, CheckedAt: checkedAt,
				LatencyMs: time.Since(start).Milliseconds(), Error: err.Error()}
		}
		resp.Body.Close()
		ok := resp.StatusCode < 500
		errMsg := ""
		if !ok {
			errMsg = "upstream returned " + resp.Status
		}
		return Result{Healthy: ok, CheckedAt: checkedAt,
			LatencyMs: time.Since(start).Milliseconds(), Error: errMsg}

	default:
		d := net.Dialer{Timeout: 2 * time.Second}
		c, err := d.DialContext(ctx2, "tcp", t.LocalAddr)
		if err != nil {
			// Try IPv6 fallback once before giving up.
			if c2, e2 := d.DialContext(ctx2, "tcp6", t.LocalAddr); e2 == nil {
				_ = c2.Close()
				return Result{Healthy: true, CheckedAt: checkedAt,
					LatencyMs: time.Since(start).Milliseconds()}
			}
			return Result{Healthy: false, CheckedAt: checkedAt,
				LatencyMs: time.Since(start).Milliseconds(), Error: errMessage(err)}
		}
		_ = c.Close()
		return Result{Healthy: true, CheckedAt: checkedAt,
			LatencyMs: time.Since(start).Milliseconds()}
	}
}

func errMessage(err error) string {
	if err == nil {
		return ""
	}
	// net.OpError prints the full "dial tcp 127.0.0.1:8080: ..." which
	// is more noise than signal. Trim to just the cause.
	if oe, ok := err.(*net.OpError); ok && oe.Err != nil {
		return oe.Err.Error()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return err.Error()
}
