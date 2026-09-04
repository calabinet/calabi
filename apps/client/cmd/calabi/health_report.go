// health_report.go — platform-only daemon background reporter that pushes
// per-tunnel upstream (local_addr) health to bff-console, so the cloud console
// can show "异常 / upstream unreachable" instead of a misleading "online".
//
// The probe.Monitor already detects upstream reachability locally (and the
// on-device :7400 console shows it); this closes the gap by forwarding the
// signal to the cloud over the daemon's existing authenticated bff-console
// channel (same creds clientreg uses). No edge / control-protocol changes.
//
// Design:
//   - Reads the monitor snapshot on a ticker (aligned with the 30s probe).
//   - Maps each probe Result's proxy_id → cloud tunnel_id via the registry;
//     skips proxies that aren't claimed cloud tunnels (standalone/local-only).
//   - Anti-flap: reports "unhealthy" only after 2 consecutive bad probes
//     (~60s), "healthy" on the first good probe. Avoids crying wolf on a
//     single blip while still flipping back fast on recovery.
//   - Only POSTs on a state CHANGE vs what was last reported, plus a periodic
//     re-assert (every 5 min) so a dropped POST self-heals.
//   - Best-effort throughout: any error is logged and retried next tick; it
//     never blocks the data plane.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/probe"
)

// upstreamHealthReporter forwards probe results to bff-console.
type upstreamHealthReporter struct {
	logger  *slog.Logger
	mon     *probe.Monitor
	reg     *daemonRegistry
	baseURL string
	httpc   *http.Client

	// last reported healthy state + when, keyed by tunnel_id.
	lastHealthy map[int64]bool
	lastSentAt  map[int64]time.Time
}

const (
	upstreamReportInterval = 30 * time.Second // matches the probe cadence
	upstreamReassertEvery  = 5 * time.Minute  // periodic re-assert / self-heal
	upstreamBadThreshold   = 2                // consecutive bad probes before "unhealthy"
)

// runUpstreamHealthReporter loops until ctx is cancelled. Safe to start even
// when the daemon has no creds yet — each tick re-resolves the token and
// no-ops when absent (login may happen after boot).
func runUpstreamHealthReporter(ctx context.Context, logger *slog.Logger, mon *probe.Monitor, reg *daemonRegistry, baseURL string) {
	if mon == nil || reg == nil || strings.TrimSpace(baseURL) == "" {
		return
	}
	r := &upstreamHealthReporter{
		logger:      logger.With("component", "upstream-health-reporter"),
		mon:         mon,
		reg:         reg,
		baseURL:     strings.TrimRight(baseURL, "/"),
		httpc:       &http.Client{Timeout: 6 * time.Second},
		lastHealthy: make(map[int64]bool),
		lastSentAt:  make(map[int64]time.Time),
	}
	t := time.NewTicker(upstreamReportInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tick(ctx)
		}
	}
}

func (r *upstreamHealthReporter) tick(ctx context.Context) {
	results := r.mon.Snapshot()
	if len(results) == 0 {
		return
	}
	token := resolveReportToken()
	if token == "" {
		return // not logged in / no api-key yet — nothing to report with
	}
	seen := make(map[int64]struct{}, len(results))
	for _, res := range results {
		tid, ok := r.reg.TunnelIDByProxyID(res.ProxyID)
		if !ok || tid == 0 {
			continue // not a claimed cloud tunnel
		}
		seen[tid] = struct{}{}
		// Debounce: a single failed probe shouldn't flip the cloud to "异常".
		healthy := res.Healthy
		if !healthy && res.ConsecutiveBad < upstreamBadThreshold {
			continue // still within the grace window; wait for confirmation
		}
		prev, had := r.lastHealthy[tid]
		stale := time.Since(r.lastSentAt[tid]) >= upstreamReassertEvery
		if had && prev == healthy && !stale {
			continue // unchanged + freshly asserted — skip
		}
		if r.post(ctx, token, tid, healthy, res.Error) {
			r.lastHealthy[tid] = healthy
			r.lastSentAt[tid] = time.Now()
		}
	}
	// Forget tunnels that are no longer live so a re-appearing one re-reports.
	for tid := range r.lastHealthy {
		if _, ok := seen[tid]; !ok {
			delete(r.lastHealthy, tid)
			delete(r.lastSentAt, tid)
		}
	}
}

func (r *upstreamHealthReporter) post(ctx context.Context, token string, tunnelID int64, healthy bool, errMsg string) bool {
	body, _ := json.Marshal(map[string]any{"healthy": healthy, "error": errMsg})
	url := fmt.Sprintf("%s/v1/tunnels/%d/upstream-health", r.baseURL, tunnelID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.httpc.Do(req)
	if err != nil {
		r.logger.Debug("upstream health post failed", "tunnel_id", tunnelID, "err", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		r.logger.Debug("upstream health post non-2xx", "tunnel_id", tunnelID, "code", resp.StatusCode)
		return false
	}
	return true
}

// resolveReportToken mirrors clientreg.tokenFor: prefer the rotating login
// access token, fall back to the long-lived API key (agent mode). Re-read each
// tick so a post-boot login starts reporting without a restart.
func resolveReportToken() string {
	cfg, err := creds.Load()
	if err != nil || cfg == nil {
		return ""
	}
	if cfg.AccessToken != "" {
		return cfg.AccessToken
	}
	return cfg.APIKey
}
