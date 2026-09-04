package quotaclient

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	eventbus "github.com/calabi/calabi/apps/calabi-edge/internal/bus"
)

// CachedClient wraps Client with a per-org TTL cache and parallel
// fetch for the (bandwidth, online_client_limit) pair.
//
// Why
// ---
// Edge calls into quota-svc twice per AUTH handshake:
//   - OnlineClientLimit (cap)         → quota-svc.GetEffective
//   - BandwidthBytesPerSec (rate)     → quota-svc.GetEffective
//
// Both queries hit the same underlying row. In cross-region prod each
// round trip adds ~60-100ms, so two serial round trips cost ~200ms
// extra on every session start. For 10k clients reconnecting once a
// day that's 30k+ wasted round trips a day.
//
// The cache memoizes the (cap, rate) tuple keyed by org_id for 30s.
// Plan changes during a TTL window are tolerated because:
//   - the next 30s window picks them up; AUTHs admitted during the
//     window with a stale value will still get the right answer on
//     their next reconnect
//   - billing-svc publishes calabi.usage.deny.<org> /.allow.<org> on
//     hard transitions; this cache subscribes and invalidates the
//     affected org immediately for those high-stakes changes
//
// Pure local clock + TTL — no NATS at-least-once requirements.
//
// IMPORTANT: This cache memoizes PLAN-DERIVED values (cap + rate).
// It does NOT memoize the org's live online count — that always
// goes through identity-svc fresh, because the count moves every 10s
// presence tick and a stale view would silently break the cap.
type CachedClient struct {
	*Client

	logger *slog.Logger
	bus    eventbus.Bus
	sub    eventbus.Subscription

	ttl time.Duration

	mu      sync.RWMutex
	entries map[int64]quotaCacheEntry
}

type quotaCacheEntry struct {
	cap       int64 // -1 = unlimited, 0 = no opinion, >0 = numeric cap
	bps       int64 // sustained bytes/sec; 0 = unlimited
	peakBps   int64 // peak (burst) bytes/sec; 0 = no separate burst tier
	maxConns  int64 // concurrent visitor-connection cap; 0 = unlimited
	tcpRPM    int64 // new TCP/TLS(+SNI/UDP) connection rate, events/min; 0 = unlimited
	httpRPM   int64 // new HTTP(S) connection rate, events/min; 0 = unlimited
	expiresAt time.Time
}

// DefaultCacheTTL is the org-level quota cache TTL. 30s pairs with
// identity-svc's presence freshness window so a freshly-evicted org
// retries the lookup roughly when the count would've decayed anyway.
const DefaultCacheTTL = 30 * time.Second

// WithCache returns a CachedClient layered on top of c. The bus is
// optional; nil keeps the cache purely TTL-driven. Pass eventbus.Bus
// (already dialed by main) so the cache can react to usage.deny /
// usage.allow events instantly.
//
// ttl=0 picks DefaultCacheTTL.
func (c *Client) WithCache(logger *slog.Logger, bus eventbus.Bus, ttl time.Duration) *CachedClient {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	cc := &CachedClient{
		Client:  c,
		logger:  logger.With("component", "quotaclient.cache"),
		bus:     bus,
		ttl:     ttl,
		entries: make(map[int64]quotaCacheEntry, 32),
	}
	if bus != nil {
		// Subscribe to the deny/allow families — those are the only
		// signals that flip an org's effective quota mid-TTL.
		// usage.deny.<org> — monthly traffic exhausted
		// usage.allow.<org> — explicit re-enable (op tool)
		if s, err := bus.Subscribe("calabi.usage.deny.>", cc.onUsageEvent); err == nil {
			cc.sub = s
		} else {
			cc.logger.Warn("usage.deny subscribe failed; cache will rely on TTL only",
				"err", err)
		}
		// Best-effort — if the second subscribe fails we still have TTL.
		if _, err := bus.Subscribe("calabi.usage.allow.>", cc.onUsageEvent); err != nil {
			cc.logger.Warn("usage.allow subscribe failed", "err", err)
		}
	}
	return cc
}

// Close drains the bus subscription before delegating to the underlying
// Client. Safe to call multiple times.
func (cc *CachedClient) Close() error {
	if cc.sub != nil {
		_ = cc.sub.Drain()
		cc.sub = nil
	}
	return cc.Client.Close()
}

// onUsageEvent parses the org_id out of a deny/allow subject suffix
// and invalidates that entry. We rely on the payload's "org_id" field
// when present, falling back to the subject parse.
func (cc *CachedClient) onUsageEvent(m *eventbus.Msg) {
	var orgID int64
	// Subject shape: "calabi.usage.{deny,allow}.<org_id>"
	if idx := strings.LastIndexByte(m.Subject, '.'); idx >= 0 {
		var n int64
		_, _ = parseInt64(m.Subject[idx+1:], &n)
		orgID = n
	}
	if orgID == 0 {
		// Try the JSON body — defensive against future schema changes.
		var p struct {
			OrgID int64 `json:"org_id"`
		}
		if err := json.Unmarshal(m.Data, &p); err == nil {
			orgID = p.OrgID
		}
	}
	if orgID <= 0 {
		return
	}
	cc.invalidate(orgID)
	cc.logger.Debug("quota cache invalidated", "org_id", orgID, "subject", m.Subject)
}

// invalidate drops a single org's cache entry. Safe to call from any
// goroutine.
func (cc *CachedClient) invalidate(orgID int64) {
	cc.mu.Lock()
	delete(cc.entries, orgID)
	cc.mu.Unlock()
}

// LookupOrg returns the org's cached plan-derived limits, drawing on the
// cache first. On miss, fires all underlying lookups in PARALLEL (one
// round-trip's worth of latency instead of serial) and stores the result.
//
// Returns, in order:
//   - cap:      online-client cap (-1 unlimited, 0 no opinion, >0 numeric)
//   - bps/peak: bandwidth bytes/sec (0 = unlimited / no burst tier)
//   - maxConns: concurrent-connection cap (0 = unlimited)
//   - tcpRPM / httpRPM: new-connection rate caps, events/min (0 = unlimited)
//
// Returns the cap-lookup error if any (admit path fails closed). Bandwidth
// + connection caps degrade open on error per their Client contracts.
func (cc *CachedClient) LookupOrg(ctx context.Context, orgID int64) (cap, bps, peak, maxConns, tcpRPM, httpRPM int64, err error) {
	if cc == nil || cc.Client == nil || orgID <= 0 {
		return -1, 0, 0, 0, 0, 0, nil
	}
	// Cache fast path.
	cc.mu.RLock()
	e, ok := cc.entries[orgID]
	cc.mu.RUnlock()
	if ok && time.Now().Before(e.expiresAt) {
		return e.cap, e.bps, e.peakBps, e.maxConns, e.tcpRPM, e.httpRPM, nil
	}

	// Cache miss — fan out the underlying calls. Each GetEffective hits
	// the same row, but firing them concurrently keeps the handshake's
	// quota lookups at ~one round-trip of latency.
	type capResult struct {
		v   int64
		err error
	}
	type bwResult struct{ bps, peak int64 }
	type connResult struct{ maxConns, tcpRPM, httpRPM int64 }
	capCh := make(chan capResult, 1)
	bwCh := make(chan bwResult, 1)
	connCh := make(chan connResult, 1)
	go func() {
		v, ierr := cc.Client.OnlineClientLimit(ctx, orgID)
		capCh <- capResult{v: v, err: ierr}
	}()
	go func() {
		s, p := cc.Client.BandwidthLimitsBytesPerSec(ctx, orgID)
		bwCh <- bwResult{bps: s, peak: p}
	}()
	go func() {
		mc, t, h := cc.Client.ConnLimits(ctx, orgID)
		connCh <- connResult{maxConns: mc, tcpRPM: t, httpRPM: h}
	}()
	capR := <-capCh
	bwR := <-bwCh
	connR := <-connCh
	if capR.err != nil {
		// Cap is the fail-closed dimension; surface the error. Don't
		// write the cache so the next reconnect retries fresh.
		return 0, bwR.bps, bwR.peak, connR.maxConns, connR.tcpRPM, connR.httpRPM, capR.err
	}
	cc.mu.Lock()
	cc.entries[orgID] = quotaCacheEntry{
		cap:       capR.v,
		bps:       bwR.bps,
		peakBps:   bwR.peak,
		maxConns:  connR.maxConns,
		tcpRPM:    connR.tcpRPM,
		httpRPM:   connR.httpRPM,
		expiresAt: time.Now().Add(cc.ttl),
	}
	cc.mu.Unlock()
	return capR.v, bwR.bps, bwR.peak, connR.maxConns, connR.tcpRPM, connR.httpRPM, nil
}

// OnlineClientLimit honors the cache. Falls through to the underlying
// Client on cache miss + fresh-error.
func (cc *CachedClient) OnlineClientLimit(ctx context.Context, orgID int64) (int64, error) {
	cap, _, _, _, _, _, err := cc.LookupOrg(ctx, orgID)
	return cap, err
}

// BandwidthBytesPerSec honors the cache. Returns the sustained rate; 0 on
// any uncacheable error (matching the underlying Client's degrade-open).
func (cc *CachedClient) BandwidthBytesPerSec(ctx context.Context, orgID int64) int64 {
	_, bps, _, _, _, _, _ := cc.LookupOrg(ctx, orgID)
	return bps
}

// BandwidthLimitsBytesPerSec honors the cache; returns (sustained, peak).
func (cc *CachedClient) BandwidthLimitsBytesPerSec(ctx context.Context, orgID int64) (int64, int64) {
	_, bps, peak, _, _, _, _ := cc.LookupOrg(ctx, orgID)
	return bps, peak
}

// ConnLimits honors the cache; returns (maxConns, tcpRatePerMin,
// httpRatePerMin). Each 0 = unlimited. Degrades open (zeros) on error.
func (cc *CachedClient) ConnLimits(ctx context.Context, orgID int64) (maxConns, tcpRatePerMin, httpRatePerMin int64) {
	_, _, _, mc, t, h, _ := cc.LookupOrg(ctx, orgID)
	return mc, t, h
}

// parseInt64 is an alloc-free integer parser for the subject suffix.
// Returns (n, ok). Tolerates leading + or - sign.
func parseInt64(s string, out *int64) (int64, bool) {
	if s == "" {
		return 0, false
	}
	var neg bool
	i := 0
	if s[0] == '-' {
		neg = true
		i = 1
	} else if s[0] == '+' {
		i = 1
	}
	var n int64
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	*out = n
	return n, true
}
