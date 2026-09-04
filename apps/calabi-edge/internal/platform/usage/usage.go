// Package usage publishes per-tunnel bandwidth usage reports to NATS and
// subscribes to per-org deny signals.
//
// Reporter scope:
//
//   - Reporter: every 60s, walk the session manager and each session's
//     proxies, sum BytesIn / BytesOut by (org_id, tunnel_id), publish to
//     "calabi.usage.report". One message per (org, tunnel) with a
//     non-zero delta since the last report. tunnel_id=0 is the
//     "unattributed" bucket (standalone proxies / the session-level
//     fallback counter), and org-level totals are recovered by summing
//     across tunnel_id downstream — see metering-svc.
//
//   - DenyHook: subscribes to "calabi.usage.deny.>". Subjects are
//     "calabi.usage.deny.<org_id>" with a JSON body `{"reason": "..."}`.
//     The hook maintains an atomic set of blocked org_ids; new
//     OpenProxyConn calls for those orgs are refused. In-flight
//     proxies keep serving. NOTE: quota
//     enforcement stays ORG-level; tunnel_id is a reporting dimension
//     only.
//
// Publisher format (JSON):
//
//	{
//	  "edge_node_id": "edge-1",
//	  "org_id": 42,
//	  "tunnel_id": 1234,
//	  "ts": 1716000000,
//	  "bytes_in":  12345,
//	  "bytes_out": 6789
//	}
//
// We intentionally don't include tenant / workspace strings — metering
// keys on (org_id, tunnel_id) only. Edge sums local activity since the
// last report.
package usage

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	eventbus "github.com/calabi/calabi/apps/calabi-edge/internal/bus"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
)

// SubjectReport is where edges publish usage deltas.
const SubjectReport = "calabi.usage.report"

// SubjectDenyPrefix is the wildcard subject the edge subscribes to.
// Concrete subjects look like "calabi.usage.deny.42" for org_id=42.
const SubjectDenyPrefix = "calabi.usage.deny."

// SubjectAllowPrefix lifts a previous deny for the same org. The
// publisher (metering-svc.usagedeny) emits one when an org's usage
// drops back below the monthly cap (typically at month rollover).
// Wire shape mirrors Deny — the reason field is informational only.
const SubjectAllowPrefix = "calabi.usage.allow."

// DefaultReportInterval is the cadence the reporter ticks at.
const DefaultReportInterval = 60 * time.Second

// Report is the JSON wire shape published to SubjectReport.
type Report struct {
	// EdgeNodeID is the reporting edge's NUMERIC control-plane id. It was a
	// STRING (this node's label) until the 2026-09 cutover, and NodeLabel now
	// carries what it used to hold. metering-svc accepts either form, so it can
	// ship first and edges can follow whenever — but it MUST ship first: an old
	// consumer drops a numeric id instead of billing it.
	EdgeNodeID int64  `json:"edge_node_id"`
	NodeLabel  string `json:"node_label"`
	OrgID      int64  `json:"org_id"`
	// TunnelID is the tunnel-svc row id the bytes are attributed to.
	// 0 = unattributed (standalone proxy / session-level fallback).
	// metering-svc reconstructs org totals by summing across tunnel_id.
	TunnelID  int64  `json:"tunnel_id"`
	Timestamp int64  `json:"ts"`
	BytesIn   uint64 `json:"bytes_in"`
	BytesOut  uint64 `json:"bytes_out"`
}

// Deny is the JSON wire shape consumed from SubjectDenyPrefix.<org_id>.
// reason is informational; the wire never carries a per-org-quota policy
// (that lives in quota-svc / metering-svc).
type Deny struct {
	Reason string `json:"reason"`
}

// Reporter periodically publishes per-tunnel bandwidth deltas. The bytes
// counters live on *session.Proxy (and, as a fallback, *session.Session);
// we accumulate the last-seen value per counter-source key so a
// disconnect / tunnel teardown doesn't double-count.
type Reporter struct {
	logger *slog.Logger
	bus    eventbus.Bus
	mgr    *session.Manager
	// edgeNodeID is the numeric control-plane id every report is attributed
	// to; nodeLabel is this node's human name, sent alongside for display.
	// Keeping each named for what it holds is the point of the 2026-09
	// cutover — the wire used to carry the label under the name edge_node_id.
	edgeNodeID int64
	nodeLabel  string
	interval   time.Duration

	// last is keyed by a counter-source key:
	//   "<sessID>|p|<proxyID>"  for a per-tunnel proxy counter
	//   "<sessID>|s"            for the session-level fallback counter
	// Values are the cumulative byte counters last reported.
	// Diff = current - last.
	mu   sync.Mutex
	last map[string]counterTotals
}

type counterTotals struct {
	bytesIn  uint64
	bytesOut uint64
}

// NewReporter builds an unstarted reporter. interval=0 uses default.
func NewReporter(logger *slog.Logger, bus eventbus.Bus, mgr *session.Manager, edgeNodeID int64, nodeLabel string, interval time.Duration) *Reporter {
	if interval == 0 {
		interval = DefaultReportInterval
	}
	return &Reporter{
		logger:     logger.With("component", "usage.reporter"),
		bus:        bus,
		mgr:        mgr,
		edgeNodeID: edgeNodeID,
		nodeLabel:  nodeLabel,
		interval:   interval,
		last:       make(map[string]counterTotals),
	}
}

// Run blocks until ctx is cancelled. Ticks every Interval, publishes
// one Report per (org_id, tunnel_id) with a non-zero delta.
func (r *Reporter) Run(ctx context.Context) error {
	if r.bus == nil {
		r.logger.Info("usage reporter: no event bus configured; idling")
		<-ctx.Done()
		return nil
	}
	tick := time.NewTicker(r.interval)
	defer tick.Stop()
	r.logger.Info("usage reporter running", "interval", r.interval)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			r.tick()
		}
	}
}

func (r *Reporter) tick() {
	// Sum by (org_id, tunnel_id), computing deltas vs. the last snapshot
	// per counter source. We walk each session's proxies (per-tunnel
	// counters) plus the session-level fallback counter (tunnel_id=0).
	type aggKey struct {
		org    int64
		tunnel int64
	}
	deltaIn := map[aggKey]uint64{}
	deltaOut := map[aggKey]uint64{}

	// live tracks the counter-source keys seen this tick, for GC.
	live := make(map[string]struct{})

	// accumulate diffs one counter source against its last snapshot and
	// folds the non-zero delta into the (org, tunnel) bucket.
	accumulate := func(mapKey string, org, tunnel int64, curIn, curOut uint64) {
		live[mapKey] = struct{}{}
		r.mu.Lock()
		prev := r.last[mapKey]
		r.last[mapKey] = counterTotals{curIn, curOut}
		r.mu.Unlock()
		dIn := curIn - prev.bytesIn
		dOut := curOut - prev.bytesOut
		if dIn == 0 && dOut == 0 {
			return
		}
		k := aggKey{org, tunnel}
		deltaIn[k] += dIn
		deltaOut[k] += dOut
	}

	r.mgr.All(func(s *session.Session) bool {
		org, _ := strconv.ParseInt(s.TenantID, 10, 64)
		if org <= 0 {
			// non-numeric tenant (dev / static-YAML mode); skip
			return true
		}
		// Per-tunnel proxy counters.
		for _, px := range s.Proxies() {
			accumulate(s.ID+"|p|"+px.ID, org, px.TunnelID,
				px.BytesIn.Load(), px.BytesOut.Load())
		}
		// Session-level fallback bucket (tunnel_id=0). Normally stays 0;
		// only grows for connections that couldn't be attributed to a
		// proxy (rare race / standalone), keeping org totals lossless.
		accumulate(s.ID+"|s", org, 0, s.BytesIn.Load(), s.BytesOut.Load())
		return true
	})

	now := time.Now().Unix()
	for k, dIn := range deltaIn {
		rep := Report{
			EdgeNodeID: r.edgeNodeID,
			NodeLabel:  r.nodeLabel,
			OrgID:      k.org,
			TunnelID:   k.tunnel,
			Timestamp:  now,
			BytesIn:    dIn,
			BytesOut:   deltaOut[k],
		}
		payload, _ := json.Marshal(rep)
		if err := r.bus.Publish(SubjectReport, payload); err != nil {
			r.logger.Warn("publish usage report failed",
				"org", k.org, "tunnel", k.tunnel, "err", err)
		}
	}

	// Garbage-collect entries whose counter source no longer exists
	// (session ended / tunnel torn down). live was populated above in the
	// same walk, so this prunes at most one tick late.
	r.gcLastMap(live)
}

func (r *Reporter) gcLastMap(live map[string]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id := range r.last {
		if _, ok := live[id]; !ok {
			delete(r.last, id)
		}
	}
}

// DenyHook tracks the set of org_ids the cluster has marked over-quota.
// New OpenProxyConn / NEW_PROXY calls for these orgs should be refused;
// in-flight tunnels keep serving.
//
// The set is loaded from NATS via Subscribe and an atomic.Pointer to a
// map[int64]string (reason) so reads stay lock-free.
type DenyHook struct {
	logger *slog.Logger
	bus    eventbus.Bus

	denied atomic.Pointer[map[int64]string]
	sub    eventbus.Subscription
	// allowSub is the parallel subscription for "calabi.usage.allow.<org>"
	// — same hook clears the entry from the denied map when received.
	allowSub eventbus.Subscription
}

// NewDenyHook builds an unstarted hook.
func NewDenyHook(logger *slog.Logger, bus eventbus.Bus) *DenyHook {
	h := &DenyHook{
		logger: logger.With("component", "usage.deny"),
		bus:    bus,
	}
	empty := map[int64]string{}
	h.denied.Store(&empty)
	return h
}

// Start subscribes to the deny + allow topics. Returns nil if the bus
// is nil (no-op mode is valid for tests / dev).
func (h *DenyHook) Start() error {
	if h == nil || h.bus == nil {
		return nil
	}
	sub, err := h.bus.Subscribe(SubjectDenyPrefix+">", func(msg *eventbus.Msg) {
		// Subject format: calabi.usage.deny.<org_id>
		orgStr := strings.TrimPrefix(msg.Subject, SubjectDenyPrefix)
		org, err := strconv.ParseInt(orgStr, 10, 64)
		if err != nil || org <= 0 {
			h.logger.Warn("deny: malformed subject", "subject", msg.Subject)
			return
		}
		var body Deny
		_ = json.Unmarshal(msg.Data, &body)
		h.set(org, body.Reason)
		h.logger.Info("org blocked", "org", org, "reason", body.Reason)
	})
	if err != nil {
		return err
	}
	h.sub = sub

	// Parallel subscription for allow events. Same wire shape as Deny.
	allowSub, err := h.bus.Subscribe(SubjectAllowPrefix+">", func(msg *eventbus.Msg) {
		orgStr := strings.TrimPrefix(msg.Subject, SubjectAllowPrefix)
		org, err := strconv.ParseInt(orgStr, 10, 64)
		if err != nil || org <= 0 {
			h.logger.Warn("allow: malformed subject", "subject", msg.Subject)
			return
		}
		h.Allow(org)
		h.logger.Info("org unblocked", "org", org)
	})
	if err != nil {
		// Roll back the deny subscription to keep state clean.
		_ = h.sub.Drain()
		h.sub = nil
		return err
	}
	h.allowSub = allowSub
	return nil
}

// Close drains both underlying subscriptions.
func (h *DenyHook) Close() error {
	if h == nil {
		return nil
	}
	var firstErr error
	if h.sub != nil {
		if err := h.sub.Drain(); err != nil {
			firstErr = err
		}
	}
	if h.allowSub != nil {
		if err := h.allowSub.Drain(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// IsBlocked returns (true, reason) if NATS has flagged orgID over-quota.
func (h *DenyHook) IsBlocked(orgID int64) (bool, string) {
	if h == nil {
		return false, ""
	}
	m := h.denied.Load()
	if m == nil {
		return false, ""
	}
	reason, ok := (*m)[orgID]
	return ok, reason
}

// Allow lifts a previous deny. Mostly for tests; production rotation
// would come via a "calabi.usage.allow.<org>" subject.
func (h *DenyHook) Allow(orgID int64) {
	if h == nil {
		return
	}
	prev := h.denied.Load()
	if prev == nil {
		return
	}
	next := make(map[int64]string, len(*prev))
	for k, v := range *prev {
		if k != orgID {
			next[k] = v
		}
	}
	h.denied.Store(&next)
}

func (h *DenyHook) set(orgID int64, reason string) {
	prev := h.denied.Load()
	next := make(map[int64]string, len(*prev)+1)
	for k, v := range *prev {
		next[k] = v
	}
	next[orgID] = reason
	h.denied.Store(&next)
}
