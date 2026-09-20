// Package quotaclient is calabi-edge's gRPC client to quota-svc.
//
// Edge uses it once per session, right after handshake, to look up the
// effective bandwidth_kbps for the session's org and configure the
// per-session token bucket. The lookup degrades open on any failure
// (returns 0 = unlimited) so quota-svc being down doesn't choke users.
//
// Unrelated to apps/tunnel-svc/internal/quotaclient — same upstream,
// different consumer. Keeping it separated avoids a hard dep on
// tunnel-svc from edge.
package quotaclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"google.golang.org/grpc"

	pb "github.com/calabinet/calabi/pkg/edge-proto/edgepb"
)

// RPC is the narrow subset of pb.QuotaClient the edge actually uses.
// In bff-edge mode the caller wraps bff_edge.BFFEdgeClient via
// bffedgeclient.NewQuotaAdapter to satisfy this interface; in cluster
// mode pb.QuotaClient itself satisfies it directly.
type RPC interface {
	GetEffective(ctx context.Context, in *pb.GetEffectiveRequest, opts ...grpc.CallOption) (*pb.EffectiveQuota, error)
}

// Client wraps the grpc connection to quota-svc.
type Client struct {
	conn   *grpc.ClientConn // nil when constructed via Wrap (shared conn)
	cli    RPC
	logger *slog.Logger
}

// Wrap constructs a Client from a pre-made gRPC client (e.g. a
// bff-edge adapter). Close() is a no-op for wrapped instances.
func Wrap(logger *slog.Logger, client RPC) *Client {
	return &Client{
		cli:    client,
		logger: logger.With("component", "quotaclient"),
	}
}

// The direct-dial constructor was removed in F3 step 2b: every edge now
// reaches the control plane through bff-edge, so this package is only ever
// handed a ready client.
// Close releases the underlying conn.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// BandwidthBytesPerSec returns the effective bandwidth cap for orgID
// expressed in bytes/sec. Returns 0 on any failure (unlimited) and logs
// the reason at debug — we don't want a quota-svc outage to refuse
// service.
//
// The plan's quotas_json carries `bandwidth_kbps`; we convert to
// bytes/sec on the way out. -1 in the JSON means "unlimited" → also 0.
func (c *Client) BandwidthBytesPerSec(ctx context.Context, orgID int64) int64 {
	if c == nil || c.cli == nil || orgID <= 0 {
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	resp, err := c.cli.GetEffective(ctx, &pb.GetEffectiveRequest{OrgId: orgID})
	if err != nil {
		c.logger.Debug("get effective quota failed; defaulting to unlimited",
			"org", orgID, "err", err)
		return 0
	}
	kbps, ok := extractKbps(resp.GetQuotasJson())
	if !ok || kbps <= 0 {
		return 0
	}
	return int64(kbps) * 1024 / 8
}

// OnlineClientLimit returns the org's max_online_clients quota value.
// -1 = unlimited (caller skips the gate). 0 with err=nil means the
// plan has no opinion (missing key); the caller should treat that as
// unlimited so older un-migrated plans don't accidentally lock anyone
// out.
//
// Distinct from BandwidthBytesPerSec' "degrade open on error" policy:
// this method surfaces RPC errors so the caller can decide. The edge
// admit path fails closed (refuses the session) on error because
// admitting silently breaks the cap.
func (c *Client) OnlineClientLimit(ctx context.Context, orgID int64) (int64, error) {
	if c == nil || c.cli == nil || orgID <= 0 {
		return -1, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	resp, err := c.cli.GetEffective(ctx, &pb.GetEffectiveRequest{OrgId: orgID})
	if err != nil {
		return 0, err
	}
	if resp.GetQuotasJson() == "" {
		return -1, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(resp.GetQuotasJson()), &m); err != nil {
		return 0, err
	}
	raw, ok := m["max_online_clients"]
	if !ok {
		return -1, nil
	}
	switch v := raw.(type) {
	case float64:
		return int64(v), nil
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("max_online_clients not a number: %v", v)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("max_online_clients unexpected type %T", raw)
	}
}

// Bandwidth is an org's TWO-TIER bandwidth allowance in bytes/sec:
//
//   - Sustained / Peak      = bandwidth_kbps / bandwidth_burst_kbps,
//     applied to EACH TUNNEL (套餐「带宽速度 / 带宽上限」).
//   - OrgSustained / OrgPeak = org_bandwidth_kbps / org_bandwidth_burst_kbps,
//     applied to the org as a whole.
//
// 0 in any field = no limit at that tier. An absent org_* key therefore
// leaves the org tier off, which is what every plan row looked like before
// the keys were seeded — an old row must not suddenly throttle anyone.
type Bandwidth struct {
	Sustained    int64
	Peak         int64
	OrgSustained int64
	OrgPeak      int64
	// OrgRelaySustained / OrgRelayPeak are the org-wide tier for MESH RELAY
	// traffic (org_relay_bandwidth_kbps). A separate allowance from the tunnel
	// one on purpose — the two are metered separately and enforced in different
	// processes, so one shared number could not be honoured across them. The
	// PER-DEVICE relay rate reuses Sustained / Peak.
	//
	OrgRelaySustained int64
	OrgRelayPeak      int64
}

// BandwidthCapsBytesPerSec returns both tiers from ONE GetEffective.
// Degrades open (zero value = unlimited) on any failure so a quota-svc
// outage doesn't choke users.
func (c *Client) BandwidthCapsBytesPerSec(ctx context.Context, orgID int64) Bandwidth {
	if c == nil || c.cli == nil || orgID <= 0 {
		return Bandwidth{}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	resp, err := c.cli.GetEffective(ctx, &pb.GetEffectiveRequest{OrgId: orgID})
	if err != nil {
		c.logger.Debug("get effective quota failed; defaulting to unlimited",
			"org", orgID, "err", err)
		return Bandwidth{}
	}
	return bandwidthCapsFromJSON(resp.GetQuotasJson())
}

// BandwidthLimitsBytesPerSec returns only the per-tunnel tier. Kept for
// callers that do not care about the org tier.
func (c *Client) BandwidthLimitsBytesPerSec(ctx context.Context, orgID int64) (sustained, peak int64) {
	b := c.BandwidthCapsBytesPerSec(ctx, orgID)
	return b.Sustained, b.Peak
}

// OrgBandwidthLimitsBytesPerSec returns only the org-wide tier.
//
// On the uncached Client this costs a second GetEffective when the caller
// also asked for the per-tunnel tier. That is fine because production wires
// the CachedClient, whose override answers both from one cached row; the
// uncached path is dev / tests.
func (c *Client) OrgBandwidthLimitsBytesPerSec(ctx context.Context, orgID int64) (sustained, peak int64) {
	b := c.BandwidthCapsBytesPerSec(ctx, orgID)
	return b.OrgSustained, b.OrgPeak
}

// ConnLimits returns the org's anti-abuse connection caps from quota
// (Phase A, 2026-06-11):
//   - maxConns:       concurrent visitor-connection cap (max_conns)
//   - tcpRatePerMin:  new TCP/TLS(+SNI/UDP-flow) connection rate, events/min
//   - httpRatePerMin: new HTTP(S) connection rate, events/min
//
// Each is 0 = unlimited (absent or -1 in the JSON), positive otherwise.
// Degrades open to (0,0,0) on any failure so a quota-svc outage doesn't
// choke users — abuse protection is best-effort, never a hard dependency.
func (c *Client) ConnLimits(ctx context.Context, orgID int64) (maxConns, tcpRatePerMin, httpRatePerMin int64) {
	if c == nil || c.cli == nil || orgID <= 0 {
		return 0, 0, 0
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	resp, err := c.cli.GetEffective(ctx, &pb.GetEffectiveRequest{OrgId: orgID})
	if err != nil {
		c.logger.Debug("get effective quota failed; defaulting to unlimited conn caps",
			"org", orgID, "err", err)
		return 0, 0, 0
	}
	return connLimitsFromJSON(resp.GetQuotasJson())
}

// connLimitsFromJSON pulls the three connection caps out of a quotas_json
// blob. Reuses extractKbpsKey's parse (number / string / absent, negatives
// treated as the unlimited sentinel) — the helper is kbps-named for
// history but its semantics fit any non-negative int quota field.
func connLimitsFromJSON(quotasJSON string) (maxConns, tcpRatePerMin, httpRatePerMin int64) {
	if v, ok := extractKbpsKey(quotasJSON, "max_conns"); ok && v > 0 {
		maxConns = int64(v)
	}
	if v, ok := extractKbpsKey(quotasJSON, "tcp_conn_rate_per_min"); ok && v > 0 {
		tcpRatePerMin = int64(v)
	}
	if v, ok := extractKbpsKey(quotasJSON, "http_conn_rate_per_min"); ok && v > 0 {
		httpRatePerMin = int64(v)
	}
	return
}

// DailyLimits returns the org's per-day anti-abuse caps from quota
// (2026-06-12):
//   - dailyTCPConns: new TCP/TLS(+SNI/UDP-flow) connections per UTC day
//   - dailyHTTPReqs: HTTP/HTTPS requests per UTC day (true per-request)
//
// Each is 0 = unlimited (absent or -1 in the JSON), positive otherwise. Only
// the free plan carries finite caps today; every paid tier is unlimited.
// Degrades open to (0,0) on any failure so a quota-svc outage never blocks
// users. *CachedClient inherits this (uncached) via its embedded *Client —
// fine, since it's only read once per session handshake.
func (c *Client) DailyLimits(ctx context.Context, orgID int64) (dailyTCPConns, dailyHTTPReqs int64) {
	if c == nil || c.cli == nil || orgID <= 0 {
		return 0, 0
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	resp, err := c.cli.GetEffective(ctx, &pb.GetEffectiveRequest{OrgId: orgID})
	if err != nil {
		c.logger.Debug("get effective quota failed; defaulting to unlimited daily caps",
			"org", orgID, "err", err)
		return 0, 0
	}
	return dailyLimitsFromJSON(resp.GetQuotasJson())
}

// dailyLimitsFromJSON pulls the two per-day caps out of a quotas_json blob.
func dailyLimitsFromJSON(quotasJSON string) (dailyTCPConns, dailyHTTPReqs int64) {
	if v, ok := extractKbpsKey(quotasJSON, "daily_tcp_conns"); ok && v > 0 {
		dailyTCPConns = int64(v)
	}
	if v, ok := extractKbpsKey(quotasJSON, "daily_http_reqs"); ok && v > 0 {
		dailyHTTPReqs = int64(v)
	}
	return
}

// bandwidthCapsFromJSON extracts both tiers from a quotas_json blob.
// kbps→bytes/sec uses the same *1024/8 convention throughout.
func bandwidthCapsFromJSON(quotasJSON string) Bandwidth {
	kbpsToBps := func(key string) int64 {
		if kbps, ok := extractKbpsKey(quotasJSON, key); ok && kbps > 0 {
			return int64(kbps) * 1024 / 8
		}
		return 0
	}
	return Bandwidth{
		Sustained:         kbpsToBps("bandwidth_kbps"),
		Peak:              kbpsToBps("bandwidth_burst_kbps"),
		OrgSustained:      kbpsToBps("org_bandwidth_kbps"),
		OrgPeak:           kbpsToBps("org_bandwidth_burst_kbps"),
		OrgRelaySustained: kbpsToBps("org_relay_bandwidth_kbps"),
		OrgRelayPeak:      kbpsToBps("org_relay_bandwidth_burst_kbps"),
	}
}

// bandwidthLimitsFromJSON extracts (sustained, peak) bytes/sec from a
// quotas_json blob — the per-tunnel tier only.
func bandwidthLimitsFromJSON(quotasJSON string) (sustained, peak int64) {
	b := bandwidthCapsFromJSON(quotasJSON)
	return b.Sustained, b.Peak
}

// extractKbps pulls bandwidth_kbps out of a quotas_json blob.
func extractKbps(quotasJSON string) (int, bool) {
	return extractKbpsKey(quotasJSON, "bandwidth_kbps")
}

// extractKbpsKey pulls an integer kbps value for `key` out of a quotas_json
// blob. We tolerate the field being a JSON number (int or float), a string,
// or absent. Returns (0, false) for "unlimited" sentinels (-1) / absent.
func extractKbpsKey(quotasJSON, key string) (int, bool) {
	if quotasJSON == "" {
		return 0, false
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(quotasJSON), &m); err != nil {
		return 0, false
	}
	raw, ok := m[key]
	if !ok {
		return 0, false
	}
	switch v := raw.(type) {
	case float64:
		if v < 0 {
			return 0, false
		}
		return int(v), true
	case int:
		if v < 0 {
			return 0, false
		}
		return v, true
	case string:
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
