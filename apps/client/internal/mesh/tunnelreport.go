package mesh

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// The tunnels a self-hosted daemon serves, reported to its coordinator so the
// meshnet's phones can list them and add up their traffic. A platform coordinator
// refuses the report — calabi.net keeps tunnels in its own services — and the
// loop then stops for the session.

// TunnelState is one tunnel as the daemon serves it now.
type TunnelState struct {
	Name, Type, PublicAddr, LocalAddr string
	// Status: "online", "pending" or "offline".
	Status string
	// Instance names this run of the byte counters below. They restart from 0
	// whenever the tunnel is registered with its edge again, and a new Instance
	// is how the meter tells that apart from a counter that went backwards.
	Instance          string
	BytesIn, BytesOut int64
}

// TunnelReport is one tunnel as ReportTunnels sends it: its current state and
// the bytes it carried since the last accepted report.
type TunnelReport struct {
	Name, Type, PublicAddr, LocalAddr, Status string
	BytesIn, BytesOut                         int64
}

type tunnelReading struct {
	instance string
	in, out  int64
}

// TunnelMeter turns a daemon's cumulative tunnel counters into what each report
// adds. It belongs to the daemon, not to a session: a session that ends and a
// new one that starts must not count the same bytes twice. The baseline moves
// only when a report is accepted, so a failed one delays bytes rather than
// losing them.
type TunnelMeter struct {
	read func() []TunnelState

	mu    sync.Mutex
	acked map[string]tunnelReading
}

// NewTunnelMeter meters what read returns.
func NewTunnelMeter(read func() []TunnelState) *TunnelMeter {
	return &TunnelMeter{read: read, acked: map[string]tunnelReading{}}
}

// pending is the report to send now, and the readings it was taken from.
func (m *TunnelMeter) pending() ([]TunnelReport, map[string]tunnelReading) {
	states := m.read()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TunnelReport, 0, len(states))
	readings := make(map[string]tunnelReading, len(states))
	for _, s := range states {
		if _, dup := readings[s.Name]; dup || s.Name == "" {
			continue
		}
		cur := tunnelReading{instance: s.Instance, in: max(s.BytesIn, 0), out: max(s.BytesOut, 0)}
		readings[s.Name] = cur
		r := TunnelReport{Name: s.Name, Type: s.Type, PublicAddr: s.PublicAddr, LocalAddr: s.LocalAddr, Status: s.Status,
			BytesIn: cur.in, BytesOut: cur.out}
		// The same run of counters: what it added since the last accepted report.
		// A new run started from zero, so all of it is new.
		if prev, ok := m.acked[s.Name]; ok && prev.instance == cur.instance && cur.in >= prev.in && cur.out >= prev.out {
			r.BytesIn, r.BytesOut = cur.in-prev.in, cur.out-prev.out
		}
		out = append(out, r)
	}
	return out, readings
}

// ack moves the baseline to the readings of a report the coordinator accepted.
func (m *TunnelMeter) ack(readings map[string]tunnelReading) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acked = readings
}

// tunnelReportInterval is how often a desktop reports its tunnels when nothing
// about them changed: often enough that a crash costs minutes of traffic.
const tunnelReportInterval = 5 * time.Minute

// TunnelReportEvery is tunnelReportInterval, for a daemon that runs the report
// loop itself (TunnelMeter.Report).
const TunnelReportEvery = tunnelReportInterval

// tunnelChangeCheck is how often the report loop looks for a tunnel that came
// up, went down or was added, to report it without waiting for the interval.
var tunnelChangeCheck = 15 * time.Second // a var for tests

// tunnelReportRetry is how long a failed report waits before the next try, at
// most: a coordinator that is away, or refuses, is not asked every
// tunnelChangeCheck.
var tunnelReportRetry = time.Minute // a var for tests

// tunnelReportLoop reports c.Tunnels over the session at once, whenever the list
// changes, and every Timing.TunnelReport in between. It stops for the session
// when the coordinator will not take reports: a platform one (PermissionDenied)
// or one older than ReportTunnels (Unimplemented).
func (c *Controller) tunnelReportLoop(ctx context.Context) {
	if c.Tunnels == nil || c.Coord == nil {
		return
	}
	c.Tunnels.Report(ctx, c.timing().TunnelReport, c.Coord.ReportTunnels, func(err error) bool {
		switch status.Code(err) {
		case codes.PermissionDenied, codes.Unimplemented:
			c.logf(slog.LevelInfo, "this coordinator does not keep tunnels; not reporting them", "err", err)
			return true
		}
		c.logf(slog.LevelDebug, "tunnel report failed; the next one carries its bytes", "err", err)
		return false
	})
}

// Report sends the meter's tunnels with send at once, whenever the list
// changes, and every `every` in between, until ctx ends — or until failed says
// to stop after a report send could not deliver. A failed report moves no
// baseline, so the next one carries its bytes; it is tried again after
// tunnelReportRetry (or `every`, if shorter), not at every look for a change.
func (m *TunnelMeter) Report(ctx context.Context, every time.Duration, send func(context.Context, []TunnelReport) error, failed func(error) (stop bool)) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(min(every, tunnelChangeCheck))
	defer t.Stop()
	var lastShape string
	var lastSent, retryAt time.Time
	for {
		reports, readings := m.pending()
		shape := tunnelShape(reports)
		if (shape != lastShape || time.Since(lastSent) >= every) && !time.Now().Before(retryAt) {
			if err := send(ctx, reports); err == nil {
				m.ack(readings)
				lastShape, lastSent, retryAt = shape, time.Now(), time.Time{}
			} else if failed != nil && failed(err) {
				return
			} else {
				retryAt = time.Now().Add(min(every, tunnelReportRetry))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// tunnelShape is what a list looks like without its byte counts: a change in it
// is worth reporting now.
func tunnelShape(reports []TunnelReport) string {
	parts := make([]string, 0, len(reports))
	for _, r := range reports {
		parts = append(parts, strings.Join([]string{r.Name, r.Type, r.PublicAddr, r.LocalAddr, r.Status}, "\x1f"))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x1e")
}

// ReportTunnels sends the daemon's current tunnels to a self-hosted coordinator.
func (c *CoordClient) ReportTunnels(ctx context.Context, reports []TunnelReport) error {
	req := &meshpb.ReportTunnelsRequest{SessionToken: c.sessionToken()}
	for _, r := range reports {
		req.Tunnels = append(req.Tunnels, &meshpb.TunnelReport{
			Name: r.Name, Type: r.Type, PublicAddr: r.PublicAddr, LocalAddr: r.LocalAddr, Status: r.Status,
			BytesIn: r.BytesIn, BytesOut: r.BytesOut,
		})
	}
	_, err := c.rpc.ReportTunnels(ctx, req)
	return err
}

// TunnelInfo is one tunnel of the meshnet as ListTunnels reports it.
type TunnelInfo struct {
	ID         int64
	NodeID     int64
	NodeName   string
	NodeOnline bool
	Name       string
	Type       string
	PublicAddr string
	LocalAddr  string
	Status     string
	Traffic30d int64
	FirstSeen  time.Time
	ReportedAt time.Time
}

// ListTunnels lists every tunnel the meshnet's daemons reported to a self-hosted
// coordinator.
func (c *CoordClient) ListTunnels(ctx context.Context) ([]TunnelInfo, error) {
	resp, err := c.rpc.ListTunnels(ctx, &meshpb.ListTunnelsRequest{SessionToken: c.sessionToken()})
	if err != nil {
		return nil, err
	}
	out := make([]TunnelInfo, 0, len(resp.GetTunnels()))
	for _, t := range resp.GetTunnels() {
		out = append(out, TunnelInfo{
			ID: t.GetId(), NodeID: t.GetNodeId(), NodeName: t.GetNodeName(), NodeOnline: t.GetNodeOnline(),
			Name: t.GetName(), Type: t.GetType(), PublicAddr: t.GetPublicAddr(), LocalAddr: t.GetLocalAddr(),
			Status: t.GetStatus(), Traffic30d: t.GetTraffic_30D(),
			FirstSeen: time.Unix(t.GetFirstSeenUnix(), 0), ReportedAt: time.Unix(t.GetReportedUnix(), 0),
		})
	}
	return out, nil
}

// Usage is a meshnet's traffic through a self-hosted server, as GetUsage reports it.
type Usage struct {
	// Unavailable says why there are no traffic figures ("no_database"); Month
	// is then nil.
	Unavailable      string
	RelayNotRecorded bool
	Month            *UsageMonth
	Days             []UsageDay
	DevicesUsed      int64
	DevicesDisabled  int64
	// DevicesLimit is -1 for no limit.
	DevicesLimit int64
}

// UsageMonth is the viewer's current month, [From, To).
type UsageMonth struct {
	From, To                time.Time
	TunnelBytes, RelayBytes int64
}

// UsageDay is one of the viewer's days: tunnels plus relay.
type UsageDay struct {
	Start time.Time
	Bytes int64
}

// GetUsage reads the meshnet's traffic for a viewer in timeZone (IANA; "" =
// UTC), over the last days days.
func (c *CoordClient) GetUsage(ctx context.Context, timeZone string, days int) (Usage, error) {
	resp, err := c.rpc.GetUsage(ctx, &meshpb.GetUsageRequest{SessionToken: c.sessionToken(), TimeZone: timeZone, Days: int32(days)})
	if err != nil {
		return Usage{}, err
	}
	u := Usage{
		Unavailable: resp.GetUnavailable(), RelayNotRecorded: resp.GetRelayNotRecorded(),
		DevicesUsed: resp.GetDevicesUsed(), DevicesDisabled: resp.GetDevicesDisabled(), DevicesLimit: resp.GetDevicesLimit(),
	}
	if m := resp.GetMonth(); m != nil {
		u.Month = &UsageMonth{
			From: time.Unix(m.GetFromUnix(), 0), To: time.Unix(m.GetToUnix(), 0),
			TunnelBytes: m.GetTunnelBytes(), RelayBytes: m.GetRelayBytes(),
		}
	}
	for _, d := range resp.GetDays() {
		u.Days = append(u.Days, UsageDay{Start: time.Unix(d.GetStartUnix(), 0), Bytes: d.GetBytes()})
	}
	return u, nil
}

// OpenViewSession proves the node key to a self-hosted coordinator for a
// read-only session, which this client then reads with: ListNodes, ListTunnels
// and GetUsage work until it expires, without the node being connected and
// without ending a session it may hold elsewhere. Only for a client that is not
// also the node's live session.
func (c *CoordClient) OpenViewSession(ctx context.Context, nodeID int64, key meshproto.NodeKey, priv PrivateKey) (time.Time, error) {
	chr, err := c.rpc.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{NodeId: nodeID, NodeKey: key.String()})
	if err != nil {
		return time.Time{}, err
	}
	ch, err := meshproto.ParseRegisterChallenge(chr.GetChallenge())
	if err != nil {
		return time.Time{}, err
	}
	resp, err := c.rpc.OpenViewSession(ctx, &meshpb.OpenViewSessionRequest{
		NodeId: nodeID, NodeKey: key.String(), ChallengeId: chr.GetChallengeId(),
		Proof: meshproto.SealRegisterProof(ch, key, [meshproto.KeyLen]byte(priv)),
	})
	if err != nil {
		return time.Time{}, err
	}
	c.sessMu.Lock()
	c.session = resp.GetViewToken()
	c.sessMu.Unlock()
	return time.Unix(resp.GetExpiresUnix(), 0), nil
}
