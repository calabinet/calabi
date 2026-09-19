package core

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Tunnels and usage for a self-hosted coordinator's apps.
//
// A self-hosted phone talks to nothing but its coordinator, so what a platform
// user reads from tunnel-svc and metering-svc has to come from here: each
// desktop daemon that is also a mesh device reports the tunnels it serves
// (ReportTunnels), and the coordinator keeps the current list plus hourly
// traffic. Information only — a tunnel grants nothing in the mesh, so none of
// this is ever an authorization input, and none of it needs approving.
//
// The platform coordinator refuses these reports: there, tunnels live in
// tunnel-svc and traffic in metering-svc.

// Tunnel is one reverse tunnel as its node last reported it.
type Tunnel struct {
	ID         int64
	Meshnet    MeshnetID
	NodeID     int64
	Name       string
	Type       string
	PublicAddr string
	LocalAddr  string
	Status     string
	// FirstSeen is when the node first reported a tunnel by this name;
	// ReportedAt when it last reported at all.
	FirstSeen  time.Time
	ReportedAt time.Time
}

// TunnelReport is one entry of a node's report: the tunnel as it is now, and
// the bytes it carried since the node's last accepted report.
type TunnelReport struct {
	Name, Type, PublicAddr, LocalAddr, Status string
	BytesIn, BytesOut                         int64
}

// TunnelKey names a tunnel across reports: a node and the name in its config.
type TunnelKey struct {
	NodeID int64
	Name   string
}

// TunnelUsage is one tunnel's traffic in one UTC hour.
type TunnelUsage struct {
	Meshnet  MeshnetID
	NodeID   int64
	Name     string
	Hour     time.Time
	BytesIn  int64
	BytesOut int64
}

// TunnelStore keeps each node's current tunnel list.
type TunnelStore interface {
	// ReplaceTunnels makes list the node's tunnels: a name it no longer reports
	// goes, a name it reported before keeps its id and FirstSeen.
	ReplaceTunnels(ctx context.Context, t MeshnetID, nodeID int64, list []Tunnel, now time.Time) error
	ListTunnels(ctx context.Context, t MeshnetID) ([]Tunnel, error)
	DeleteTunnelsOf(ctx context.Context, nodeID int64) error
}

// TunnelUsageStore keeps tunnel traffic by the hour. Database only: a
// coordinator without one reports usage as unavailable rather than as zero.
type TunnelUsageStore interface {
	// AddTunnelUsage adds to whatever is stored for each (node, name, hour).
	AddTunnelUsage(ctx context.Context, rows []TunnelUsage) error
	// TunnelBytesByHour is a meshnet's tunnel traffic, both ways, per UTC hour
	// in [from, to).
	TunnelBytesByHour(ctx context.Context, t MeshnetID, from, to time.Time) (map[time.Time]int64, error)
	// TunnelBytesSince is each tunnel's traffic, both ways, since since.
	TunnelBytesSince(ctx context.Context, t MeshnetID, since time.Time) (map[TunnelKey]int64, error)
	PurgeTunnelUsageBefore(ctx context.Context, cutoff time.Time) (int, error)
}

const (
	// maxTunnelsPerReport bounds one node's list. A daemon serving more is
	// misconfigured or probing; the excess is dropped, not stored.
	maxTunnelsPerReport = 256
	maxTunnelNameLen    = 128
	maxTunnelFieldLen   = 255
	// TunnelUsageRetention is how long hourly tunnel traffic is kept: enough for
	// "last 30 days" and a whole month in any time zone, with room to spare.
	TunnelUsageRetention = 92 * 24 * time.Hour
)

// ReportTunnels records node's current tunnels and the traffic they carried.
// Entries without a name or with a type it does not know are dropped; the rest
// of the report still counts.
func (c *Coordinator) ReportTunnels(ctx context.Context, node *Node, reports []TunnelReport, now time.Time) error {
	if c.Tunnels == nil {
		return nil
	}
	if len(reports) > maxTunnelsPerReport {
		reports = reports[:maxTunnelsPerReport]
	}
	hour := now.UTC().Truncate(time.Hour)
	seen := map[string]bool{}
	list := make([]Tunnel, 0, len(reports))
	var usage []TunnelUsage
	for _, r := range reports {
		name := clip(strings.TrimSpace(r.Name), maxTunnelNameLen)
		typ := strings.ToLower(strings.TrimSpace(r.Type))
		if name == "" || seen[name] || !knownTunnelType(typ) {
			continue
		}
		seen[name] = true
		list = append(list, Tunnel{
			Meshnet: node.Meshnet, NodeID: node.ID, Name: name, Type: typ,
			PublicAddr: clip(strings.TrimSpace(r.PublicAddr), maxTunnelFieldLen),
			LocalAddr:  clip(strings.TrimSpace(r.LocalAddr), maxTunnelFieldLen),
			Status:     tunnelStatus(r.Status),
		})
		in, out := max(r.BytesIn, 0), max(r.BytesOut, 0)
		if in+out > 0 {
			usage = append(usage, TunnelUsage{Meshnet: node.Meshnet, NodeID: node.ID, Name: name, Hour: hour, BytesIn: in, BytesOut: out})
		}
	}
	if err := c.Tunnels.ReplaceTunnels(ctx, node.Meshnet, node.ID, list, now); err != nil {
		return fmt.Errorf("core: store tunnels: %w", err)
	}
	if c.TunnelUsage != nil && len(usage) > 0 {
		if err := c.TunnelUsage.AddTunnelUsage(ctx, usage); err != nil {
			return fmt.Errorf("core: store tunnel usage: %w", err)
		}
	}
	return nil
}

func knownTunnelType(t string) bool {
	switch t {
	case "http", "https", "tcp", "udp", "sni":
		return true
	}
	return false
}

func tunnelStatus(s string) string {
	switch s = strings.ToLower(strings.TrimSpace(s)); s {
	case "online", "pending":
		return s
	}
	return "offline"
}

// clip cuts s to at most n bytes without splitting a character.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// TunnelView is a tunnel as a list shows it.
type TunnelView struct {
	Tunnel
	NodeName   string
	NodeOnline bool
	Traffic30d int64
}

// MeshnetTunnels lists every tunnel the meshnet's nodes reported, by device and
// then by name. A tunnel whose node was deleted is left out.
func (c *Coordinator) MeshnetTunnels(ctx context.Context, t MeshnetID, now time.Time) ([]TunnelView, error) {
	if c.Tunnels == nil {
		return nil, nil
	}
	tunnels, err := c.Tunnels.ListTunnels(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("core: list tunnels: %w", err)
	}
	nodes, err := c.Nodes.ListMeshnet(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("core: list meshnet: %w", err)
	}
	names := make(map[int64]string, len(nodes))
	for _, n := range nodes {
		names[n.ID] = n.Name
	}
	var traffic map[TunnelKey]int64
	if c.TunnelUsage != nil {
		if traffic, err = c.TunnelUsage.TunnelBytesSince(ctx, t, now.Add(-30*24*time.Hour)); err != nil {
			return nil, fmt.Errorf("core: tunnel traffic: %w", err)
		}
	}
	out := make([]TunnelView, 0, len(tunnels))
	for _, tn := range tunnels {
		name, ok := names[tn.NodeID]
		if !ok {
			continue
		}
		out = append(out, TunnelView{
			Tunnel: tn, NodeName: name, NodeOnline: tunnelNodeOnline(c.Presence.IsOnline(tn.NodeID), tn.ReportedAt, now),
			Traffic30d: traffic[TunnelKey{NodeID: tn.NodeID, Name: tn.Name}],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NodeName != out[j].NodeName {
			return out[i].NodeName < out[j].NodeName
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// TunnelReportFresh is how long a report keeps its device counted as up for
// its tunnels: two of the daemon's five-minute reports, and some slack.
const TunnelReportFresh = 11 * time.Minute

// tunnelNodeOnline is whether the device serving a tunnel is up: on the mesh,
// or reporting its tunnels without it — a device with its mesh switched off
// serves tunnels all the same, and reports them over a view session.
func tunnelNodeOnline(onMesh bool, reportedAt, now time.Time) bool {
	return onMesh || (!reportedAt.IsZero() && now.Sub(reportedAt) < TunnelReportFresh)
}

// Usage is a meshnet's traffic through this server as one viewer sees it: the
// viewer's month and days, since a self-hosted server has no billing month.
type Usage struct {
	// Unavailable says why there are no traffic figures ("no_database"); the
	// month and days are then empty, and a usage view says so instead of zero.
	Unavailable string
	// RelayNotRecorded: relayed traffic is not recorded, so the figures are the
	// tunnels alone.
	RelayNotRecorded   bool
	MonthFrom, MonthTo time.Time
	MonthTunnel        int64
	MonthRelay         int64
	Days               []UsageDay // oldest first, today last
	Seats              SeatUsage
}

// UsageDay is one of the viewer's days: tunnels + relay.
type UsageDay struct {
	Start time.Time
	Bytes int64
}

// Usage adds up t's traffic for a viewer in loc: tunnel traffic plus the mesh
// traffic the relays carried, as its senders reported it (each relayed byte is
// counted once, by the side that sent it). Direct paths never touch the server
// and are not counted.
func (c *Coordinator) Usage(ctx context.Context, t MeshnetID, loc *time.Location, days int, now time.Time) (Usage, error) {
	if loc == nil {
		loc = time.UTC
	}
	days = min(max(days, 1), 31)
	var u Usage
	seats, err := c.SeatUsage(ctx, t)
	if err != nil {
		return u, err
	}
	u.Seats = seats
	if c.TunnelUsage == nil {
		u.Unavailable = "no_database"
		return u, nil
	}

	local := now.In(loc)
	u.MonthFrom = time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, loc)
	u.MonthTo = u.MonthFrom.AddDate(0, 1, 0)
	today := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	u.Days = make([]UsageDay, days)
	for i := range u.Days {
		u.Days[i].Start = today.AddDate(0, 0, i-days+1)
	}
	from := u.MonthFrom
	if u.Days[0].Start.Before(from) {
		from = u.Days[0].Start
	}
	to := today.AddDate(0, 0, 1)

	tunnel, err := c.TunnelUsage.TunnelBytesByHour(ctx, t, from, to)
	if err != nil {
		return u, fmt.Errorf("core: tunnel usage: %w", err)
	}
	var relay map[time.Time]int64
	switch recorded, rerr := c.relayRecorded(ctx, t); {
	case rerr != nil:
		return u, rerr
	case !recorded:
		u.RelayNotRecorded = true
	default:
		if relay, err = c.ConnRecords.RelayBytesByHour(ctx, t, from, to); err != nil {
			return u, fmt.Errorf("core: relay usage: %w", err)
		}
	}
	add := func(hours map[time.Time]int64, month *int64) {
		for h, b := range hours {
			at := h.In(loc)
			if !at.Before(u.MonthFrom) && at.Before(u.MonthTo) {
				*month += b
			}
			// Every hour is before `to` (the query's end), so the last day
			// that started at or before it is its day.
			for i := len(u.Days) - 1; i >= 0; i-- {
				if !at.Before(u.Days[i].Start) {
					u.Days[i].Bytes += b
					break
				}
			}
		}
	}
	add(tunnel, &u.MonthTunnel)
	add(relay, &u.MonthRelay)
	return u, nil
}

// relayRecorded reports whether t's relayed traffic is being recorded: this
// coordinator keeps connection records and the meshnet has not switched them off.
func (c *Coordinator) relayRecorded(ctx context.Context, t MeshnetID) (bool, error) {
	if c.ConnRecords == nil {
		return false, nil
	}
	if c.Settings != nil {
		set, err := c.Settings.GetSettings(ctx, t)
		if err != nil {
			return false, fmt.Errorf("core: usage settings: %w", err)
		}
		if set.ConnRecordsDisabled {
			return false, nil
		}
	}
	return true, nil
}

// MemTunnelStore is TunnelStore in memory: a coordinator without a database
// still lists tunnels, and forgets them on restart until each daemon's next
// report (every few minutes).
type MemTunnelStore struct {
	mu     sync.Mutex
	nextID int64
	byNode map[int64][]Tunnel
}

func NewMemTunnelStore() *MemTunnelStore { return &MemTunnelStore{byNode: map[int64][]Tunnel{}} }

func (s *MemTunnelStore) ReplaceTunnels(_ context.Context, t MeshnetID, nodeID int64, list []Tunnel, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := map[string]Tunnel{}
	for _, tn := range s.byNode[nodeID] {
		prev[tn.Name] = tn
	}
	next := make([]Tunnel, 0, len(list))
	for _, tn := range list {
		tn.Meshnet, tn.NodeID, tn.ReportedAt = t, nodeID, now
		if old, ok := prev[tn.Name]; ok {
			tn.ID, tn.FirstSeen = old.ID, old.FirstSeen
		} else {
			s.nextID++
			tn.ID, tn.FirstSeen = s.nextID, now
		}
		next = append(next, tn)
	}
	if len(next) == 0 {
		delete(s.byNode, nodeID)
	} else {
		s.byNode[nodeID] = next
	}
	return nil
}

func (s *MemTunnelStore) ListTunnels(_ context.Context, t MeshnetID) ([]Tunnel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Tunnel
	for _, list := range s.byNode {
		for _, tn := range list {
			if tn.Meshnet == t {
				out = append(out, tn)
			}
		}
	}
	return out, nil
}

func (s *MemTunnelStore) DeleteTunnelsOf(_ context.Context, nodeID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byNode, nodeID)
	return nil
}
