package core

import (
	"context"
	"strings"
	"testing"
	"time"
)

type memTunnelUsage struct{ rows []TunnelUsage }

func (m *memTunnelUsage) AddTunnelUsage(_ context.Context, rows []TunnelUsage) error {
	m.rows = append(m.rows, rows...)
	return nil
}

func (m *memTunnelUsage) TunnelBytesByHour(_ context.Context, t MeshnetID, from, to time.Time) (map[time.Time]int64, error) {
	out := map[time.Time]int64{}
	for _, r := range m.rows {
		if r.Meshnet == t && !r.Hour.Before(from) && r.Hour.Before(to) {
			out[r.Hour] += r.BytesIn + r.BytesOut
		}
	}
	return out, nil
}

func (m *memTunnelUsage) TunnelBytesSince(_ context.Context, t MeshnetID, since time.Time) (map[TunnelKey]int64, error) {
	out := map[TunnelKey]int64{}
	for _, r := range m.rows {
		if r.Meshnet == t && !r.Hour.Before(since) {
			out[TunnelKey{r.NodeID, r.Name}] += r.BytesIn + r.BytesOut
		}
	}
	return out, nil
}

func (m *memTunnelUsage) PurgeTunnelUsageBefore(context.Context, time.Time) (int, error) {
	return 0, nil
}

// The month and the days are the viewer's: just before midnight on the last of
// September in New York it is already October in UTC, and the traffic of that
// evening still belongs to September 30.
func TestUsageFollowsTheViewersCalendar(t *testing.T) {
	ctx := context.Background()
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	utc := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	usage := &memTunnelUsage{rows: []TunnelUsage{
		{Meshnet: 1, NodeID: 7, Name: "photos", Hour: utc("2026-10-01T01:00:00Z"), BytesIn: 100},  // Sep 30, 21:00 in New York
		{Meshnet: 1, NodeID: 7, Name: "photos", Hour: utc("2026-09-01T03:00:00Z"), BytesIn: 1000}, // Aug 31, 23:00: not this month
		{Meshnet: 1, NodeID: 7, Name: "photos", Hour: utc("2026-09-01T05:00:00Z"), BytesOut: 10},  // Sep 1, 01:00
		{Meshnet: 2, NodeID: 9, Name: "other", Hour: utc("2026-10-01T01:00:00Z"), BytesIn: 5000},  // another meshnet
	}}
	relay := &memConnRecords{rows: []ConnRecord{
		{MeshnetID: 1, SrcNodeID: 7, DstNodeID: 8, Hour: utc("2026-09-30T12:00:00Z"), BytesTx: 900, RelayBytesTx: 7},
	}}
	c := &Coordinator{Nodes: NewMemNodeStore(), TunnelUsage: usage, ConnRecords: relay, Settings: NewMemSettingsStore()}
	now := utc("2026-10-01T02:00:00Z")

	u, err := c.Usage(ctx, 1, ny, 7, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 9, 1, 0, 0, 0, 0, ny); !u.MonthFrom.Equal(want) {
		t.Fatalf("month from %v, want %v", u.MonthFrom, want)
	}
	if u.MonthTunnel != 110 || u.MonthRelay != 7 {
		t.Fatalf("month tunnel %d relay %d, want 110 and 7", u.MonthTunnel, u.MonthRelay)
	}
	if len(u.Days) != 7 || !u.Days[6].Start.Equal(time.Date(2026, 9, 30, 0, 0, 0, 0, ny)) || u.Days[6].Bytes != 107 {
		t.Fatalf("days = %+v, want 7 ending Sep 30 with 107", u.Days)
	}
	if !u.Days[0].Start.Equal(time.Date(2026, 9, 24, 0, 0, 0, 0, ny)) {
		t.Fatalf("first day %v, want Sep 24", u.Days[0].Start)
	}

	// An org that switched connection records off has no relay figures: they
	// are said to be missing, not added as zero.
	if err := c.Settings.SetSettings(ctx, 1, MeshnetSettings{ConnRecordsDisabled: true}); err != nil {
		t.Fatal(err)
	}
	u, err = c.Usage(ctx, 1, ny, 7, now)
	if err != nil {
		t.Fatal(err)
	}
	if !u.RelayNotRecorded || u.MonthRelay != 0 || u.MonthTunnel != 110 {
		t.Fatalf("with records off: %+v", u)
	}
}

// A pair that moved between relay and direct within an hour keeps the relayed
// part of its bytes apart, whichever path the hour ended on.
func TestRecordConnectionsKeepsTheRelayedPart(t *testing.T) {
	c, recs := coordWithRecords(t)
	a, b := enrollPair(t, c)
	relayed := sample(b)
	relayed.Path = "relay"
	direct := sample(b)
	direct.BytesTx, direct.BytesRx = 1000, 2000
	if _, err := c.RecordConnections(context.Background(), a, []ConnSample{relayed, direct}); err != nil {
		t.Fatal(err)
	}
	if len(recs.rows) != 1 {
		t.Fatalf("rows = %+v, want one pair-hour", recs.rows)
	}
	r := recs.rows[0]
	if r.BytesTx != 1100 || r.BytesRx != 2200 || r.RelayBytesTx != 100 || r.RelayBytesRx != 200 {
		t.Fatalf("row = %+v, want 1100/2200 of which 100/200 relayed", r)
	}
}

// What a report cannot use is dropped one entry at a time; the rest counts.
func TestReportTunnelsDropsWhatItCannotUse(t *testing.T) {
	ctx := context.Background()
	usage := &memTunnelUsage{}
	c := &Coordinator{Nodes: NewMemNodeStore(), Tunnels: NewMemTunnelStore(), TunnelUsage: usage}
	node := &Node{ID: 5, Meshnet: 1}
	now := time.Date(2026, 9, 18, 10, 20, 0, 0, time.UTC)
	long := strings.Repeat("é", 100) // 200 bytes
	err := c.ReportTunnels(ctx, node, []TunnelReport{
		{Name: "photos", Type: "HTTP", Status: "Online", BytesIn: 10, BytesOut: 20},
		{Name: "photos", Type: "tcp"}, // the same name again
		{Name: "", Type: "http"},      // no name
		{Name: "ftp", Type: "ftp"},    // a type it does not know
		{Name: "ssh", Type: "tcp", Status: "weird", BytesIn: -5},
		{Name: long, Type: "udp"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := c.Tunnels.ListTunnels(ctx, 1)
	got := map[string]Tunnel{}
	for _, tn := range list {
		got[tn.Name] = tn
	}
	if len(got) != 3 || got["photos"].Type != "http" || got["photos"].Status != "online" || got["ssh"].Status != "offline" {
		t.Fatalf("stored %+v", got)
	}
	for name := range got {
		if len(name) > maxTunnelNameLen {
			t.Fatalf("a name of %d bytes was stored", len(name))
		}
	}
	if len(usage.rows) != 1 || usage.rows[0].BytesIn != 10 || usage.rows[0].BytesOut != 20 || !usage.rows[0].Hour.Equal(now.Truncate(time.Hour)) {
		t.Fatalf("usage rows %+v, want photos' 10/20 in the 10:00 hour", usage.rows)
	}
}

// A device is up for its tunnels while it is on the mesh, or while its reports
// keep coming — a device with its mesh switched off serves tunnels all the same.
func TestTunnelNodeOnline(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		onMesh   bool
		reported time.Time
		want     bool
	}{
		{"on the mesh", true, time.Time{}, true},
		{"reported a minute ago", false, now.Add(-time.Minute), true},
		{"missed one report", false, now.Add(-9 * time.Minute), true},
		{"silent past two reports", false, now.Add(-TunnelReportFresh), false},
		{"never reported", false, time.Time{}, false},
	} {
		if got := tunnelNodeOnline(tc.onMesh, tc.reported, now); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
