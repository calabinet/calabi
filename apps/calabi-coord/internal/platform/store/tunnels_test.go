package store

import (
	"context"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
)

// A node's report replaces its list: a name it reported before keeps its row,
// a new one is added, a missing one goes; other nodes are untouched.
func TestReplaceTunnelsKeepsIdentity(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(5 * time.Minute)

	if err := s.ReplaceTunnels(ctx, 1, 7, []core.Tunnel{
		{Name: "photos", Type: "http", PublicAddr: "photos.example.com", Status: "online"},
		{Name: "ssh", Type: "tcp", PublicAddr: "edge.example.com:2222", Status: "online"},
	}, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceTunnels(ctx, 1, 8, []core.Tunnel{{Name: "nas", Type: "http", Status: "pending"}}, t0); err != nil {
		t.Fatal(err)
	}
	before, _ := s.ListTunnels(ctx, 1)
	var photosID int64
	for _, tn := range before {
		if tn.Name == "photos" {
			photosID = tn.ID
		}
	}
	if err := s.ReplaceTunnels(ctx, 1, 7, []core.Tunnel{
		{Name: "photos", Type: "http", PublicAddr: "photos.example.com", Status: "offline"},
		{Name: "git", Type: "http", PublicAddr: "git.example.com", Status: "online"},
	}, t1); err != nil {
		t.Fatal(err)
	}
	after, err := s.ListTunnels(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Tunnel{}
	for _, tn := range after {
		got[tn.Name] = tn
	}
	if len(got) != 3 || got["ssh"].Name != "" {
		t.Fatalf("after the second report: %v, want photos, git and the other node's nas", got)
	}
	p := got["photos"]
	if p.ID != photosID || !p.FirstSeen.Equal(t0) || !p.ReportedAt.Equal(t1) || p.Status != "offline" {
		t.Fatalf("photos = %+v, want id %d first seen %v reported %v offline", p, photosID, t0, t1)
	}
	if !got["git"].FirstSeen.Equal(t1) || got["nas"].NodeID != 8 {
		t.Fatalf("git %+v nas %+v", got["git"], got["nas"])
	}
	if err := s.DeleteTunnelsOf(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.ListTunnels(ctx, 1); len(left) != 1 || left[0].Name != "nas" {
		t.Fatalf("after deleting node 7's: %v", left)
	}
}

// Traffic adds up per hour and per tunnel, and is summed back by the database.
func TestTunnelUsageSums(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	add := func(rows ...core.TunnelUsage) {
		t.Helper()
		if err := s.AddTunnelUsage(ctx, rows); err != nil {
			t.Fatal(err)
		}
	}
	add(core.TunnelUsage{Meshnet: 1, NodeID: 7, Name: "photos", Hour: h.Add(10 * time.Minute), BytesIn: 10, BytesOut: 90})
	add(core.TunnelUsage{Meshnet: 1, NodeID: 7, Name: "photos", Hour: h, BytesIn: 5, BytesOut: 5})
	add(core.TunnelUsage{Meshnet: 1, NodeID: 7, Name: "ssh", Hour: h, BytesIn: 1, BytesOut: 1},
		core.TunnelUsage{Meshnet: 1, NodeID: 7, Name: "photos", Hour: h.Add(time.Hour), BytesIn: 100},
		core.TunnelUsage{Meshnet: 2, NodeID: 9, Name: "photos", Hour: h, BytesIn: 1000})

	byHour, err := s.TunnelBytesByHour(ctx, 1, h, h.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(byHour) != 2 || byHour[h] != 112 || byHour[h.Add(time.Hour)] != 100 {
		t.Fatalf("by hour = %v, want %v: 112 and the next hour 100", byHour, h)
	}
	since, err := s.TunnelBytesSince(ctx, 1, h)
	if err != nil {
		t.Fatal(err)
	}
	if since[core.TunnelKey{NodeID: 7, Name: "photos"}] != 210 || since[core.TunnelKey{NodeID: 7, Name: "ssh"}] != 2 || len(since) != 2 {
		t.Fatalf("since = %v", since)
	}
	n, err := s.PurgeTunnelUsageBefore(ctx, h.Add(time.Hour))
	if err != nil || n != 3 {
		t.Fatalf("purge: %d %v, want the three rows of the first hour", n, err)
	}
}

// Relayed bytes are kept apart from the hour's last path and summed per hour.
func TestRelayBytesByHour(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	if err := s.AddConnSamples(ctx, []core.ConnRecord{
		{MeshnetID: 1, SrcNodeID: 7, DstNodeID: 8, Hour: h, BytesTx: 100, BytesRx: 10, Path: "relay", RelayBytesTx: 100, RelayBytesRx: 10},
		{MeshnetID: 1, SrcNodeID: 8, DstNodeID: 7, Hour: h, BytesTx: 30, Path: "relay", RelayBytesTx: 30},
	}); err != nil {
		t.Fatal(err)
	}
	// The pair went direct later in the hour: the path flips, the relayed bytes stay.
	if err := s.AddConnSamples(ctx, []core.ConnRecord{
		{MeshnetID: 1, SrcNodeID: 7, DstNodeID: 8, Hour: h, BytesTx: 500, Path: "direct"},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.RelayBytesByHour(ctx, 1, h, h.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got[h] != 130 || len(got) != 1 {
		t.Fatalf("relay by hour = %v, want 130 at %v", got, h)
	}
	rows, _ := s.ListConnRecords(ctx, 1, core.ConnRecordQuery{NodeIDs: []int64{7}})
	for _, r := range rows {
		if r.SrcNodeID == 7 && (r.BytesTx != 600 || r.RelayBytesTx != 100 || r.Path != "direct") {
			t.Fatalf("row = %+v, want 600 sent of which 100 relayed, path direct", r)
		}
	}
}
