package main

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/mesh"
	"github.com/calabinet/calabi/apps/client/internal/session"
	"github.com/calabinet/calabi/apps/client/internal/status"
)

// What the local daemon reports to a self-hosted coordinator: every configured
// tunnel, with the address its edge assigned and its live counters; one that is
// not registered is offline, and a disconnected session makes every one offline
// while its counters stay with it.
func TestTunnelStatesForTheCoordinator(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	planned := planTunnels(logger, []localTunnelConfig{
		{Name: "photos", Type: "http", Local: "8080"},
		{Name: "ssh", Type: "tcp", Local: "22"},
		{Name: "games", Type: "udp", Local: "27015", RemotePort: 27015},
	})
	sv := newLocalSupervisor(logger, localConfig{}, filepath.Join(t.TempDir(), "t.yaml"), planned)
	sv.setEdgeAddr("[2001:db8::1]:7443")
	state := status.New("test", "[2001:db8::1]:7443")
	state.SetConnected(true, "s", "", "", "example.com", "", 0, 0)

	sv.markLive(planned[0].id, session.Assigned{Domain: "photos.example.com"})
	state.AddTunnel(status.TunnelInfo{ProxyID: "p1", TunnelID: planned[0].id, Name: "photos", Type: "http"})
	state.AddBytes("p1", "in", 100)
	state.AddBytes("p1", "out", 7)
	sv.markLive(planned[1].id, session.Assigned{RemotePort: 2222})
	state.AddTunnel(status.TunnelInfo{ProxyID: "p2", TunnelID: planned[1].id, Name: "ssh", Type: "tcp", Pending: true})

	got := map[string]mesh.TunnelState{}
	for _, s := range sv.tunnelStates(state) {
		got[s.Name] = s
	}
	want := map[string]mesh.TunnelState{
		"photos": {Name: "photos", Type: "http", LocalAddr: "127.0.0.1:8080", PublicAddr: "photos.example.com", Status: "online", Instance: "p1", BytesIn: 100, BytesOut: 7},
		"ssh":    {Name: "ssh", Type: "tcp", LocalAddr: "127.0.0.1:22", PublicAddr: "[2001:db8::1]:2222", Status: "pending", Instance: "p2"},
		"games":  {Name: "games", Type: "udp", LocalAddr: "127.0.0.1:27015", PublicAddr: "[2001:db8::1]:27015", Status: "offline"},
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s = %+v\nwant %+v", name, got[name], w)
		}
	}

	state.SetConnected(false, "", "", "", "", "", 0, 0)
	for _, s := range sv.tunnelStates(state) {
		if s.Status != "offline" {
			t.Errorf("%s is %s with the session down, want offline", s.Name, s.Status)
		}
		if s.Name == "photos" && (s.Instance != "p1" || s.BytesIn != 100) {
			t.Errorf("photos lost its counters during the blip: %+v", s)
		}
	}
}
