package status

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// listenWithFallback must move to the next free port when the requested one is
// taken — this is what lets a second daemon get its own console port.
func TestListenWithFallback_PortBusy(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	addr := busy.Addr().String() // "127.0.0.1:<P>"
	_, portStr, _ := net.SplitHostPort(addr)

	ln, err := listenWithFallback(addr)
	if err != nil {
		t.Fatalf("fallback failed: %v", err)
	}
	defer ln.Close()
	_, gotPort, _ := net.SplitHostPort(ln.Addr().String())
	if gotPort == portStr {
		t.Fatalf("expected a different port than the busy %s, got the same", portStr)
	}
}

// When the requested port is free, listenWithFallback binds exactly it.
func TestListenWithFallback_PortFree(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close() // free it so the requested port is available

	ln, err := listenWithFallback(addr)
	if err != nil {
		t.Fatalf("listen on free port: %v", err)
	}
	defer ln.Close()
	if ln.Addr().String() != addr {
		t.Fatalf("free port not bound exactly: want %s, got %s", addr, ln.Addr().String())
	}
}

func TestStateAddRemoveTunnel(t *testing.T) {
	s := New("test", "edge:7443")
	s.AddTunnel(TunnelInfo{
		ProxyID:    "px-1",
		Name:       "web",
		Type:       "http",
		LocalAddr:  "127.0.0.1:9090",
		PublicAddr: "http://u1.localtest.me",
	})

	snap := s.SnapshotNow()
	if len(snap.Tunnels) != 1 || snap.Tunnels[0].ProxyID != "px-1" {
		t.Fatalf("expected 1 tunnel px-1, got %+v", snap.Tunnels)
	}

	s.AddBytes("px-1", "in", 100)
	s.AddBytes("px-1", "out", 50)
	s.AddBytes("px-1", "in", 25)
	// Negative/zero are ignored.
	s.AddBytes("px-1", "in", 0)
	s.AddBytes("px-1", "in", -10)
	s.AddConnection("px-1")
	s.AddConnection("px-1")
	// Bytes for an unknown proxy_id are silently dropped (no panic).
	s.AddBytes("does-not-exist", "in", 999)

	snap = s.SnapshotNow()
	tt := snap.Tunnels[0]
	if tt.BytesIn != 125 || tt.BytesOut != 50 {
		t.Errorf("bytes in/out = %d/%d, want 125/50", tt.BytesIn, tt.BytesOut)
	}
	if tt.Connections != 2 {
		t.Errorf("connections = %d, want 2", tt.Connections)
	}

	s.RemoveTunnel("px-1")
	if len(s.SnapshotNow().Tunnels) != 0 {
		t.Errorf("expected empty after RemoveTunnel")
	}
}

// Covers the FullSync catch-up path: a list of authoritative tunnel_ids
// must drop every active+pending row whose id isn't in the keep-set,
// preserve CLI-launched rows that have tunnel_id=0 (the daemon's auto-
// claim path didn't put them there and shouldn't reconcile them), and
// return the dropped-active proxy_ids so the caller can unwind the
// proxy registry.
func TestStateReconcileToTunnelIDs(t *testing.T) {
	s := New("test", "edge:7443")
	// active rows the daemon auto-claimed (have tunnel_id)
	s.AddActiveTunnel("px-keep", 10, "keep", "http", "127.0.0.1:9000", "http://k.localtest.me")
	s.AddActiveTunnel("px-stale", 20, "stale", "http", "127.0.0.1:9001", "http://s.localtest.me")
	// pending row (Phase C console-pushed but not yet claimed)
	s.UpsertPending(30, "pending-keep", "http", "127.0.0.1:9002", "p.localtest.me", 0)
	s.UpsertPending(40, "pending-stale", "http", "127.0.0.1:9003", "ps.localtest.me", 0)
	// CLI-launched row with tunnel_id=0 — must survive a reconcile pass
	s.AddTunnel(TunnelInfo{
		ProxyID:    "px-cli",
		TunnelID:   0,
		Name:       "cli-tunnel",
		Type:       "tcp",
		LocalAddr:  "127.0.0.1:22",
		PublicAddr: "tcp://:5000",
	})

	if got := len(s.SnapshotNow().Tunnels); got != 5 {
		t.Fatalf("setup: snapshot has %d tunnels, want 5", got)
	}

	dropped := s.ReconcileToTunnelIDs(map[int64]struct{}{
		10: {},
		30: {},
	})

	// Two ACTIVE rows existed (10 keep, 20 stale); only px-stale should
	// be reported. Pending rows being dropped is fine — caller doesn't
	// need to unwind the proxy registry for them.
	if len(dropped) != 1 || dropped[0] != "px-stale" {
		t.Fatalf("dropped active proxy_ids = %v, want [px-stale]", dropped)
	}

	snap := s.SnapshotNow()
	got := map[string]bool{}
	for _, t := range snap.Tunnels {
		got[t.ProxyID] = true
	}
	want := map[string]bool{
		"px-keep":    true, // tunnel_id=10 kept
		"pending:30": true, // tunnel_id=30 kept
		"px-cli":     true, // tunnel_id=0 preserved
	}
	if len(snap.Tunnels) != len(want) {
		t.Fatalf("snapshot has %d tunnels, want %d (got=%v)", len(snap.Tunnels), len(want), got)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("expected %q to survive reconcile, got=%v", k, got)
		}
	}
}

func TestServerEndpoints(t *testing.T) {
	s := New("test-srv", "edge:7443")
	s.AddTunnel(TunnelInfo{
		ProxyID:    "px-a",
		Name:       "web",
		Type:       "http",
		LocalAddr:  "127.0.0.1:9090",
		PublicAddr: "http://u1.localtest.me",
	})
	s.SetConnected(true, "sess-1", "tenant-x", "client-y", "localtest.me", "127.0.0.1", 8080, 8443)
	s.AddConnection("px-a")
	s.AddBytes("px-a", "in", 1024)

	// Pick a random free local port.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := NewServer(slog.Default(), s, addr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- srv.Run(ctx) }()

	if !waitReachable(t, addr, 2*time.Second) {
		t.Fatalf("status page never came up at %s", addr)
	}

	// /healthz now returns structured JSON. After
	// SetConnected(true) the state should be "connected".
	body, code := httpGet(t, "http://"+addr+"/healthz")
	if code != 200 || !strings.Contains(body, `"state":"connected"`) {
		t.Errorf("/healthz: code=%d body=%q", code, body)
	}
	if !strings.Contains(body, `"connected":true`) {
		t.Errorf("/healthz missing connected=true: body=%q", body)
	}

	// /tunnels returns the snapshot JSON.
	body, code = httpGet(t, "http://"+addr+"/tunnels")
	if code != 200 {
		t.Fatalf("/tunnels status=%d", code)
	}
	var snap Snapshot
	if err := json.Unmarshal([]byte(body), &snap); err != nil {
		t.Fatalf("/tunnels unmarshal: %v body=%q", err, body)
	}
	if !snap.Connected || snap.SessionID != "sess-1" {
		t.Errorf("snapshot connect/session wrong: %+v", snap)
	}
	if len(snap.Tunnels) != 1 || snap.Tunnels[0].ProxyID != "px-a" {
		t.Errorf("snapshot tunnels wrong: %+v", snap.Tunnels)
	}
	if snap.Tunnels[0].BytesIn != 1024 || snap.Tunnels[0].Connections != 1 {
		t.Errorf("snapshot bytes/conn wrong: %+v", snap.Tunnels[0])
	}

	// /metrics surfaces our gauges/counters.
	body, code = httpGet(t, "http://"+addr+"/metrics")
	if code != 200 {
		t.Fatalf("/metrics status=%d", code)
	}
	for _, want := range []string{
		`calabi_client_active_tunnels 1`,
		`calabi_client_session_connected 1`,
		`calabi_client_visitor_connections_total{proxy_type="http"}`,
		`calabi_client_bytes_transferred_total{direction="visitor_to_local",proxy_type="http"}`,
		`calabi_client_build_info`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}

	// / returns the embedded SPA shell. swapped the inline HTML
	// for the Vite-built React app; the shell now contains only the
	// title + bootstrap <script>. The JSON-backed pages (/tunnels etc.)
	// are asserted above.
	body, code = httpGet(t, "http://"+addr+"/")
	if code != 200 || !strings.Contains(body, "Calabi") || !strings.Contains(body, `id="root"`) {
		t.Errorf("/ html missing expected SPA markers; code=%d body=%q", code, body)
	}

	cancel()
	select {
	case <-runErrCh:
	case <-time.After(3 * time.Second):
		t.Errorf("Run did not return after cancel")
	}
}

// Browser-guard contract: a request without the "CalabiDesktop" UA
// marker gets 403 + the friendly HTML page, except for /healthz and
// /metrics (operator surfaces, must stay reachable from curl etc.).
func TestBrowserGuard(t *testing.T) {
	s := New("guard-test", "edge:7443")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := NewServer(slog.Default(), s, addr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()
	if !waitReachable(t, addr, 2*time.Second) {
		t.Fatalf("server never came up")
	}

	get := func(path, ua string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, "http://"+addr+path, nil)
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// Browser UA on / → 403 + the blocked-page marker.
	code, body := get("/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")
	if code != http.StatusForbidden {
		t.Errorf("browser GET / want 403, got %d", code)
	}
	if !strings.Contains(body, "desktop client") {
		t.Errorf("blocked body missing marker: %q", body)
	}
	// Browser UA on /tunnels → also 403 (no JSON leak).
	if code, _ := get("/tunnels", "curl/8.0"); code != http.StatusForbidden {
		t.Errorf("/tunnels w/o marker want 403, got %d", code)
	}
	// Desktop marker passes through.
	if code, _ := get("/", "Mozilla/5.0 ... CalabiDesktop/0.1.0"); code != http.StatusOK {
		t.Errorf("desktop GET / want 200, got %d", code)
	}
	// /healthz always open.
	if code, _ := get("/healthz", "curl/8.0"); code != http.StatusOK {
		t.Errorf("/healthz w/o marker want 200, got %d", code)
	}
	// /metrics always open.
	if code, _ := get("/metrics", "Prometheus/2.0"); code != http.StatusOK {
		t.Errorf("/metrics w/o marker want 200, got %d", code)
	}
}

func TestServerBindFailureIsNotFatal(t *testing.T) {
	// Hold a listener so the next Listen on the same port fails.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("setup listener: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	s := New("bind-failure", "edge:7443")
	srv := NewServer(slog.Default(), s, addr)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	// Give Run a tick to attempt bind + log the warning, then cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned non-nil err: %v (should be silent on bind failure)", err)
		}
	case <-time.After(2 * time.Second):
		t.Errorf("Run did not return on bind failure within 2s")
	}
}

// ----- helpers (mirror admin_test.go) --------------------------------------

// httpGet sends the browser-guard's expected UA marker so tests aren't
// blocked by the middleware that gates :7400 against plain browsers.
func httpGet(t *testing.T, url string) (string, int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build req %s: %v", url, err)
	}
	req.Header.Set("User-Agent", "test-CalabiDesktop/0.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), resp.StatusCode
}

func waitReachable(t *testing.T, addr string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
