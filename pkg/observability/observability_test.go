package observability

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestProvider_RunAndEndpoints(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()

	prov := New(slog.Default(), Options{
		Service:   "test-svc",
		Version:   "0.0.1-test",
		AdminAddr: addr,
	})

	probe := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "calabi_obs_test_probe_total",
		Help: "fixture",
	})
	prov.Registry().MustRegister(probe)
	probe.Inc()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- prov.Run(ctx) }()

	if !waitReachable(addr, 2*time.Second) {
		t.Fatalf("admin not reachable at %s", addr)
	}

	// /healthz
	if body, code := httpGet(t, "http://"+addr+"/healthz"); code != 200 || !strings.Contains(body, "ok") {
		t.Errorf("/healthz: code=%d body=%q", code, body)
	}

	// /readyz before SetReady: 503
	if _, code := httpGet(t, "http://"+addr+"/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz before ready = %d, want 503", code)
	}
	prov.SetReady(true)
	if _, code := httpGet(t, "http://"+addr+"/readyz"); code != 200 {
		t.Errorf("/readyz after ready = %d, want 200", code)
	}

	// /metrics shows the probe + build_info
	body, code := httpGet(t, "http://"+addr+"/metrics")
	if code != 200 {
		t.Fatalf("/metrics code=%d", code)
	}
	for _, want := range []string{
		`calabi_obs_test_probe_total 1`,
		`calabi_build_info{`,
		`service="test-svc"`,
		`version="0.0.1-test"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned err=%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("Run did not return within 3s after cancel")
	}
}

func TestProvider_ReadyzDependencyCheck(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()

	dependencyOK := false
	prov := New(slog.Default(), Options{
		Service:   "test-svc",
		AdminAddr: addr,
		IsReady: func() (bool, string) {
			if dependencyOK {
				return true, ""
			}
			return false, "fake dep down"
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = prov.Run(ctx) }()
	if !waitReachable(addr, 2*time.Second) {
		t.Fatalf("admin not reachable")
	}

	// Even after SetReady(true), /readyz returns 503 because dep check fails.
	prov.SetReady(true)
	body, code := httpGet(t, "http://"+addr+"/readyz")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "fake dep down") {
		t.Errorf("/readyz with failing dep: code=%d body=%q", code, body)
	}

	// Flip the dep ok.
	dependencyOK = true
	_, code = httpGet(t, "http://"+addr+"/readyz")
	if code != 200 {
		t.Errorf("/readyz with passing dep = %d, want 200", code)
	}
}

func httpGet(t *testing.T, url string) (string, int) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), resp.StatusCode
}

func waitReachable(addr string, timeout time.Duration) bool {
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
