//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/platform/statusapi"
	"github.com/calabinet/calabi/apps/client/internal/status"
)

func TestDaemonManagementSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.sock")
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CALABI_DAEMON_SOCKET", path)
	t.Setenv("CALABI_STATUS_ADDR", "disabled")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := quietTestLogger()
	api := statusapi.New(logger, statusapi.Config{DisableInteractiveAuth: true})
	_, done, err := startDaemonConsole(ctx, logger, status.New("test", ""), api.Register)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()

	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: %v, %v", st, err)
	}
	if ln, err := listenDaemonSocket(path); err == nil {
		ln.Close()
		t.Fatal("a second listener replaced the live daemon socket")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	for _, tc := range []struct {
		method string
		path   string
		status int
	}{
		{"GET", "/healthz", http.StatusOK},
		{"GET", "/v1/service-mode", http.StatusOK},
		{"POST", "/v1/auth/login", http.StatusForbidden},
		{"GET", "/", http.StatusNotFound},
	} {
		req, err := http.NewRequest(tc.method, "http://localhost"+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Errorf("%s %s: got %d, want %d", tc.method, tc.path, resp.StatusCode, tc.status)
		}
	}
	cancel()
	<-done
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after shutdown: %v", err)
	}
}
