// oneshot_page_test.go — the page a one-off `calabi http` serves.
//
// Reported 2026-09-15: with no daemon running, `calabi http 8081` bound :7400
// and served the full dashboard SPA. The SPA's first /v1/ call 404'd, so the
// page showed "连接本地守护进程… (HTTP 404) — 若长时间无响应,请检查 daemon 是否
// 运行 (托盘 → 重启 daemon)". Wrong twice over: nothing failed to start, and the
// process serving that page is not a daemon at all.
//
// The writable API is what separates the two: a daemon attaches one, the
// one-off commands never do. So that is what decides which page goes out.
//
// RUN: go test./apps/client/internal/status/ -run TestOneShot -v
package status

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func oneShotServer(t *testing.T) *Server {
	t.Helper()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := New("test", "edge:7443")
	st.AddTunnel(TunnelInfo{
		ProxyID: "p1", Name: "testcli01", Type: "http",
		LocalAddr: "127.0.0.1:8081", PublicAddr: "http://u000009.sgp.calabi.online",
	})
	// No AttachAPI — this is `calabi http`, not `calabi daemon`.
	return NewServer(lg, st, "127.0.0.1:0")
}

func TestOneShotIndexIsNotTheSPA(t *testing.T) {
	rr := httptest.NewRecorder()
	oneShotServer(t).handleIndex(rr, httptest.NewRequest("GET", "/", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /: got %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, `id="root"`) {
		t.Fatal("a one-off command served the dashboard SPA. It has no /v1/ behind " +
			"it, so the page loads and then reports the daemon as unreachable — " +
			"blaming a process that was never meant to be there")
	}
	// It must still be useful: this command's own tunnel is the whole point of
	// having a status page at all.
	if !strings.Contains(body, "u000009.sgp.calabi.online") {
		t.Errorf("the inline page does not list the command's own tunnel:\n%s", body)
	}
	// And it must say whose page it is — somebody arriving at :7400 out of habit
	// is expecting the dashboard.
	if !strings.Contains(body, "calabi daemon") {
		t.Errorf("the inline page does not point at where the real dashboard lives:\n%s", body)
	}
}

// The SPA's asset mounts must be gone too, not just the index: leaving them
// would serve a bundle that only ever renders the error above.
func TestOneShotDoesNotMountTheSPAAssets(t *testing.T) {
	srv := oneShotServer(t)
	srv.AllowBrowser()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()

	var base string
	select {
	case base = <-srv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("status server never bound")
	}

	for _, path := range []string{"/ui/", "/assets/app.js"} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 — leaving the SPA reachable without its "+
				"API just moves the broken page one click away", path, resp.StatusCode)
		}
	}
}
