package assistance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Only the frame response is slow. The host must still hear from a live viewer,
// and the heartbeat must disappear when that frame request finishes.
func TestViewHeartbeatDuringSlowFrame(t *testing.T) {
	for _, supported := range []bool{true, false} {
		t.Run(map[bool]string{true: "negotiated", false: "legacy"}[supported], func(t *testing.T) {
			var last, pings atomic.Int64
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var c Command
				if json.NewDecoder(r.Body).Decode(&c) != nil {
					t.Error("bad command")
					return
				}
				reply := Reply{State: "view"}
				switch c.Op {
				case "request":
					reply = Reply{ID: "original", State: "pending", ViewPing: supported}
				case "frame_delta":
					last.Store(time.Now().UnixMilli())
					time.Sleep(4100 * time.Millisecond)
					if time.Now().UnixMilli()-last.Load() > 3500 {
						http.Error(w, "viewer_idle_timeout", 409)
						return
					}
				case "view_ping":
					if !supported || c.ID != "original" || c.Epoch != 0 || c.Input != "" {
						t.Error("unexpected heartbeat or input")
					}
					last.Store(time.Now().UnixMilli())
					pings.Add(1)
				default:
					t.Error("unexpected operation", c.Op)
				}
				json.NewEncoder(w).Encode(reply)
			}))
			defer srv.Close()
			addr := netip.MustParseAddrPort(srv.Listener.Addr().String())
			var ctrl Controller
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if _, e := ctrl.Do(ctx, srv.Client(), addr.Addr(), addr.Port(), Command{Op: "request"}); e != nil {
				t.Fatal(e)
			}
			got, e := ctrl.Do(ctx, srv.Client(), addr.Addr(), addr.Port(), Command{Op: "frame_delta", ID: "original"})
			if !supported {
				if e == nil || !strings.Contains(e.Error(), "viewer_idle_timeout") || pings.Load() != 0 {
					t.Fatal(e, pings.Load())
				}
				return
			}
			n := pings.Load()
			if e != nil || got.State != "view" || ctrl.active != nil || n < 2 {
				t.Fatal(got.State, e, n)
			}
			time.Sleep(time.Second)
			if pings.Load() != n {
				t.Fatal("heartbeat outlived frame")
			}
		})
	}
}
