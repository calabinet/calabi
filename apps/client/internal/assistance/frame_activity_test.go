package assistance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestFrameNextAllowsInputAndDiscardsRevokedFrame(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := make(chan struct{})
	finish := make(chan struct{})
	defer func() {
		select {
		case <-finish:
		default:
			close(finish)
		}
	}()
	var frames atomic.Int32
	var revoked atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c Command
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			return
		}
		out := Reply{State: "control", Epoch: 1}
		switch c.Op {
		case "frame_delta":
			if frames.Add(1) == 1 {
				close(started)
				select {
				case <-finish:
				case <-r.Context().Done():
					return
				}
				out.Revision = 19
			}
		case "input":
			out.Applied = !revoked.Load()
		}
		if revoked.Load() && out.Revision != 19 {
			out.State = "view"
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	addr := netip.MustParseAddrPort(server.Listener.Addr().String())
	route := Route{Local: addr.Addr(), Remote: addr.Addr(), Port: addr.Port()}
	config := server.Client().Transport.(*http.Transport).TLSClientConfig
	var c Controller
	defer c.Suspend()
	call := func(op string) Reply {
		t.Helper()
		r, e := c.Call(ctx, route, config, Command{Op: op, ID: "session", Epoch: 1})
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	call("release")
	if !call("frame_next").FramePending {
		t.Fatal("expected background frame")
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !call("input").Applied || !call("frame_next").FramePending || frames.Load() != 1 {
		t.Fatal("input blocked or duplicate frame")
	}
	close(finish)
	for {
		r := call("frame_next")
		if !r.FramePending {
			if r.Revision != 19 {
				t.Fatal("missing frame")
			}
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !call("frame_next").FramePending {
		t.Fatal("second frame was not scheduled")
	}
	revoked.Store(true)
	if r := call("input"); r.State != "view" || r.Applied {
		t.Fatal("revoke not observed")
	}
	if r := call("frame_next"); r.State != "view" || c.active != nil || c.frame != nil {
		t.Fatal("stale control restored")
	}
}
