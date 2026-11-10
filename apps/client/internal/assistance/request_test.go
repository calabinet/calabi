package assistance

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestFirstAssistanceRequest(t *testing.T) {
	for _, tc := range []struct {
		name              string
		reject            int32
		op                string
		handshakes, posts int32
		success           bool
	}{
		{"publication delay", 2, "request", 3, 1, true},
		{"persistent TLS failure", 10, "request", 6, 0, false},
		{"untrusted certificate", 0, "request", 1, 0, false},
		{"denied by host", 0, "request", 1, 1, false},
		{"lost response after POST", 0, "request", 1, 1, false},
		{"never retry input", 1, "input", 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var handshakes, posts atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				switch tc.name {
				case "denied by host":
					http.Error(w, "disabled", 403)
				case "lost response after POST":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
				default:
					io.WriteString(w, `{"state":"pending","id":"test"}`)
				}
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				if handshakes.Add(1) <= tc.reject {
					return nil, errors.New("unknown mesh peer")
				}
				return nil, nil
			}}
			server.StartTLS()
			defer server.Close()
			config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			if tc.name == "untrusted certificate" {
				config.VerifyConnection = func(tls.ConnectionState) error { return errors.New("certificate pin mismatch") }
			}
			addr := netip.MustParseAddrPort(server.Listener.Addr().String())
			route := Route{Local: netip.MustParseAddr("127.0.0.1"), Remote: addr.Addr(), Port: addr.Port()}
			var controller Controller
			reply, err := controller.Call(context.Background(), route, config, Command{Op: tc.op})
			if (err == nil) != tc.success || tc.success && reply.State != "pending" || handshakes.Load() != tc.handshakes || posts.Load() != tc.posts {
				t.Fatalf("state=%q error=%v handshakes=%d POSTs=%d", reply.State, err, handshakes.Load(), posts.Load())
			}
		})
	}
}

func TestAssistanceReadHandshakeRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, op               string
		denied                 int
		lostGrant              bool
		status                 int
		wantRefresh, wantPosts int
		success                bool
	}{
		{"republish existing view", "frame", 1, false, 200, 1, 1, true},
		{"propagation delay", "frame_delta", 2, false, 200, 1, 1, true},
		{"current authorization lost", "frame", 1, true, 200, 1, 0, false},
		{"session already ended", "frame", 0, false, 409, 0, 1, false},
		{"input is never replayed", "input", 1, false, 200, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hellos, posts atomic.Int32
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				var c Command
				if err := json.NewDecoder(r.Body).Decode(&c); err != nil || c.ID != "active" || c.Op != tc.op || c.Epoch != 3 {
					t.Error("changed session or operation", err)
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, `{"state":"view","epoch":3}`)
			}))
			srv.Config.ErrorLog = log.New(io.Discard, "", 0)
			srv.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				if int(hellos.Add(1)) <= tc.denied {
					return nil, errors.New("declaration_missing")
				}
				return nil, nil
			}}
			srv.StartTLS()
			defer srv.Close()
			addr := netip.MustParseAddrPort(srv.Listener.Addr().String())
			route := Route{Local: addr.Addr(), Remote: addr.Addr(), Port: addr.Port()}
			refreshes := 0
			refresh := func(_ context.Context, announce bool) error {
				if announce {
					refreshes++
				} else if tc.lostGrant {
					return errors.New("withdrawn")
				}
				return nil
			}
			var c Controller
			r, err := c.CallWithFrameRecovery(context.Background(), route, srv.Client().Transport.(*http.Transport).TLSClientConfig, Command{ID: "active", Op: tc.op, Epoch: 3}, refresh)
			if (err == nil) != tc.success || refreshes != tc.wantRefresh || int(posts.Load()) != tc.wantPosts || tc.success && r.State != "view" {
				t.Fatalf("reply=%s error=%v refresh=%d delivered=%d", r.State, err, refreshes, posts.Load())
			}
		})
	}
}
