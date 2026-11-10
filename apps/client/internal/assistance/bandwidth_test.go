package assistance

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type meteredListener struct {
	net.Listener
	sent, received, connections atomic.Int64
}

type meteredConn struct {
	net.Conn
	meter *meteredListener
}

func (l *meteredListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.connections.Add(1)
	return &meteredConn{c, l}, nil
}
func (c *meteredConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.meter.received.Add(int64(n))
	return n, e
}
func (c *meteredConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.meter.sent.Add(int64(n))
	return n, e
}

func TestIdleTransport(t *testing.T) {
	for _, state := range []string{"view", "control"} {
		t.Run(state, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var cmd Command
				if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
					http.Error(w, "bad command", 400)
					return
				}
				reply := Reply{State: state, Epoch: 1, Revision: 1}
				if cmd.Op == "request" {
					reply = Reply{ID: "test", State: "pending", FrameDelta: true}
				}
				json.NewEncoder(w).Encode(reply)
			}))
			meter := &meteredListener{Listener: server.Listener}
			server.Listener = meter
			server.StartTLS()
			defer server.Close()
			tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig
			addr := server.Listener.Addr().(*net.TCPAddr).AddrPort()
			route := Route{Local: netip.MustParseAddr("127.0.0.1"), Remote: addr.Addr(), Port: addr.Port()}
			var controller Controller
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			call := func(c Command) {
				t.Helper()
				if _, err := controller.Call(ctx, route, tlsConfig, c); err != nil {
					t.Fatal(err)
				}
			}
			call(Command{Op: "request"})
			frame := Command{Op: "frame_delta", ID: "test", Epoch: 1, Baseline: 1}
			call(frame)
			start := time.Now()
			before := meter.sent.Load() + meter.received.Load()
			for i := 0; i < 30; i++ {
				time.Sleep(160 * time.Millisecond)
				call(frame)
			}
			total := meter.sent.Load() + meter.received.Load() - before
			t.Logf("encrypted bidirectional bytes=%d elapsed=%v throughput=%.1f kbit/s connections=%d", total, time.Since(start), float64(total)*8/time.Since(start).Seconds()/1000, meter.connections.Load())
			if total > 100000 || meter.connections.Load() > 4 {
				t.Fatal("idle polls did not reuse a bounded transport")
			}
			call(Command{Op: "end", ID: "test", Epoch: 1})
		})
	}
}
