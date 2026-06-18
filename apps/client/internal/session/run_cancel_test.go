package session

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/calabi/calabi/apps/client/internal/transport"
	"github.com/hashicorp/yamux"
)

// TestRunStopsOnContextCancel is the regression for "无法用 Ctrl+C 终止":
// an idle session parks in c.ctrl.Read(), and the control loop only checked
// ctx.Done() between frames — so cancelling ctx (Ctrl+C) did nothing until a
// frame arrived or the TCP connection died (minutes). Run now closes the mux
// on ctx cancel, which unblocks the Read; this test sends NO frames, cancels,
// and asserts Run returns promptly.
func TestRunStopsOnContextCancel(t *testing.T) {
	mux, srvCtrl := newYamuxMuxPair(t)
	// Drain the server side so yamux flow control never blocks the client's
	// heartbeat writes; we never feed a frame back, keeping the stream idle.
	go io.Copy(io.Discard, srvCtrl)

	c := &Client{
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		mux:               mux,
		ctrl:              newFrameStream(mux.Control),
		heartbeatInterval: time.Hour, // don't let the heartbeat write during the test
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, func(string) (Tunnel, bool) { return Tunnel{}, false })
	}()

	// Give Run a moment to reach the blocking c.ctrl.Read().
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Run returned after cancel — the fix works.
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of ctx cancel — an idle Ctrl+C would hang")
	}
}

// newYamuxMuxPair stands up a real yamux session over a TCP loopback and
// returns the client-side transport.Mux (with its control stream opened) plus
// the server-side control stream. A real mux is required because the fix under
// test relies on transport.Mux.Close() unblocking a parked yamux Read — a
// net.Pipe wouldn't exercise that path.
func newYamuxMuxPair(t *testing.T) (*transport.Mux, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type srv struct {
		sess *yamux.Session
		conn net.Conn
	}
	srvCh := make(chan srv, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvCh <- srv{}
			return
		}
		sess, err := yamux.Server(conn, nil)
		if err != nil {
			srvCh <- srv{}
			return
		}
		srvCh <- srv{sess: sess}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	csess, err := yamux.Client(conn, nil)
	if err != nil {
		t.Fatalf("yamux client: %v", err)
	}
	cctrl, err := csess.OpenStream()
	if err != nil {
		t.Fatalf("open control stream: %v", err)
	}
	// Nudge the stream open so the server's AcceptStream fires.
	if _, err := cctrl.Write([]byte{}); err != nil {
		t.Fatalf("prime control stream: %v", err)
	}

	s := <-srvCh
	if s.sess == nil {
		t.Fatal("server yamux session setup failed")
	}
	sctrl, err := s.sess.AcceptStream()
	if err != nil {
		t.Fatalf("accept control stream: %v", err)
	}

	t.Cleanup(func() {
		_ = s.sess.Close()
	})
	return &transport.Mux{Conn: conn, Session: csess, Control: cctrl}, sctrl
}
