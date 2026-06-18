package listener

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/mesh"
	"github.com/calabi/calabi/apps/calabi-edge/internal/router"
)

// TestMeshRoundTripMiss wires the relay side (relayToPeer) to a REAL owner-
// side Forward listener over loopback TCP and asserts the full frame round
// trip on a router miss: relay encodes the frame → Forward decodes it →
// routes (miss, no route registered) → writes a 502 → relay splices it back
// to the visitor. This is the integration of (forward listener) and
// (relay) without the session/yamux data path.
func TestMeshRoundTripMiss(t *testing.T) {
	// Owner edge: a real Forward listener with an EMPTY router → every
	// lookup misses.
	r := router.New()
	fwd := NewForward(discardLogger(), ForwardOptions{
		Addr:   "127.0.0.1:0",
		Router: r,
	})
	// Bind explicitly so we can read the chosen port before Run's accept loop.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fwd.ln = ln
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go fwd.handle(c)
		}
	}()

	// Visitor loopback pair: vs handed to relayToPeer, vc plays the browser.
	visLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer visLn.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := visLn.Accept(); accepted <- c }()
	vc, err := net.Dial("tcp", visLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer vc.Close()
	vs := <-accepted
	defer vs.Close()

	resolver := fakeResolver{addr: ln.Addr().String(), id: 7, ok: true}

	go func() {
		relayToPeer(discardLogger(), resolver, 1, nil,
			mesh.KindHTTP, "u1.cn-chengdu.example.com", "/", vs, bufio.NewReader(vs),
			[]byte("GET / HTTP/1.1\r\nHost: u1.cn-chengdu.example.com\r\n\r\n"))
		// Mirror listener.handle's `defer visitor.Close()` so the visitor
		// read below sees EOF promptly once the relay splice ends.
		_ = vs.Close()
	}()

	// The visitor should receive the owner's 502 (relayed back).
	_ = vc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf, _ := io.ReadAll(vc)
	got := string(buf)
	if !strings.Contains(got, "502") || !strings.Contains(got, "no tunnel for host") {
		t.Fatalf("visitor should receive a 502 from the owner via the relay, got:\n%q", got)
	}
}

// TestMeshRoundTripHit wires the relay to a REAL Forward listener whose
// router HAS a route, but with a stub session type that is NOT
// *session.Session. The forward handler's type assertion fails → it writes a
// 500 back. This exercises the hit-branch lookup + the type-mismatch guard
// across the wire without standing up a yamux session.
func TestMeshRoundTripRouteTypeMismatch(t *testing.T) {
	r := router.New()
	// Register an HTTP route whose Session is a non-*session.Session value so
	// the forward handler's target.Session.(*session.Session) assertion fails.
	if err := r.RegisterHTTP("u2.cn-chengdu.example.com", "not-a-session", "sess-1", "proxy-1"); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fwd := NewForward(discardLogger(), ForwardOptions{Router: r})
	fwd.ln = ln
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go fwd.handle(c)
		}
	}()

	// Dial the owner directly as if we were a relay: write the frame, read
	// the response.
	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := mesh.WriteFrame(peer, mesh.ForwardHeader{
		Kind: mesh.KindHTTP, Host: "u2.cn-chengdu.example.com", Path: "/",
	}, []byte("GET / HTTP/1.1\r\nHost: u2.cn-chengdu.example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf, _ := io.ReadAll(peer)
	if !strings.Contains(string(buf), "500") {
		t.Fatalf("route type mismatch should yield 500, got:\n%q", buf)
	}
	_ = context.Background()
}
