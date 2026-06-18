package session

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	proto "github.com/calabi/calabi/pkg/protocol"
)

func TestDialUpstream_HTTPUsesPlainTCP(t *testing.T) {
	// httptest.NewServer is a plain HTTP listener.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	addr := stripScheme(srv.URL)
	tun := Tunnel{Type: proto.ProxyKindHTTP, LocalAddr: addr}
	conn, err := dialUpstream(tun)
	if err != nil {
		t.Fatalf("plain dial failed: %v", err)
	}
	defer conn.Close()
	if _, ok := conn.(*tls.Conn); ok {
		t.Fatal("HTTP tunnel dial should NOT be wrapped in TLS")
	}
}

func TestDialUpstream_HTTPSWrapsTLS(t *testing.T) {
	// httptest.NewTLSServer terminates TLS with a self-signed cert —
	// exactly the upstream profile we care about (Home Assistant etc).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secure ok"))
	}))
	defer srv.Close()

	addr := stripScheme(srv.URL)
	tun := Tunnel{Type: proto.ProxyKindHTTPS, LocalAddr: addr}
	conn, err := dialUpstream(tun)
	if err != nil {
		t.Fatalf("tls dial failed: %v", err)
	}
	defer conn.Close()
	if _, ok := conn.(*tls.Conn); !ok {
		t.Fatalf("HTTPS tunnel dial must wrap in TLS; got %T", conn)
	}
}

func TestDialUpstream_HTTPSWithPlainUpstreamFails(t *testing.T) {
	// A plain TCP listener that doesn't speak TLS should reject the
	// TLS-wrapped dial. Verifies we don't silently fall back.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// Accept-and-close so the dialer gets through TCP connect.
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()
	tun := Tunnel{Type: proto.ProxyKindHTTPS, LocalAddr: ln.Addr().String()}
	conn, err := dialUpstream(tun)
	if err == nil {
		conn.Close()
		t.Fatal("expected TLS handshake to fail against plain TCP listener")
	}
}

func stripScheme(u string) string {
	for _, p := range []string{"https://", "http://"} {
		if len(u) > len(p) && u[:len(p)] == p {
			return u[len(p):]
		}
	}
	return u
}
