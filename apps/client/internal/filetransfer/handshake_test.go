package filetransfer

import (
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestInboundHandshakeDiagnostics(t *testing.T) {
	receiver, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sender, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.Addr().(*net.TCPAddr).AddrPort()
	var published atomic.Bool
	type event struct {
		ip       netip.Addr
		reason   string
		verified bool
	}
	events := make(chan event, 8)
	lookup := func(ip netip.Addr) (Grant, error) {
		if !published.Load() {
			return Grant{}, errors.New("declaration_missing")
		}
		return Grant{Peer: Peer{IP: ip, Fingerprint: sender.Fingerprint}}, nil
	}
	agent, err := NewAgent(AgentConfig{Directory: t.TempDir(), Scope: "test", Identity: receiver, LocalIP: addr.Addr(), Port: addr.Port(), Kbps: 512, MaxBytes: 1024,
		Resolve: func(ip netip.Addr) (Grant, bool) { g, e := lookup(ip); return g, e == nil }, Incoming: func(netip.Addr, uint16) bool { return false },
		HandshakeLookup: lookup, HandshakeLog: func(ip netip.Addr, s string, v bool) { events <- event{ip, s, v} }})
	if err != nil {
		t.Fatal(err)
	}
	done, err := agent.Serve(l)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { agent.Close(); <-done }()
	for _, reason := range []string{"declaration_missing", "transfer certificate fingerprint mismatch", "tls: client didn't provide a certificate", "peer_certificate_verified"} {
		config := sender.ClientTLS(Peer{IP: addr.Addr(), Fingerprint: receiver.Fingerprint})
		if reason != "declaration_missing" {
			published.Store(true)
		}
		if reason == "transfer certificate fingerprint mismatch" {
			config.Certificates = []tls.Certificate{receiver.Certificate}
		}
		if reason == "tls: client didn't provide a certificate" {
			config.Certificates = nil
		}
		conn, err := tls.Dial("tcp", addr.String(), config)
		if conn != nil {
			defer conn.Close()
		}
		if reason == "peer_certificate_verified" && err != nil {
			t.Fatal(err)
		}
		select {
		case e := <-events:
			if e.reason != reason || e.ip != addr.Addr() || e.verified != (reason == "peer_certificate_verified") {
				t.Fatalf("want %q got %+v", reason, e)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no server diagnostic for %q", reason)
		}
	}
}
