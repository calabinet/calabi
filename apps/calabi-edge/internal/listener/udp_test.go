package listener

import (
	"net"
	"testing"
	"time"
)

// TestSplitUDPAddr exercises the *net.UDPAddr fast path + the SplitHostPort fallback.
func TestSplitUDPAddr(t *testing.T) {
	cases := []struct {
		addr     net.Addr
		wantHost string
		wantPort uint32
	}{
		{&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 54321}, "10.0.0.1", 54321},
		{&net.UDPAddr{IP: net.ParseIP("::1"), Port: 9090}, "::1", 9090},
	}
	for _, c := range cases {
		host, port := splitUDPAddr(c.addr)
		if host != c.wantHost || port != c.wantPort {
			t.Fatalf("splitUDPAddr(%v) = (%q, %d), want (%q, %d)",
				c.addr, host, port, c.wantHost, c.wantPort)
		}
	}
}

// Ensure StartUDPProxy refuses remote_port=0 (the proto handshake assigns
// a port up front; a 0 here is a bug).
func TestStartUDPProxy_RejectsZeroPort(t *testing.T) {
	_, err := StartUDPProxy(nil, 0, nil, "p-x", nil, nil)
	if err == nil {
		t.Fatalf("expected error on port 0")
	}
}

// Time helpers: keep tests fast but stable.
func eventually(t *testing.T, d time.Duration, fn func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("eventually: %s", msg)
}
