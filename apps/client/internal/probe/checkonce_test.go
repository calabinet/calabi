package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The wizard's check must refuse a public target. The endpoint in front of it
// sits on :7400, which has no auth of its own — an unguarded probe is a port
// scanner aimed at whatever the daemon's host can reach. Note these cases must
// fail WITHOUT dialling, so the test never touches the network.
func TestCheckOnceRefusesNonLocalTargets(t *testing.T) {
	for _, addr := range []string{
		"1.1.1.1:80",
		"8.8.8.8:53",
		"93.184.216.34:443",
	} {
		start := time.Now()
		got := CheckOnce(context.Background(), TunnelTarget{Type: "tcp", LocalAddr: addr})
		if got.Healthy {
			t.Errorf("CheckOnce(%q).Healthy = true, want false", addr)
		}
		if !strings.Contains(got.Error, "public address") {
			t.Errorf("CheckOnce(%q).Error = %q, want it to name the public-address rule", addr, got.Error)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("CheckOnce(%q) took %v — it must reject before dialling", addr, d)
		}
	}
}

func TestCheckOnceMalformedAddr(t *testing.T) {
	for _, addr := range []string{"www.google.com", "127.0.0.1:", "127.0.0.1:http"} {
		got := CheckOnce(context.Background(), TunnelTarget{Type: "http", LocalAddr: addr})
		if got.Healthy {
			t.Errorf("CheckOnce(%q).Healthy = true, want false", addr)
		}
		if got.Error == "" {
			t.Errorf("CheckOnce(%q) gave no reason", addr)
		}
	}
	if got := CheckOnce(context.Background(), TunnelTarget{Type: "http"}); got.Healthy || got.Error != "no local_addr" {
		t.Errorf("empty addr = %+v, want healthy=false error=no local_addr", got)
	}
}

func TestCheckOnceHTTPUpstream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound) // 404 is alive: the process answered
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	got := CheckOnce(context.Background(), TunnelTarget{Type: "http", LocalAddr: addr})
	if !got.Healthy {
		t.Fatalf("live http upstream reported unhealthy: %+v", got)
	}
}

// An HTTP tunnel pointed at a port where something is listening but nothing
// speaks HTTP still fails — which is the whole reason the check knows the type.
func TestCheckOnceHTTPAgainstNonHTTPListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close() // accept then hang up: not an HTTP server
		}
	}()

	addr := ln.Addr().String()
	if got := CheckOnce(context.Background(), TunnelTarget{Type: "tcp", LocalAddr: addr}); !got.Healthy {
		t.Errorf("tcp probe of a live listener = %+v, want healthy", got)
	}
	if got := CheckOnce(context.Background(), TunnelTarget{Type: "http", LocalAddr: addr}); got.Healthy {
		t.Errorf("http probe of a non-HTTP listener = %+v, want unhealthy", got)
	}
}

func TestCheckOnceClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing is listening there now

	got := CheckOnce(context.Background(), TunnelTarget{Type: "tcp", LocalAddr: addr})
	if got.Healthy {
		t.Errorf("closed port reported healthy: %+v", got)
	}
	if got.Error == "" {
		t.Error("closed port gave no reason")
	}
}

// A bare port is a legal local address everywhere else in the client, so the
// check has to expand it the same way rather than dialling "http://8080/".
func TestCheckOnceBarePort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	if got := CheckOnce(context.Background(), TunnelTarget{Type: "tcp", LocalAddr: port}); !got.Healthy {
		t.Errorf("CheckOnce(bare port %q) = %+v, want healthy", port, got)
	}
}

// The reason shown under the wizard's address box must be the cause, not the
// whole wrapped chain — an http failure used to render as
// `Get "http://127.0.0.1:9999/": dial tcp 127.0.0.1:9999: <cause>`, restating
// the address the reader is already looking at.
func TestCheckOnceErrorIsTrimmedToTheCause(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	got := CheckOnce(context.Background(), TunnelTarget{Type: "http", LocalAddr: addr})
	if got.Healthy {
		t.Fatalf("closed port healthy: %+v", got)
	}
	for _, noise := range []string{`Get "http`, "dial tcp"} {
		if strings.Contains(got.Error, noise) {
			t.Errorf("error %q still carries the wrapper %q", got.Error, noise)
		}
	}
	if got.Error == "" {
		t.Error("trimmed away the whole message")
	}
}
