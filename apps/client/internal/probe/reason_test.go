package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

// The whole point of Reason is that the UI never has to pattern-match an OS
// sentence. These tests dial real sockets rather than hand-building errors,
// because the thing that actually breaks is the platform reporting something
// the classifier doesn't recognise — and a hand-built error can't catch that.
//
// Windows is the specific trap: it reports WSAECONNREFUSED (10061), which is
// NOT syscall.ECONNREFUSED there, so errors.Is misses it. If someone
// "simplifies" reason.go down to the platform constant, this test goes red on
// Windows and stays green on Linux — which is exactly the asymmetry that let
// the bug exist in the first place.
func TestClassify_RefusedIsRecognisedOnThisPlatform(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // nothing is listening there now

	res := CheckOnce(context.Background(), TunnelTarget{Type: "tcp", LocalAddr: addr})
	if res.Healthy {
		t.Skip("something grabbed the port between close and dial")
	}
	if res.Reason != ReasonRefused {
		t.Fatalf("reason = %q (error %q), want %q — the classifier does not recognise this platform's refused-connection error",
			res.Reason, res.Error, ReasonRefused)
	}
}

// A healthy target must carry NO reason: the UI keys "show a friendly failure
// line" off Reason being set, so a stray code would put a warning under a
// working service.
func TestClassify_HealthyHasNoReason(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	res := CheckOnce(context.Background(), TunnelTarget{Type: "tcp", LocalAddr: l.Addr().String()})
	if !res.Healthy {
		t.Fatalf("expected healthy, got %+v", res)
	}
	if res.Reason != "" {
		t.Fatalf("healthy result carries reason %q", res.Reason)
	}
}

// An address the validator rejects never reaches the dialler, so it needs its
// own reason — otherwise the UI shows a raw validation string.
func TestClassify_InvalidAddress(t *testing.T) {
	res := CheckOnce(context.Background(), TunnelTarget{Type: "http", LocalAddr: "8.8.8.8:53"})
	if res.Healthy {
		t.Fatalf("a public address must not pass the local-target validator: %+v", res)
	}
	if res.Reason != ReasonInvalid {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonInvalid)
	}
}

// A deadline must classify as timeout regardless of which layer reports it.
func TestClassify_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	// 10.255.255.1 is RFC1918 (so it passes the local-target validator) and
	// almost never routable, but the nanosecond deadline is what decides here.
	res := CheckOnce(ctx, TunnelTarget{Type: "tcp", LocalAddr: "10.255.255.1:1"})
	if res.Healthy {
		t.Skip("unexpectedly reachable")
	}
	if res.Reason != ReasonTimeout {
		t.Fatalf("reason = %q (error %q), want %q", res.Reason, res.Error, ReasonTimeout)
	}
}
