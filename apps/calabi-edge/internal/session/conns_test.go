package session

import (
	"io"
	"testing"
)

// fakeRWC is a minimal in-flight data stream stand-in.
type fakeRWC struct {
	closed int
}

func (f *fakeRWC) Read([]byte) (int, error)  { return 0, io.EOF }
func (f *fakeRWC) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeRWC) Close() error                { f.closed++; return nil }

// CloseProxyConns must force-close every tracked stream for the proxy and
// be idempotent / safe on an unknown proxy id.
func TestCloseProxyConns(t *testing.T) {
	s := &Session{} // conns starts nil; trackConn must initialise it
	a, b := &fakeRWC{}, &fakeRWC{}
	ta := &trackedConn{ReadWriteCloser: a, s: s, proxyID: "p1"}
	tb := &trackedConn{ReadWriteCloser: b, s: s, proxyID: "p1"}
	other := &fakeRWC{}
	to := &trackedConn{ReadWriteCloser: other, s: s, proxyID: "p2"}
	s.trackConn("p1", ta)
	s.trackConn("p1", tb)
	s.trackConn("p2", to)

	if n := s.CloseProxyConns("p1"); n != 2 {
		t.Fatalf("CloseProxyConns(p1) = %d, want 2", n)
	}
	if a.closed != 1 || b.closed != 1 {
		t.Fatalf("p1 streams not closed exactly once: a=%d b=%d", a.closed, b.closed)
	}
	if other.closed != 0 {
		t.Fatalf("p2 stream must not be touched, closed=%d", other.closed)
	}
	// Idempotent: the proxy entry is gone now.
	if n := s.CloseProxyConns("p1"); n != 0 {
		t.Fatalf("second CloseProxyConns(p1) = %d, want 0", n)
	}
	// Unknown proxy id is a no-op.
	if n := s.CloseProxyConns("nope"); n != 0 {
		t.Fatalf("CloseProxyConns(unknown) = %d, want 0", n)
	}
}

// A listener-initiated Close() must deregister the stream so a later
// CloseProxyConns doesn't double-close it, and the underlying close fires
// exactly once.
func TestTrackedConn_CloseDeregisters(t *testing.T) {
	s := &Session{}
	f := &fakeRWC{}
	tc := &trackedConn{ReadWriteCloser: f, s: s, proxyID: "p1"}
	s.trackConn("p1", tc)

	if err := tc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if f.closed != 1 {
		t.Fatalf("underlying close count = %d, want 1", f.closed)
	}
	// Already deregistered → teardown finds nothing.
	if n := s.CloseProxyConns("p1"); n != 0 {
		t.Fatalf("CloseProxyConns after Close = %d, want 0", n)
	}
	// Double Close stays idempotent on the underlying stream.
	if err := tc.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if f.closed != 1 {
		t.Fatalf("underlying closed again: count = %d, want 1", f.closed)
	}
}
