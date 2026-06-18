package session

import (
	"io"
	"sync/atomic"
	"testing"

	"github.com/calabi/calabi/apps/calabi-edge/internal/policy"
)

type fakeConn struct{ closed atomic.Bool }

func (f *fakeConn) Read([]byte) (int, error)  { return 0, io.EOF }
func (f *fakeConn) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeConn) Close() error               { f.closed.Store(true); return nil }

// TestCloseProxyConnsDenied verifies a hot policy update cuts ONLY the
// established connections the new policy denies, leaving allowed ones open —
// the fix for "a new denylist entry doesn't take effect until the browser
// restarts" (keep-alive connections bypass the per-accept check).
func TestCloseProxyConnsDenied(t *testing.T) {
	s := &Session{}
	allowed := &fakeConn{}
	denied := &fakeConn{}
	s.trackConn("p1", &trackedConn{ReadWriteCloser: allowed, s: s, proxyID: "p1", visitorIP: "10.0.0.5"})
	s.trackConn("p1", &trackedConn{ReadWriteCloser: denied, s: s, proxyID: "p1", visitorIP: "127.0.0.1"})

	pol, _ := policy.Parse(`{"security":{"ip":{"deny":["127.0.0.1"]}}}`)
	n := s.CloseProxyConnsDenied("p1", pol)
	if n != 1 {
		t.Fatalf("want 1 conn cut, got %d", n)
	}
	if !denied.closed.Load() {
		t.Fatalf("the denied source (127.0.0.1) must be force-closed")
	}
	if allowed.closed.Load() {
		t.Fatalf("the still-allowed source (10.0.0.5) must stay open")
	}

	// A nil / rule-less policy must cut nothing.
	if got := s.CloseProxyConnsDenied("p1", nil); got != 0 {
		t.Fatalf("nil policy should cut 0 conns, got %d", got)
	}
}
