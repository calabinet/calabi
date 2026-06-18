package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewRegistersAllCollectors(t *testing.T) {
	reg := prometheus.NewRegistry()
	s := New(reg)

	// Sanity: each collector is wired and the registry can gather without
	// panicking. This catches duplicate-name collisions at boot.
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("Gather: %v", err)
	}

	// Drive each helper and re-assert via testutil.ToFloat64 -- this is the
	// canonical way to verify a label-vec increment happened.
	s.OnSessionAccepted()
	if got := testutil.ToFloat64(s.SessionsAcceptedTotal); got != 1 {
		t.Errorf("SessionsAcceptedTotal = %v, want 1", got)
	}

	s.SetActiveSessions(3)
	if got := testutil.ToFloat64(s.ActiveSessions); got != 3 {
		t.Errorf("ActiveSessions = %v, want 3", got)
	}

	s.OnProxyOpened("http")
	s.OnProxyOpened("http")
	s.OnProxyOpened("tcp")
	if got := testutil.ToFloat64(s.ActiveProxies.WithLabelValues("http")); got != 2 {
		t.Errorf("ActiveProxies{http} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(s.ActiveProxies.WithLabelValues("tcp")); got != 1 {
		t.Errorf("ActiveProxies{tcp} = %v, want 1", got)
	}

	s.OnProxyClosed("http", "client_close")
	if got := testutil.ToFloat64(s.ActiveProxies.WithLabelValues("http")); got != 1 {
		t.Errorf("ActiveProxies{http} after close = %v, want 1", got)
	}

	s.OnBytesTransferred("http", "visitor_to_client", 1024)
	s.OnBytesTransferred("http", "visitor_to_client", 512)
	if got := testutil.ToFloat64(s.BytesTransferredTotal.WithLabelValues("http", "visitor_to_client")); got != 1536 {
		t.Errorf("BytesTransferredTotal = %v, want 1536", got)
	}

	// Negative or zero bytes are silently ignored (avoids dirty counters).
	s.OnBytesTransferred("http", "visitor_to_client", 0)
	s.OnBytesTransferred("http", "visitor_to_client", -10)
	if got := testutil.ToFloat64(s.BytesTransferredTotal.WithLabelValues("http", "visitor_to_client")); got != 1536 {
		t.Errorf("BytesTransferredTotal after zero/negative = %v, want 1536", got)
	}

	s.OnHandshakeFailure("auth")
	if got := testutil.ToFloat64(s.HandshakeFailuresTotal.WithLabelValues("auth")); got != 1 {
		t.Errorf("HandshakeFailuresTotal{auth} = %v, want 1", got)
	}
}
