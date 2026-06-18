package metrics

// This file wires *Set up to the small interfaces declared in the consumer
// packages (session.SessionObserver, listener.HTTPObserver,
// listener.TCPObserver). Keeping the interface satisfaction here lets the
// consumer packages stay independent of Prometheus -- they just see plain
// method calls, which keeps them trivially mockable.

// --- session.SessionObserver -----------------------------------------------

func (s *Set) OnSessionAccepted() { s.SessionsAcceptedTotal.Inc() }
func (s *Set) OnSessionClosed()   { s.SessionsClosedTotal.Inc() }
func (s *Set) SetActiveSessions(n int) {
	s.ActiveSessions.Set(float64(n))
}

func (s *Set) OnProxyOpened(proxyType string) {
	s.ProxiesOpenedTotal.WithLabelValues(proxyType).Inc()
	s.ActiveProxies.WithLabelValues(proxyType).Inc()
}

func (s *Set) OnProxyClosed(proxyType, reason string) {
	s.ProxiesClosedTotal.WithLabelValues(proxyType, reason).Inc()
	s.ActiveProxies.WithLabelValues(proxyType).Dec()
}

// --- listener observers ---------------------------------------------------

// OnVisitorRequest is incremented every time a visitor-facing connection
// is dispatched (or fails). outcome is one of {"ok", "no_tunnel",
// "open_upstream_failed", "sniff_failed"}.
func (s *Set) OnVisitorRequest(proxyType, outcome string) {
	s.VisitorRequestsTotal.WithLabelValues(proxyType, outcome).Inc()
}

// OnBytesTransferred adds n bytes to the rolling counter. direction is one
// of {"visitor_to_client", "client_to_visitor"}.
func (s *Set) OnBytesTransferred(proxyType, direction string, n int64) {
	if n <= 0 {
		return
	}
	s.BytesTransferredTotal.WithLabelValues(proxyType, direction).Add(float64(n))
}

// OnHandshakeFailure increments handshake failures by reason.
func (s *Set) OnHandshakeFailure(reason string) {
	s.HandshakeFailuresTotal.WithLabelValues(reason).Inc()
}
