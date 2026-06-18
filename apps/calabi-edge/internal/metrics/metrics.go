// Package metrics holds the calabi-edge-specific Prometheus collectors.
//
// every milestone must surface
// Prometheus metrics + structured logs + trace spans. shipped the
// surface; (this) moved the runtime + admin HTTP server into
// pkg/observability so all six control-plane services share the baseline.
//
// Design notes:
//   - The Registry is owned by pkg/observability; we register our
//     collectors into the provided one (no global state).
//   - All metrics carry a stable name with the "calabi_edge_" prefix.
//   - Cardinality is bounded: proxy_type labels are limited to the small
//     set defined in proto.ProxyKind. We do NOT emit per-tenant labels
//     here -- that's metering-svc territory.
//   - build_info is supplied by pkg/observability (calabi_build_info with
//     a service label), so we don't duplicate it here.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Set bundles every collector calabi-edge exposes. Pass instances around by
// pointer; nil-checks are intentionally absent to surface wiring bugs as
// nil-deref crashes during dev rather than silent metric loss.
type Set struct {
	// Session lifecycle.
	ActiveSessions         prometheus.Gauge
	SessionsAcceptedTotal  prometheus.Counter
	SessionsClosedTotal    prometheus.Counter
	HandshakeFailuresTotal *prometheus.CounterVec // labels: reason

	// Proxy lifecycle. proxy_type ∈ {http, tcp, udp, https, sni, grpc, stdio}.
	ActiveProxies      *prometheus.GaugeVec   // labels: proxy_type
	ProxiesOpenedTotal *prometheus.CounterVec // labels: proxy_type
	ProxiesClosedTotal *prometheus.CounterVec // labels: proxy_type, reason

	// Visitor-facing traffic.
	VisitorRequestsTotal  *prometheus.CounterVec // labels: proxy_type, outcome
	BytesTransferredTotal *prometheus.CounterVec // labels: proxy_type, direction
}

// New constructs a Set and registers all collectors on the supplied
// registry (owned by pkg/observability).
//
// If a collector fails to register (duplicate name, etc.) the underlying
// prometheus library panics -- which is the right behavior since this is
// a programmer error caught at boot time.
func New(reg prometheus.Registerer) *Set {
	s := &Set{}

	s.ActiveSessions = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "calabi_edge_active_sessions",
		Help: "Number of currently connected client sessions.",
	})
	s.SessionsAcceptedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "calabi_edge_sessions_accepted_total",
		Help: "Total number of client sessions that completed handshake.",
	})
	s.SessionsClosedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "calabi_edge_sessions_closed_total",
		Help: "Total number of client sessions that have exited.",
	})
	s.HandshakeFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "calabi_edge_handshake_failures_total",
		Help: "Failed client handshakes, partitioned by reason.",
	}, []string{"reason"})

	s.ActiveProxies = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "calabi_edge_active_proxies",
		Help: "Number of currently registered proxies, by type.",
	}, []string{"proxy_type"})
	s.ProxiesOpenedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "calabi_edge_proxies_opened_total",
		Help: "Total proxies opened, by type.",
	}, []string{"proxy_type"})
	s.ProxiesClosedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "calabi_edge_proxies_closed_total",
		Help: "Total proxies closed, by type and reason.",
	}, []string{"proxy_type", "reason"})

	s.VisitorRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "calabi_edge_visitor_requests_total",
		Help: "Visitor-facing requests routed through edge, by type and outcome.",
	}, []string{"proxy_type", "outcome"})

	s.BytesTransferredTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "calabi_edge_bytes_transferred_total",
		Help: "Bytes proxied between visitor and client, by type and direction.",
	}, []string{"proxy_type", "direction"})

	reg.MustRegister(
		s.ActiveSessions,
		s.SessionsAcceptedTotal,
		s.SessionsClosedTotal,
		s.HandshakeFailuresTotal,
		s.ActiveProxies,
		s.ProxiesOpenedTotal,
		s.ProxiesClosedTotal,
		s.VisitorRequestsTotal,
		s.BytesTransferredTotal,
	)
	return s
}
