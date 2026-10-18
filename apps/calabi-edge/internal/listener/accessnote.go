// accessnote.go — the one place a listener turns "what just happened to this
// visitor" into a row of the tunnel access log.
//
// Every listener calls noteAccess at each terminal decision for a visitor
// connection, using the vocabulary in internal/accesslog. Keeping the lookup
// (session + proxy id → org + tunnel) here rather than at each call site means
// the five listeners cannot drift on what a row is keyed by.
//
// Cost when nothing is wired: one map lookup for the proxy plus an atomic load
// that finds no sink. That is why the call sits at the decision points rather
// than behind a per-listener option — there is nothing to switch off.
package listener

import (
	"log/slog"
	"net"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/accesslog"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/session"
)

// noteAccess records one visitor connection's outcome against the tunnel it was
// aimed at.
//
// A proxy that has gone away between the routing lookup and here (teardown
// racing an accept) records nothing: without it there is no tunnel id, and a
// row that cannot name its tunnel is not worth writing.
func noteAccess(sess *session.Session, proxyID, visitorIP, outcome string) {
	if sess == nil {
		return
	}
	p := sess.Proxy(proxyID)
	if p == nil {
		return
	}
	accesslog.Note(sess.OrgID(), p.TunnelID, visitorIP, outcome)
}

// noteAccessAddr is noteAccess for the callers that hold a net.Addr rather than
// an already-extracted address string.
func noteAccessAddr(sess *session.Session, proxyID string, addr net.Addr, outcome string) {
	noteAccess(sess, proxyID, extractIP(addr), outcome)
}

// logPolicyDenial is independent of the access-record sink: BYOI nodes without
// a bus cannot publish those records, but operators still need to diagnose a
// refusal before TLS reaches the daemon. Never log the policy itself or TLS
// payloads. The forward listener must supply the original visitor's IP.
func logPolicyDenial(logger *slog.Logger, sess *session.Session, p *session.Proxy, visitorIP, outcome string) {
	logger.Info("visitor denied by security policy",
		"outcome", outcome, "visitor_ip", visitorIP,
		"domain", p.Domain, "proxy_type", string(p.Type),
		"proxy_id", p.ID, "session_id", sess.ID,
		"org_id", sess.OrgID(), "tunnel_id", p.TunnelID)
}
