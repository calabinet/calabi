// Package router maps externally visible identifiers (HTTP Host, TCP port)
// to the session + proxy that should receive the visitor connection.
//
// implementation: pure in-memory sync.Map. adds L2 ristretto cache +
// L3 Redis lookup per technical-design
package router

import (
	"errors"
	"strings"
	"sync"
)

// Target is what a router lookup yields.
type Target struct {
	SessionID string
	ProxyID   string

	// Opaque handle used by the caller to obtain the *session.Session.
	// We keep it as any to avoid an import cycle (router <- session).
	Session any
}

// Router holds the routing tables.
//
// Tables are kept separate per kind so the same domain or port can be
// registered as different kinds (e.g. an HTTP route on `foo.calabi.net`
// and an SNI passthrough on the same name listening on a different port).
type Router struct {
	mu sync.RWMutex

	httpByDomain map[string]*entry // key = lowercase host (no port)
	sniByDomain  map[string]*entry // key = lowercase SNI server_name
	tcpByPort    map[uint32]*entry
	udpByPort    map[uint32]*entry
	byProxyID    map[string]*entry
}

type entry struct {
	Target
	kind string // "http" | "tcp" | "udp" | "sni"
	key  string // domain (http/sni) or stringified port (tcp/udp)
}

// New builds an empty router.
func New() *Router {
	return &Router{
		httpByDomain: make(map[string]*entry),
		sniByDomain:  make(map[string]*entry),
		tcpByPort:    make(map[uint32]*entry),
		udpByPort:    make(map[uint32]*entry),
		byProxyID:    make(map[string]*entry),
	}
}

// RegisterHTTP binds domain -> (sess, proxyID). domain is canonicalized to
// lower case; the port part of a Host header MUST be stripped by callers.
func (r *Router) RegisterHTTP(domain string, sess any, sessionID, proxyID string) error {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return errors.New("router: empty domain")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.httpByDomain[d]; exists {
		return errors.New("domain already registered")
	}
	e := &entry{
		Target: Target{SessionID: sessionID, ProxyID: proxyID, Session: sess},
		kind:   "http",
		key:    d,
	}
	r.httpByDomain[d] = e
	r.byProxyID[proxyID] = e
	return nil
}

// RegisterTCP binds remote_port -> (sess, proxyID).
func (r *Router) RegisterTCP(port uint32, sess any, sessionID, proxyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tcpByPort[port]; exists {
		return errors.New("tcp port already registered")
	}
	e := &entry{
		Target: Target{SessionID: sessionID, ProxyID: proxyID, Session: sess},
		kind:   "tcp",
	}
	r.tcpByPort[port] = e
	r.byProxyID[proxyID] = e
	return nil
}

// RegisterUDP binds a UDP remote_port -> (sess, proxyID). UDP and TCP
// tables are independent: the same port number is allowed on both
// (different protocols are different OS resources).
func (r *Router) RegisterUDP(port uint32, sess any, sessionID, proxyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.udpByPort[port]; exists {
		return errors.New("udp port already registered")
	}
	e := &entry{
		Target: Target{SessionID: sessionID, ProxyID: proxyID, Session: sess},
		kind:   "udp",
	}
	r.udpByPort[port] = e
	r.byProxyID[proxyID] = e
	return nil
}

// RegisterSNI binds an SNI server_name -> (sess, proxyID). The SNI table
// is independent from HTTP because the routing key is the TLS SNI
// extension (no Host header) and the listener binds a different port.
func (r *Router) RegisterSNI(domain string, sess any, sessionID, proxyID string) error {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return errors.New("router: empty sni domain")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.sniByDomain[d]; exists {
		return errors.New("sni domain already registered")
	}
	e := &entry{
		Target: Target{SessionID: sessionID, ProxyID: proxyID, Session: sess},
		kind:   "sni",
		key:    d,
	}
	r.sniByDomain[d] = e
	r.byProxyID[proxyID] = e
	return nil
}

// LookupHTTP returns the routing target for an HTTP Host header (which may
// include a :port suffix).
func (r *Router) LookupHTTP(host string) (Target, bool) {
	host = strings.ToLower(host)
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.httpByDomain[host]
	if !ok {
		return Target{}, false
	}
	return e.Target, true
}

// LookupTCP returns the routing target for a TCP port.
func (r *Router) LookupTCP(port uint32) (Target, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.tcpByPort[port]
	if !ok {
		return Target{}, false
	}
	return e.Target, true
}

// LookupUDP returns the routing target for a UDP port.
func (r *Router) LookupUDP(port uint32) (Target, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.udpByPort[port]
	if !ok {
		return Target{}, false
	}
	return e.Target, true
}

// LookupSNI returns the routing target for a TLS SNI server_name.
func (r *Router) LookupSNI(host string) (Target, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.sniByDomain[host]
	if !ok {
		return Target{}, false
	}
	return e.Target, true
}

// connCloser is implemented by *session.Session. Declared here (rather than
// importing session) to avoid a router <- session import cycle — the router
// only ever holds the session as an opaque Target.Session (any).
type connCloser interface {
	CloseProxyConns(proxyID string) int
}

// UnregisterByProxyID removes whatever entry the proxy created AND force-
// closes any in-flight visitor connections still riding it. The latter is
// essential: route removal alone only blocks NEW lookups — an already-
// spliced keep-alive visitor connection would otherwise keep flowing on its
// open data stream after a disable / CLOSE_PROXY / config push, so the
// tunnel would "keep working as long as the browser stays open".
func (r *Router) UnregisterByProxyID(proxyID string) {
	r.mu.Lock()
	e, ok := r.byProxyID[proxyID]
	if !ok {
		r.mu.Unlock()
		return
	}
	delete(r.byProxyID, proxyID)
	switch e.kind {
	case "http":
		delete(r.httpByDomain, e.key)
	case "sni":
		delete(r.sniByDomain, e.key)
	case "tcp":
		// We don't keep the port on the entry; iterate.
		for p, ent := range r.tcpByPort {
			if ent == e {
				delete(r.tcpByPort, p)
				break
			}
		}
	case "udp":
		for p, ent := range r.udpByPort {
			if ent == e {
				delete(r.udpByPort, p)
				break
			}
		}
	}
	sess := e.Session
	r.mu.Unlock()
	// Drop in-flight connections outside the router lock — Close() touches
	// the network and the session's own mutex.
	if cc, ok := sess.(connCloser); ok {
		cc.CloseProxyConns(proxyID)
	}
}

// Snapshot returns a stable copy of the current routing tables for /metrics
// or debug pages.
func (r *Router) Snapshot() (httpDomains, sniDomains []string, tcpPorts, udpPorts []uint32) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	httpDomains = make([]string, 0, len(r.httpByDomain))
	for d := range r.httpByDomain {
		httpDomains = append(httpDomains, d)
	}
	sniDomains = make([]string, 0, len(r.sniByDomain))
	for d := range r.sniByDomain {
		sniDomains = append(sniDomains, d)
	}
	tcpPorts = make([]uint32, 0, len(r.tcpByPort))
	for p := range r.tcpByPort {
		tcpPorts = append(tcpPorts, p)
	}
	udpPorts = make([]uint32, 0, len(r.udpByPort))
	for p := range r.udpByPort {
		udpPorts = append(udpPorts, p)
	}
	return
}
