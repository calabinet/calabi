// Package magicdns is the client-side MagicDNS resolver for Connect: it answers
// A queries for mesh node names (from the live netmap) and forwards everything
// else to an upstream resolver, so pointing the OS at it doesn't break normal
// DNS. Names resolve in both forms: the bare "<node>" and the FQDN
// "<node>.<suffix>" (e.g. node-b.meshnet-1.mesh).
//
// Records are updated live as the netmap changes (SetRecords), so a node that
// joins/leaves appears/disappears from resolution without a restart. The OS
// integration (pointing resolv.conf at this resolver) is platform-specific and
// lives in the mesh datapath, mirroring the tun route config.
package magicdns

import (
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Resolver serves mesh names + forwards the rest upstream. Safe for concurrent
// use; records are swapped under a mutex.
type Resolver struct {
	suffix   string // lowercased, no leading/trailing dot, e.g. "meshnet-1.mesh"
	upstream string // host:port for non-mesh queries; "" = REFUSED
	logger   *slog.Logger

	mu      sync.RWMutex
	records map[string]netip.Addr // key: lowercased fqdn WITH trailing dot
	srv     *dns.Server
}

// New builds a resolver. suffix is the MagicDNS domain (bare names also resolve);
// upstream is the resolver to forward non-mesh queries to (host:port).
func New(suffix, upstream string, logger *slog.Logger) *Resolver {
	return &Resolver{
		suffix:   strings.Trim(strings.ToLower(suffix), "."),
		upstream: upstream,
		logger:   logger,
		records:  map[string]netip.Addr{},
	}
}

// SetRecords rebuilds the name→IP table from (name → overlay) pairs. Each name is
// indexed under both "<name>." and "<name>.<suffix>." so short and FQDN forms
// both resolve.
func (r *Resolver) SetRecords(entries map[string]netip.Addr) {
	recs := make(map[string]netip.Addr, len(entries)*2)
	for name, ip := range entries {
		n := strings.ToLower(strings.TrimSuffix(name, "."))
		if n == "" || !ip.IsValid() {
			continue
		}
		recs[n+"."] = ip
		if r.suffix != "" {
			recs[n+"."+r.suffix+"."] = ip
		}
	}
	r.mu.Lock()
	r.records = recs
	r.mu.Unlock()
}

func (r *Resolver) lookup(fqdn string) (netip.Addr, bool) {
	r.mu.RLock()
	ip, ok := r.records[strings.ToLower(fqdn)]
	r.mu.RUnlock()
	return ip, ok
}

// ServeDNS answers A for known mesh names, returns an empty NOERROR for other
// query types on those names (so we never leak a mesh name upstream), and
// forwards everything else to the upstream resolver.
func (r *Resolver) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 1 {
		q := req.Question[0]
		if ip, ok := r.lookup(q.Name); ok {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Authoritative = true
			if q.Qtype == dns.TypeA && ip.Is4() {
				rr, err := dns.NewRR(q.Name + " 30 IN A " + ip.String())
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
			// A known name with a non-A query (e.g. AAAA) returns NOERROR + no
			// records — a mesh name must never be forwarded upstream.
			_ = w.WriteMsg(m)
			return
		}
	}
	r.forward(w, req)
}

// forward relays a non-mesh query to the upstream resolver. With no upstream it
// answers REFUSED (rather than hanging or leaking).
func (r *Resolver) forward(w dns.ResponseWriter, req *dns.Msg) {
	if r.upstream == "" {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	c := &dns.Client{Net: "udp"}
	resp, _, err := c.Exchange(req, r.upstream)
	if err != nil || resp == nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	_ = w.WriteMsg(resp)
}

// Serve binds a UDP DNS server on addr and serves in the background. Returns once
// the socket is bound (or on bind error). Needs privilege for :53.
func (r *Resolver) Serve(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	srv := &dns.Server{PacketConn: pc, Handler: r}
	r.mu.Lock()
	r.srv = srv
	r.mu.Unlock()
	go func() {
		if err := srv.ActivateAndServe(); err != nil {
			r.logger.Warn("magicdns server stopped", "err", err)
		}
	}()
	r.logger.Info("magicdns listening", "addr", addr, "suffix", r.suffix)
	return nil
}

// Close shuts the server down.
func (r *Resolver) Close() error {
	r.mu.Lock()
	srv := r.srv
	r.mu.Unlock()
	if srv != nil {
		return srv.Shutdown()
	}
	return nil
}
