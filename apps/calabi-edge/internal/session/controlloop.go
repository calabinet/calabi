package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/policy"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// ProxyRegistrar abstracts the router + listener wiring so the session
// package doesn't depend on net/listener internals.
//
// RegisterTCP / RegisterUDP atomically register the route AND open the
// per-proxy socket on the assigned port. The returned io.Closer is
// stored on Proxy.Listener; closing it stops the accept loop. For HTTP
// and SNI proxies there's nothing to listen on per-proxy -- the global
// HTTP / SNI listeners already route by Host / server_name respectively.
type ProxyRegistrar interface {
	RegisterHTTP(domain string, sess *Session, proxyID string) error
	RegisterSNI(domain string, sess *Session, proxyID string) error
	RegisterTCP(remotePort uint32, sess *Session, proxyID string) (io.Closer, error)
	RegisterUDP(remotePort uint32, sess *Session, proxyID string) (io.Closer, error)
	UnregisterByProxyID(proxyID string)
}

// DomainAllocator hands out auto-assigned subdomains for NEW_PROXY when
// the client did not specify one.
type DomainAllocator interface {
	Allocate(kind proto.ProxyKind) string
}

// PortAllocator hands out remote ports for TCP/UDP proxies.
type PortAllocator interface {
	Allocate() (uint32, bool)
	Release(port uint32)
}

// ProxyPersister optionally records proxy lifecycle to an external
// store (tunnel-svc).
//
// OnProxyOpened is called after the proxy is registered locally. The
// returned tunnelID (if non-zero) is stamped onto Proxy.TunnelID so the
// matching OnProxyClosed call later carries it.
//
// the second return is non-nil ONLY when the persister
// reached a definitive failure that means the proxy cannot exist (e.g.,
// a (edge_node_id, remote_port) collision detected by tunnel-svc's
// unique check). The caller MUST roll back the local registration in
// that case — the proxy must not serve traffic and the port must be
// released so the next NEW_PROXY can re-use it. A nil error coupled
// with a zero tunnel-id is still "soft failure / best-effort" (e.g.,
// transport blip): the proxy stays live locally but isn't surfaced to
// the SPA list until persistence catches up.
type ProxyPersister interface {
	OnProxyOpened(sess *Session, p *Proxy) (int64, error)
	OnProxyClosed(sess *Session, p *Proxy, reason string)
}

// Loop runs the per-session control loop. It blocks until the session ends
// or an unrecoverable error occurs.
//
// Frames it handles:
//   - PING            -> reply PONG
//   - NEW_PROXY       -> RegisterHTTP / RegisterTCP + NEW_PROXY_RESP
//   - CLOSE_PROXY     -> UnregisterByProxyID
//   - CONN_ACK        -> HandleConnAck (matches OpenProxyConn waiters)
//   - METRICS_REPORT  -> log only
//   - anything else   -> log + ignore (forward-compat)
func (s *Session) Loop(ctx context.Context, registrar ProxyRegistrar, domains DomainAllocator, ports PortAllocator, obs SessionObserver, persister ProxyPersister) {
	defer func() {
		// Tear down all proxies belonging to this session when the loop
		// exits. This keeps the router clean even after abrupt client drops.
		for _, p := range s.Proxies() {
			if p.Listener != nil {
				_ = p.Listener.Close()
			}
			registrar.UnregisterByProxyID(p.ID)
			if p.RemotePort != 0 && ports != nil {
				ports.Release(p.RemotePort)
			}
			if obs != nil {
				obs.OnProxyClosed(string(p.Type), "session_end")
			}
			if persister != nil {
				persister.OnProxyClosed(s, p, "session_end")
			}
		}
		_ = s.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closedCh:
			return
		default:
		}

		f, err := s.ReadFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Info("control read error", "err", err)
			}
			return
		}

		switch f.Type {
		case proto.FramePing:
			var ping proto.Ping
			_ = proto.Unmarshal(f.Payload, &ping)
			now := time.Now().UnixNano()
			_ = s.SendControl(proto.FramePong, &proto.Pong{
				ClientSendNs: ping.ClientSendNs,
				ServerRecvNs: now,
				ServerSendNs: now,
			})

		case proto.FrameNewProxy:
			s.handleNewProxy(f, registrar, domains, ports, obs, persister)

		case proto.FrameCloseProxy:
			var req proto.CloseProxyRequest
			if err := proto.Unmarshal(f.Payload, &req); err != nil {
				continue
			}
			s.handleCloseProxy(&req, registrar, ports, obs, persister)

		case proto.FrameConnAck:
			var ack proto.ConnAck
			if err := proto.Unmarshal(f.Payload, &ack); err != nil {
				continue
			}
			s.HandleConnAck(&ack)

		case proto.FrameMetricsReport:
			s.logger.Debug("metrics report from client", "payload_size", len(f.Payload))

		default:
			s.logger.Debug("unhandled frame", "type", f.Type.String())
		}
	}
}

// isManagedSubdomain reports whether domain falls under the edge's managed base
// domain, as known by the DomainAllocator (the allocator hands out
// "<seq>.<base>" names, so it is the authority on the active base). The base is
// read via an optional Base() method so the session package needn't depend on
// the concrete allocator type; an allocator that doesn't expose it (e.g. a test
// stub) or an empty base makes this return false — i.e. the caller treats the
// domain as a custom domain rather than a managed subdomain. Used by
// handleNewProxy to refuse client-chosen platform subdomains on the raw
// NEW_PROXY path.
func isManagedSubdomain(domains DomainAllocator, domain string) bool {
	baser, ok := domains.(interface{ Base() string })
	if !ok {
		return false
	}
	base := strings.ToLower(strings.TrimSpace(baser.Base()))
	if base == "" {
		return false
	}
	d := strings.ToLower(strings.TrimSpace(domain))
	return d == base || strings.HasSuffix(d, "."+base)
}

func (s *Session) handleNewProxy(f proto.Frame, registrar ProxyRegistrar, domains DomainAllocator, ports PortAllocator, obs SessionObserver, persister ProxyPersister) {
	var req proto.NewProxyRequest
	if err := proto.Unmarshal(f.Payload, &req); err != nil {
		_ = s.SendControl(proto.FrameNewProxyResp, &proto.NewProxyResponse{
			Error: proto.NewError(proto.CodeMalformedPayload, "calabi.err.malformed_payload", err.Error()),
		})
		return
	}

	resp := &proto.NewProxyResponse{}
	p := &Proxy{
		ID:            ProxyID(),
		Type:          req.Type,
		LocalAddr:     req.LocalAddr,
		Name:          req.Name,
		ClaimTunnelID: req.ClaimTunnelID,
	}

	switch req.Type {
	case proto.ProxyKindHTTP, proto.ProxyKindHTTPS:
		domain := req.Domain
		var regErr error
		if domain == "" {
			// Auto-allocate. The allocator's seq might be behind the
			// router's actual occupancy (file-backed seq out of sync,
			// or a parallel NEW_PROXY just claimed our number). Retry
			// up to N times — each Allocate advances seq, so a
			// genuine duplicate burns one number and we move on.
			const maxAlloc = 64
			for attempt := 0; attempt < maxAlloc; attempt++ {
				cand := domains.Allocate(req.Type)
				if err := registrar.RegisterHTTP(cand, s, p.ID); err == nil {
					domain = cand
					regErr = nil
					break
				} else {
					regErr = err
				}
			}
			if domain == "" {
				resp.Error = proto.NewError(proto.CodeProxyDuplicate,
					"calabi.err.proxy.duplicate",
					fmt.Sprintf("auto-allocate exhausted after %d attempts: %v", maxAlloc, regErr))
				_ = s.SendControl(proto.FrameNewProxyResp, resp)
				return
			}
		} else {
			// Platform managed-subdomain gate. Hand-picking a subdomain under
			// the edge's managed base domain is a paid feature, gated in
			// bff-console on the console/daemon path. That path reaches us as a
			// CLAIM (ClaimTunnelID != 0) and is exempt; a raw `calabi http
			// --domain <name>.<base>` carries no claim, so without this gate any
			// plan could grab a vanity subdomain straight from the data plane
			// (the reserved_subdomain quota only caps the COUNT — 1 for free —
			// not the NAMING). Refuse it and point the user at the console.
			// Exempt: custom domains (NOT under the managed base) fall through to
			// tunnel-svc verification; auto-allocation (domain=="") never reaches
			// here; standalone edges (TrustClientPolicy) have no plan concept.
			if !s.TrustClientPolicy && req.ClaimTunnelID == 0 && isManagedSubdomain(domains, domain) {
				resp.Error = proto.NewError(proto.CodeForbidden,
					"calabi.err.proxy.subdomain_requires_console",
					"choosing a platform subdomain is a paid feature configured in the web console; omit --domain for an auto-assigned subdomain")
				_ = s.SendControl(proto.FrameNewProxyResp, resp)
				return
			}
			// Explicit domain from client. Single attempt — we cannot
			// silently substitute a different name when the client
			// asked for one specifically.
			if err := registrar.RegisterHTTP(domain, s, p.ID); err != nil {
				resp.Error = proto.NewError(proto.CodeProxyDuplicate,
					"calabi.err.proxy.duplicate", err.Error())
				_ = s.SendControl(proto.FrameNewProxyResp, resp)
				return
			}
		}
		p.Domain = domain
		resp.ProxyID = p.ID
		resp.Domain = domain

	case proto.ProxyKindSNI:
		// SNI passthrough: the client must supply the domain (we don't
		// auto-allocate because the upstream cert is bound to a
		// specific name). The global SNI listener routes by ClientHello.
		if req.Domain == "" {
			resp.Error = proto.NewError(proto.CodeMalformedPayload,
				"calabi.err.proxy.sni_domain_required",
				"sni proxy requires --domain")
			_ = s.SendControl(proto.FrameNewProxyResp, resp)
			return
		}
		p.Domain = req.Domain
		if err := registrar.RegisterSNI(req.Domain, s, p.ID); err != nil {
			resp.Error = proto.NewError(proto.CodeProxyDuplicate,
				"calabi.err.proxy.duplicate", err.Error())
			_ = s.SendControl(proto.FrameNewProxyResp, resp)
			return
		}
		resp.ProxyID = p.ID
		resp.Domain = req.Domain

	case proto.ProxyKindTCP, proto.ProxyKindUDP:
		port := req.RemotePort
		fromPool := false
		if port == 0 {
			alloc, ok := ports.Allocate()
			if !ok {
				// Port pool exhausted: refuse gracefully (the client gets a
				// CodePortOutOfRange error frame). Log it so the WARN
				// correlates with the calabi_edge_port_pool_in_use metric
				// when an edge runs out of TCP/UDP ports.
				s.logger.Warn("edge port pool exhausted; refusing TCP/UDP proxy",
					"proxy_id", p.ID, "type", string(req.Type))
				resp.Error = proto.NewError(proto.CodePortOutOfRange,
					"calabi.err.port.unavailable", "no free remote port")
				_ = s.SendControl(proto.FrameNewProxyResp, resp)
				return
			}
			port = alloc
			fromPool = true
		}
		p.RemotePort = port

		var (
			listener io.Closer
			err      error
		)
		if req.Type == proto.ProxyKindTCP {
			listener, err = registrar.RegisterTCP(port, s, p.ID)
		} else {
			listener, err = registrar.RegisterUDP(port, s, p.ID)
		}
		if err != nil {
			if fromPool {
				ports.Release(port)
			}
			resp.Error = proto.NewError(proto.CodeProxyDuplicate,
				"calabi.err.proxy.duplicate", err.Error())
			_ = s.SendControl(proto.FrameNewProxyResp, resp)
			return
		}
		p.Listener = listener
		resp.ProxyID = p.ID
		resp.RemotePort = port

	default:
		resp.Error = proto.NewError(proto.CodeForbidden,
			"calabi.err.proxy.type_not_supported",
			fmt.Sprintf("proxy type %q not supported", req.Type))
		_ = s.SendControl(proto.FrameNewProxyResp, resp)
		return
	}

	if !s.RegisterProxy(p) {
		registrar.UnregisterByProxyID(p.ID)
		resp.Error = proto.NewError(proto.CodeProxyDuplicate, "calabi.err.proxy.duplicate", "id collision")
		_ = s.SendControl(proto.FrameNewProxyResp, resp)
		return
	}

	s.logger.Info("proxy registered",
		"proxy_id", p.ID,
		"type", string(p.Type),
		"domain", p.Domain,
		"remote_port", p.RemotePort,
		"local_addr", p.LocalAddr,
	)
	if obs != nil {
		obs.OnProxyOpened(string(p.Type))
	}
	if persister != nil {
		tid, perr := persister.OnProxyOpened(s, p)
		if perr != nil {
			// hard-failure rollback. Persister hit a definitive
			// "this proxy cannot exist" error — most commonly the
			// (edge_node_id, remote_port) unique check in tunnel-svc
			// caught a collision with another live row. We MUST undo
			// the local registration so the port becomes re-allocatable
			// and traffic doesn't land on a proxy we've already
			// repudiated server-side. Then surface the error in
			// NEW_PROXY_RESP so the daemon shows the user a clear
			// "port in use" rather than silently failing.
			if p.Listener != nil {
				_ = p.Listener.Close()
			}
			registrar.UnregisterByProxyID(p.ID)
			if p.RemotePort != 0 && ports != nil {
				ports.Release(p.RemotePort)
			}
			s.UnregisterProxy(p.ID)
			if obs != nil {
				obs.OnProxyClosed(string(p.Type), "persist_failed")
			}
			s.logger.Warn("proxy persist failed; rolled back local registration",
				"proxy_id", p.ID,
				"type", string(p.Type),
				"remote_port", p.RemotePort,
				"err", perr,
			)
			respErr := &proto.NewProxyResponse{
				Error: proto.NewError(proto.CodeProxyDuplicate,
					"calabi.err.proxy.persist_failed", perr.Error()),
			}
			_ = s.SendControl(proto.FrameNewProxyResp, respErr)
			return
		}
		p.TunnelID = tid
	}

	// Standalone (self-hosted / open-source) edge: apply the per-proxy security
	// policy the client supplied in NEW_PROXY. Managed edges keep
	// TrustClientPolicy=false and skip this entirely — there, security is
	// server-authoritative (applied by the persister from the control plane's
	// config_json), so a tampered client can't self-grant. Fail-open: a
	// malformed blob logs and leaves the proxy unpolicied (never blackholes a
	// tunnel).
	if s.TrustClientPolicy && req.Options != nil && strings.TrimSpace(req.Options.SecurityConfigJSON) != "" {
		if pol, err := policy.Parse(req.Options.SecurityConfigJSON); err != nil {
			s.logger.Warn("standalone: ignoring malformed client security policy",
				"proxy_id", p.ID, "err", err)
		} else if pol != nil {
			p.SetPolicy(pol)
			s.logger.Info("standalone: applied client-supplied security policy",
				"proxy_id", p.ID,
				"has_ip_rules", pol.HasIPRules(),
				"has_basic_auth", pol.HasBasicAuth(),
				"has_rate_limit", pol.HasRateLimit(),
				"has_request_headers", pol.HasRequestHeaders(),
				"has_oauth", pol.HasOAuth())
		}
	}

	_ = s.SendControl(proto.FrameNewProxyResp, resp)
}

func (s *Session) handleCloseProxy(req *proto.CloseProxyRequest, registrar ProxyRegistrar, ports PortAllocator, obs SessionObserver, persister ProxyPersister) {
	p := s.Proxy(req.ProxyID)
	if p == nil {
		return
	}
	if p.Listener != nil {
		_ = p.Listener.Close()
	}
	registrar.UnregisterByProxyID(p.ID)
	if p.RemotePort != 0 && ports != nil {
		ports.Release(p.RemotePort)
	}
	s.mu.Lock()
	delete(s.proxies, p.ID)
	s.mu.Unlock()
	if obs != nil {
		obs.OnProxyClosed(string(p.Type), "client_close")
	}
	if persister != nil {
		persister.OnProxyClosed(s, p, "client_close")
	}
	s.logger.Info("proxy closed", "proxy_id", p.ID, "reason", req.Reason)
}
