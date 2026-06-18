// HTTPS visitor listener.
//
// Architecturally identical to the HTTP listener (sniff Host, route by
// domain, OpenProxyConn, replay head bytes, io.Copy) — the difference
// is a TLS-1.2+ terminator wrapping the accept loop. The terminator's
// GetCertificate is wired to certclient, which provides hot-swappable
// per-SNI certificates pulled from cert-svc.
//
// Distinct from sni.go: this listener TERMINATES TLS at the edge (edge
// has and uses the user's cert + key) and ships plaintext HTTP/1.x to
// the client over yamux. sni.go is byte-passthrough — edge never sees
// inside the TLS.
//
// limitations (carried forward from HTTP listener):
//   - HTTP/1.x only over TLS. HTTP/2 ALPN negotiation.
//   - Single Host per connection; pipelined cross-host requests aren't
//     supported (visitor sees the first response and the conn closes).
package listener

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/mesh"
	"github.com/calabi/calabi/apps/calabi-edge/internal/policy"
	"github.com/calabi/calabi/apps/calabi-edge/internal/ratelimit"
	"github.com/calabi/calabi/apps/calabi-edge/internal/router"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// HTTPSOptions configures the listener.
type HTTPSOptions struct {
	Addr     string
	Router   *router.Router
	Observer HTTPObserver // reuse the HTTP observer interface; proxy_type label = "https"
	// GetCertificate is plugged in by main from certclient. Required when
	// Addr is non-empty; if nil the listener panics at startup (better
	// than serving with a missing cert table).
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// MeshResolver / SelfEdgeID enable intra-region peer forwarding on a
	// router miss. nil resolver = mesh disabled.
	MeshResolver OwnerResolver
	SelfEdgeID   int64
	// GlobalLimiter is the process-wide backpressure (Phase B). nil =
	// unlimited. Checked at accept before the TLS handshake completes work.
	GlobalLimiter *ratelimit.GlobalLimiter
}

// HTTPS is the TLS-terminating HTTP listener handle.
type HTTPS struct {
	opts   HTTPSOptions
	logger *slog.Logger

	ln       net.Listener
	stopping atomic.Bool
}

// NewHTTPS builds an unstarted HTTPS listener.
func NewHTTPS(logger *slog.Logger, opts HTTPSOptions) *HTTPS {
	return &HTTPS{
		opts:   opts,
		logger: logger.With("component", "listener.https"),
	}
}

// Run blocks until ctx cancels or Listen fails. Empty Addr is a no-op
// (HTTPS is opt-in via cfg.HTTPS.Addr).
func (h *HTTPS) Run(ctx context.Context) error {
	if h.opts.Addr == "" {
		<-ctx.Done()
		return nil
	}
	if h.opts.GetCertificate == nil {
		return fmt.Errorf("listener.https: GetCertificate is required when Addr=%q", h.opts.Addr)
	}
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: h.opts.GetCertificate,
		// NextProtos: http/1.1 only for now; adds h2.
		NextProtos: []string{"http/1.1"},
	}
	ln, err := tls.Listen("tcp", h.opts.Addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("listen %s: %w", h.opts.Addr, err)
	}
	h.ln = ln
	h.logger.Info("https listener up", "addr", h.opts.Addr)

	go func() {
		<-ctx.Done()
		h.stopping.Store(true)
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if h.stopping.Load() {
				return nil
			}
			h.logger.Warn("accept", "err", err)
			continue
		}
		// Phase B global backpressure: shed before the TLS handshake +
		// goroutine cost.
		rel, shed := globalAdmit(h.opts.GlobalLimiter)
		if shed != "" {
			h.observeRequest(shed)
			_ = conn.Close()
			continue
		}
		go func() {
			defer rel()
			h.handle(conn)
		}()
	}
}

func (h *HTTPS) handle(visitor net.Conn) {
	defer visitor.Close()
	_ = visitor.SetReadDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReaderSize(visitor, 8192)
	head, host, method, path, err := sniffHTTP(br)
	if err != nil {
		h.logger.Debug("sniff", "err", err, "remote", visitor.RemoteAddr())
		h.observeRequest("sniff_failed")
		return
	}
	_ = visitor.SetReadDeadline(time.Time{})

	target, ok := h.opts.Router.LookupHTTP(host)
	if !ok {
		// maybe a same-region peer owns this host — relay to it. The
		// visitor's TLS is already terminated here, so we forward as KindHTTPS
		// and the owner routes it on the same Host-keyed table.
		if relayToPeer(h.logger, h.opts.MeshResolver, h.opts.SelfEdgeID, h.opts.Observer,
			mesh.KindHTTPS, host, path, visitor, br, head) {
			return
		}
		writeStatus(visitor, 502, fmt.Sprintf("no tunnel for host %q", host))
		h.observeRequest("no_tunnel")
		return
	}
	sess, ok := target.Session.(*session.Session)
	if !ok {
		writeStatus(visitor, 500, "internal: routing target type mismatch")
		h.observeRequest("internal_error")
		return
	}

	// Security policy (server-authoritative IP allowlist) — see http.go. TLS
	// is already terminated here, so the source IP is the real visitor's.
	var pol *policy.Policy
	if p := sess.Proxy(target.ProxyID); p != nil {
		pol = p.LoadPolicy()
	}
	if pol != nil {
		if pol.HasIPRules() && !pol.AllowIPString(extractIP(visitor.RemoteAddr())) {
			writeStatus(visitor, 403, "forbidden: source IP not allowed")
			h.observeRequest("ip_denied")
			return
		}
		// Basic auth — see http.go. TLS is already terminated here.
		if pol.HasBasicAuth() && !pol.CheckBasicAuth(headerValue(head, "Authorization")) {
			write401(visitor, basicAuthRealm)
			h.observeRequest("auth_required")
			return
		}
		if pol.HasRateLimit() && !pol.AllowRate() {
			writeStatus(visitor, 429, "rate limit exceeded")
			h.observeRequest("rate_limited")
			return
		}
		// OAuth login wall — see http.go. HTTPS=true so the redirect_uri is https.
		if pol.HasOAuth() {
			if pol.GateOAuth(visitor, path, host, true, headerValue(head, "Cookie"), time.Now()) {
				h.observeRequest("oauth_redirect")
				return
			}
		}
	}

	// Anti-abuse gates (Phase A). HTTPS is TLS-terminated HTTP, so it
	// shares the HTTP new-connection rate bucket; concurrent cap is shared
	// across all listener types for the org.
	if err := sess.AllowHTTPConn(); err != nil {
		writeStatus(visitor, 429, "rate limit exceeded")
		h.observeRequest("rate_limited")
		return
	}
	release, err := sess.AcquireConn()
	if err != nil {
		writeStatus(visitor, 503, "connection limit reached")
		h.observeRequest("conn_capped")
		return
	}
	defer release()

	// Per-day request cap (daily_http_reqs): count request #1 (the sniffed
	// head); subsequent requests are counted by the request-boundary parser
	// wrapping the visitor→stream copy below.
	if err := sess.AllowHTTPReq(); err != nil {
		writeStatus(visitor, 429, "daily request limit exceeded")
		h.observeRequest("daily_req_capped")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := sess.OpenProxyConn(ctx, &proto.NewConnRequest{
		ProxyID:      target.ProxyID,
		VisitorIP:    extractIP(visitor.RemoteAddr()),
		VisitorPort:  uint32(extractPort(visitor.RemoteAddr())),
		OriginalHost: host,
		OriginalPath: path,
	})
	if err != nil {
		h.logger.Info("open upstream", "err", err, "host", host)
		writeStatus(visitor, 502, "upstream unavailable: "+err.Error())
		h.observeRequest("open_upstream_failed")
		return
	}
	defer stream.Close()

	// Request-header rewrite for request #1 (⑥); #2.N via the wrapper below.
	replayHead := head
	if pol.HasRequestHeaders() {
		replayHead = pol.RewriteRequestHead(head)
	}
	if _, err := stream.Write(replayHead); err != nil {
		h.observeRequest("replay_head_failed")
		return
	}
	h.observeRequest("ok")
	h.observeBytes("visitor_to_client", int64(len(replayHead)))
	// per-tunnel byte attribution (see metered.go / http.go).
	inC, outC := proxyMeters(sess, target.ProxyID)
	inC.Add(uint64(len(replayHead)))

	h.logger.Info("proxying https",
		"host", host, "method", method, "path", path,
		"session_id", target.SessionID, "proxy_id", target.ProxyID)

	// Per-session bandwidth limiter.
	lim := sess.Limiter()
	type result struct {
		dir   string
		bytes int64
		err   error
	}
	errCh := make(chan result, 2)
	// Live byte metering — see metered.go and the matching block in http.go
	// for why both halves are wrapped instead of posting totals on close.
	// Wrap the visitor→stream half with the request-boundary counter
	// reqcount.go) so keepalive requests are metered against the per-day cap.
	reqCounter := newRequestCounter(head, sess.AllowHTTPReq)
	var vsrc io.Reader = br
	if pol.HasRequestHeaders() {
		vsrc = wrapHeaderRewrite(br, pol, head)
	}
	go func() {
		n, e := io.Copy(newBytesMeter(lim.Writer(stream), inC), reqCounter.wrap(vsrc))
		errCh <- result{"visitor->stream", n, e}
	}()
	go func() {
		n, e := io.Copy(newBytesMeter(lim.Writer(visitor), outC), stream)
		errCh <- result{"stream->visitor", n, e}
	}()
	first := <-errCh
	switch first.dir {
	case "visitor->stream":
		h.observeBytes("visitor_to_client", first.bytes)
	case "stream->visitor":
		h.observeBytes("client_to_visitor", first.bytes)
	}
	h.logger.Debug("https direction finished",
		"dir", first.dir, "bytes", first.bytes, "err", first.err,
		"proxy_id", target.ProxyID)
}

func (h *HTTPS) observeRequest(outcome string) {
	if h.opts.Observer != nil {
		h.opts.Observer.OnVisitorRequest("https", outcome)
	}
}

func (h *HTTPS) observeBytes(direction string, n int64) {
	if h.opts.Observer != nil {
		h.opts.Observer.OnBytesTransferred("https", direction, n)
	}
}
