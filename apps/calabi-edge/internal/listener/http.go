package listener

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/mesh"
	"github.com/calabi/calabi/apps/calabi-edge/internal/policy"
	"github.com/calabi/calabi/apps/calabi-edge/internal/ratelimit"
	"github.com/calabi/calabi/apps/calabi-edge/internal/router"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// HTTPObserver is the visitor-facing metrics surface for the HTTP listener.
type HTTPObserver interface {
	OnVisitorRequest(proxyType, outcome string)
	OnBytesTransferred(proxyType, direction string, n int64)
}

// HTTPOptions configures the visitor-facing HTTP listener.
type HTTPOptions struct {
	Addr     string
	Router   *router.Router
	Observer HTTPObserver // may be nil
	// MeshResolver, when non-nil, enables intra-region peer forwarding: on a router miss the listener asks whether a same-region peer
	// owns the host and, if so, relays the visitor connection there instead
	// of returning 502. nil = mesh disabled (behaviour).
	MeshResolver OwnerResolver
	// SelfEdgeID is this edge's numeric id, stamped into the forward frame
	// as OriginEdge (logging / anti-loop breadcrumb).
	SelfEdgeID int64
	// GlobalLimiter is the process-wide backpressure (Phase B). nil =
	// unlimited (admits everything). Checked at accept before sniff/route.
	GlobalLimiter *ratelimit.GlobalLimiter
	// ACMEChallengeResolver, when non-nil, answers ACME http-01 validation
	// probes (/.well-known/acme-challenge/<token>) served by this edge on
	// behalf of cert-svc's user-self-service issuance. It maps a token to
	// its keyAuth. nil (self-hosted / no cert-svc) disables interception, so
	// such a path falls through to normal host routing. Checked BEFORE host
	// routing and BEFORE any auth / rate-limit gate — the probe is anonymous.
	ACMEChallengeResolver func(token string) (keyAuth string, ok bool)
}

// HTTP accepts incoming HTTP/1.x connections, sniffs the Host header, and
// proxies the raw byte stream to the matching client over a yamux data
// stream.
//
// Limitations:
//   - HTTP/1.x only; HTTP/2 cleartext is not negotiated.
//   - Single-Host per connection: if a visitor pipelines requests for
//     different Hosts on the same conn, only the first is honored.
//   - HTTPS (TLS termination) (ACME + cert-svc).
type HTTP struct {
	opts   HTTPOptions
	logger *slog.Logger

	ln       net.Listener
	stopping atomic.Bool
}

// NewHTTP builds an unstarted HTTP listener.
func NewHTTP(logger *slog.Logger, opts HTTPOptions) *HTTP {
	return &HTTP{
		opts:   opts,
		logger: logger.With("component", "listener.http"),
	}
}

// Run blocks until ctx cancels or Listen fails.
func (h *HTTP) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", h.opts.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", h.opts.Addr, err)
	}
	h.ln = ln
	h.logger.Info("http listener up", "addr", h.opts.Addr)

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
		// Phase B global backpressure: shed before spending a goroutine.
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

func (h *HTTP) handle(visitor net.Conn) {
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

	// ACME http-01 interception: a Let's Encrypt validator probing
	// /.well-known/acme-challenge/<token> must be answered by THIS edge
	// (the token lives in cert-svc and was broadcast to us), not routed to
	// a tunnel. Handled before host routing and before any auth/rate gate
	// because the probe is anonymous and must never be challenged or shed.
	if h.opts.ACMEChallengeResolver != nil {
		if token, ok := acmeChallengeToken(path); ok {
			if keyAuth, found := h.opts.ACMEChallengeResolver(token); found {
				writeACMEChallenge(visitor, keyAuth)
				h.observeRequest("acme_challenge")
				h.logger.Info("served acme http-01 challenge", "host", host, "token", token)
			} else {
				writeStatus(visitor, 404, "acme challenge token not found")
				h.observeRequest("acme_challenge_miss")
			}
			return
		}
	}

	target, ok := h.opts.Router.LookupHTTP(host)
	if !ok {
		// maybe a same-region peer owns this host — relay to it.
		if relayToPeer(h.logger, h.opts.MeshResolver, h.opts.SelfEdgeID, h.opts.Observer,
			mesh.KindHTTP, host, path, visitor, br, head) {
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

	// Security policy (server-authoritative IP allowlist): reject visitors
	// whose source IP the tunnel owner hasn't permitted. The policy is parsed
	// from the tunnel row's config_json at registration — NOT from the daemon
	// — so a tampered client can't drop it. nil/empty policy (the common case)
	// short-circuits via HasIPRules and adds no per-request cost.
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
		// Basic auth: challenge if the request lacks valid credentials.
		// Checked at connection establishment (request 1); the browser
		// re-sends the header on every request, so the protected experience
		// holds across the keep-alive connection.
		if pol.HasBasicAuth() && !pol.CheckBasicAuth(headerValue(head, "Authorization")) {
			write401(visitor, basicAuthRealm)
			h.observeRequest("auth_required")
			return
		}
		// Per-tunnel connection-rate cap.
		if pol.HasRateLimit() && !pol.AllowRate() {
			writeStatus(visitor, 429, "rate limit exceeded")
			h.observeRequest("rate_limited")
			return
		}
		// OAuth login wall: bounce unauthenticated visitors to the IdP, handle
		// the callback, gate by allowed email/domain. Request-1 / cookie model
		// (like Basic auth). Handled = the edge already wrote a redirect/error,
		// so don't open the upstream.
		if pol.HasOAuth() {
			if pol.GateOAuth(visitor, path, host, false, headerValue(head, "Cookie"), time.Now()) {
				h.observeRequest("oauth_redirect")
				return
			}
		}
	}

	// Anti-abuse gates (Phase A): new-connection rate first (cheap, sheds
	// floods before allocating), then the concurrent-connection cap.
	// Unguarded sessions (dev / no quota-svc) pass straight through.
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
	// head). Subsequent requests on this keepalive connection are counted by
	// the request-boundary parser wrapping the visitor→stream copy below.
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
		h.logger.Info("open upstream",
			"err", err, "host", host, "session_id", target.SessionID)
		writeStatus(visitor, 502, "upstream unavailable: "+err.Error())
		h.observeRequest("open_upstream_failed")
		return
	}
	defer stream.Close()

	// Replay the bytes we consumed during sniffing. Every request head gets the
	// reverse-proxy forwarding headers (real visitor IP, scheme, host) stamped
	// on so the backend sees the real client; a per-tunnel header rewrite, if
	// configured, runs AFTER so an operator can still override. Requests #2.N on
	// this keep-alive connection are transformed by the wrap below.
	visitorIP := extractIP(visitor.RemoteAddr())
	headXform := func(h []byte) []byte {
		h = injectForwardHeaders(h, visitorIP, host, false)
		if pol.HasRequestHeaders() {
			h = pol.RewriteRequestHead(h)
		}
		return h
	}
	replayHead := headXform(head)
	if _, err := stream.Write(replayHead); err != nil {
		h.observeRequest("replay_head_failed")
		return
	}
	h.observeRequest("ok")
	// Count the request-line + headers we already wrote upstream.
	h.observeBytes("visitor_to_client", int64(len(replayHead)))
	// attribute bytes to this tunnel's per-proxy counters so the
	// usage reporter can break usage down by tunnel_id.
	inC, outC := proxyMeters(sess, target.ProxyID)
	inC.Add(uint64(len(replayHead)))

	h.logger.Info("proxying",
		"host", host, "method", method, "path", path,
		"session_id", target.SessionID, "proxy_id", target.ProxyID)

	// Pipe bytes both ways. The first side to error / EOF unblocks us.
	// Both directions go through the session's per-customer rate
	// limiter; zero-rate sessions pass through unchanged.
	lim := sess.Limiter()
	type result struct {
		dir   string
		bytes int64
		err   error
	}
	errCh := make(chan result, 2)
	// Wrap both halves in bytesMeter so sess.BytesIn / sess.BytesOut
	// grow in lock-step with the I/O, not only when one side finishes
	// (see metered.go for why). The post-Copy switch below stays as a
	// metrics breadcrumb but no longer feeds the usage reporter.
	// Wrap the visitor→stream half with the request-boundary counter so each
	// subsequent request on a keepalive connection is metered against the
	// per-day cap. Transparent: bytes are forwarded verbatim; on cap-hit the
	// reader surfaces an error that unwinds the copy and closes the conn.
	reqCounter := newRequestCounter(head, sess.AllowHTTPReq)
	vsrc := wrapHeadTransform(br, headXform, head)
	go func() {
		n, e := io.Copy(newBytesMeter(lim.Writer(stream), inC), reqCounter.wrap(vsrc))
		errCh <- result{"visitor->stream", n, e}
	}()
	go func() {
		n, e := io.Copy(newBytesMeter(lim.Writer(visitor), outC), stream)
		errCh <- result{"stream->visitor", n, e}
	}()
	first := <-errCh
	// Observability counters: still report first-direction-only to keep
	// the existing prom metric shape stable. The session BytesIn/Out
	// counters that drive usage / metering are now updated live above.
	switch first.dir {
	case "visitor->stream":
		h.observeBytes("visitor_to_client", first.bytes)
	case "stream->visitor":
		h.observeBytes("client_to_visitor", first.bytes)
	}
	h.logger.Info("proxy direction finished",
		"dir", first.dir, "bytes", first.bytes, "err", first.err,
		"proxy_id", target.ProxyID)
}

func (h *HTTP) observeRequest(outcome string) {
	if h.opts.Observer != nil {
		h.opts.Observer.OnVisitorRequest("http", outcome)
	}
}

func (h *HTTP) observeBytes(direction string, n int64) {
	if h.opts.Observer != nil {
		h.opts.Observer.OnBytesTransferred("http", direction, n)
	}
}

// sniffHTTP reads exactly the HTTP request head (up to and including the
// blank-line terminator) from br line by line.
//
// We read line-by-line (rather than peeking 8KB) because peek blocks until
// the buffer is full OR a read error fires -- a short request followed by
// the client waiting for a response would stall here for the full read
// deadline. ReadSlice returns as soon as one line is available.
//
// The returned head bytes MUST be replayed verbatim onto the upstream
// connection so the local server sees the original request.
func sniffHTTP(br *bufio.Reader) (head []byte, host, method, path string, err error) {
	const maxHead = 16 * 1024
	var buf bytes.Buffer

	for {
		if buf.Len() > maxHead {
			return nil, "", "", "", errors.New("HTTP head exceeds 16 KiB")
		}
		line, rerr := br.ReadSlice('\n')
		buf.Write(line)
		if rerr != nil {
			if errors.Is(rerr, bufio.ErrBufferFull) {
				return nil, "", "", "", errors.New("HTTP header line too long")
			}
			return nil, "", "", "", rerr
		}
		if string(line) == "\r\n" || string(line) == "\n" {
			break // end of headers
		}
	}

	head = buf.Bytes()

	// Parse request line and Host header.
	headers := bytes.TrimRight(head, "\r\n")
	lines := bytes.Split(headers, []byte("\r\n"))
	if len(lines) < 1 || len(lines[0]) == 0 {
		return nil, "", "", "", errors.New("empty request line")
	}
	parts := strings.SplitN(string(lines[0]), " ", 3)
	if len(parts) < 2 {
		return nil, "", "", "", errors.New("malformed request line")
	}
	method, path = parts[0], parts[1]

	for _, line := range lines[1:] {
		if len(line) >= 5 && bytes.EqualFold(line[:5], []byte("host:")) {
			host = strings.TrimSpace(string(line[5:]))
			break
		}
	}
	if host == "" {
		return nil, "", "", "", errors.New("missing Host header")
	}
	return head, host, method, path, nil
}

// acmeChallengePrefix is the well-known path ACME http-01 validators hit.
const acmeChallengePrefix = "/.well-known/acme-challenge/"

// acmeChallengeToken returns the token from an ACME http-01 request path,
// or ok=false if the path isn't a challenge request. The token is the
// single path segment after the prefix; any query string is stripped and
// a token containing a further '/' is rejected (defends the lookup key).
func acmeChallengeToken(path string) (string, bool) {
	if !strings.HasPrefix(path, acmeChallengePrefix) {
		return "", false
	}
	tok := path[len(acmeChallengePrefix):]
	if i := strings.IndexByte(tok, '?'); i >= 0 {
		tok = tok[:i]
	}
	if tok == "" || strings.Contains(tok, "/") {
		return "", false
	}
	return tok, true
}

// writeACMEChallenge replies with the keyAuth as text/plain — the exact
// body Let's Encrypt expects at the challenge URL.
func writeACMEChallenge(w io.Writer, keyAuth string) {
	msg := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n%s",
		len(keyAuth), keyAuth,
	)
	_, _ = io.WriteString(w, msg)
}

func writeStatus(w io.Writer, code int, body string) {
	msg := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n%s",
		code, statusText(code), len(body), body,
	)
	_, _ = io.WriteString(w, msg)
}

// basicAuthRealm is the WWW-Authenticate realm shown in the browser's
// credential prompt. Kept stable so browsers reuse cached credentials.
const basicAuthRealm = "Restricted"

// headerValue returns the value of the named header from a sniffed HTTP head
// (case-insensitive), or "" if absent. Mirrors sniffHTTP's Host scan: head is
// the raw request line + header lines up to (and including) the blank line.
func headerValue(head []byte, name string) string {
	lines := bytes.Split(bytes.TrimRight(head, "\r\n"), []byte("\r\n"))
	if len(lines) < 2 {
		return ""
	}
	prefix := append([]byte(name), ':')
	for _, line := range lines[1:] { // skip the request line
		if len(line) >= len(prefix) && bytes.EqualFold(line[:len(prefix)], prefix) {
			return strings.TrimSpace(string(line[len(prefix):]))
		}
	}
	return ""
}

// write401 sends an HTTP Basic-auth challenge so the browser prompts for
// credentials (Connection: close so the next attempt is a fresh request the
// edge re-checks).
func write401(w io.Writer, realm string) {
	body := "401 Unauthorized\n"
	msg := fmt.Sprintf(
		"HTTP/1.1 401 Unauthorized\r\n"+
			"WWW-Authenticate: Basic realm=%q\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n%s",
		realm, len(body), body,
	)
	_, _ = io.WriteString(w, msg)
}

func statusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return "Status"
	}
}

func extractIP(a net.Addr) string {
	if tcp, ok := a.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

func extractPort(a net.Addr) int {
	if tcp, ok := a.(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}
