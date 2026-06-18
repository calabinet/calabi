// TLS-SNI passthrough listener.
//
// Accepts TLS connections on a dedicated port (default :8443; configurable
// via cfg.SNI.Addr). For each incoming conn we:
//
//  1. Peek the first ~4 KiB into a buffer (200 ms ReadDeadline, generous
//     for typical ClientHellos that fit in one or two TCP segments).
//  2. Parse just enough of the ClientHello to extract the SNI server_name
//     extension. We do NOT do a TLS handshake — the bytes flow through
//     untouched, the client's local TLS terminator does the cert work.
//  3. Router lookup by SNI host → session + proxy_id.
//  4. Open a yamux stream toward the client, replay the buffered bytes,
//     io.Copy in both directions.
//
// On parse failure we close the connection silently (no point telling a
// non-TLS scanner anything). On route miss we close too — there's nothing
// useful we can return without faking a TLS alert.
//
// Limits:
//   - max ClientHello peek 4 KiB (matches go stdlib's maxHandshake/16
//     and is well above real-world ClientHellos)
//   - 200 ms peek deadline; slower handshakes get closed
package listener

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/mesh"
	"github.com/calabi/calabi/apps/calabi-edge/internal/ratelimit"
	"github.com/calabi/calabi/apps/calabi-edge/internal/router"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
	proto "github.com/calabi/calabi/pkg/protocol"
)

const (
	sniPeekBuf      = 4 * 1024
	sniPeekDeadline = 200 * time.Millisecond
)

// SNIObserver is the visitor-facing metrics surface for the SNI listener.
type SNIObserver interface {
	OnVisitorRequest(proxyType, outcome string)
	OnBytesTransferred(proxyType, direction string, n int64)
}

// SNIOptions configures the SNI passthrough listener.
type SNIOptions struct {
	Addr     string
	Router   *router.Router
	Observer SNIObserver
	// MeshResolver / SelfEdgeID enable intra-region peer forwarding on a
	// router miss. nil resolver = mesh disabled.
	MeshResolver OwnerResolver
	SelfEdgeID   int64
	// GlobalLimiter is the process-wide backpressure (Phase B). nil =
	// unlimited. Checked at accept before the ClientHello peek + route.
	GlobalLimiter *ratelimit.GlobalLimiter
}

// SNI is the listener handle.
type SNI struct {
	opts   SNIOptions
	logger *slog.Logger

	ln       net.Listener
	stopping atomic.Bool
}

// NewSNI builds an unstarted SNI listener. Returns nil if opts.Addr is
// empty — SNI is opt-in via config; caller drops the nil into the
// listener goroutine list which short-circuits on nil.
func NewSNI(logger *slog.Logger, opts SNIOptions) *SNI {
	return &SNI{
		opts:   opts,
		logger: logger.With("component", "listener.sni"),
	}
}

// Run blocks until ctx cancels or Listen fails.
func (s *SNI) Run(ctx context.Context) error {
	if s.opts.Addr == "" {
		// No-op disabled listener. Block until ctx done so the
		// errgroup-style caller doesn't trip on a nil return.
		<-ctx.Done()
		return nil
	}
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.opts.Addr, err)
	}
	s.ln = ln
	s.logger.Info("sni listener up", "addr", s.opts.Addr)

	go func() {
		<-ctx.Done()
		s.stopping.Store(true)
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.stopping.Load() {
				return nil
			}
			s.logger.Warn("accept", "err", err)
			continue
		}
		// Phase B global backpressure: shed before the peek + route work.
		rel, shed := globalAdmit(s.opts.GlobalLimiter)
		if shed != "" {
			s.observeRequest(shed)
			_ = conn.Close()
			continue
		}
		go func() {
			defer rel()
			s.handle(conn)
		}()
	}
}

func (s *SNI) handle(visitor net.Conn) {
	defer visitor.Close()
	_ = visitor.SetReadDeadline(time.Now().Add(sniPeekDeadline))

	br := bufio.NewReaderSize(visitor, sniPeekBuf)
	head, sniHost, err := peekSNI(br)
	if err != nil {
		s.logger.Debug("sni peek",
			"err", err, "remote", visitor.RemoteAddr())
		s.observeRequest("peek_failed")
		return
	}
	_ = visitor.SetReadDeadline(time.Time{})

	target, ok := s.opts.Router.LookupSNI(sniHost)
	if !ok {
		// maybe a same-region peer owns this SNI host — relay the raw
		// TLS stream there (passthrough; the owner does not terminate TLS).
		if relayToPeer(s.logger, s.opts.MeshResolver, s.opts.SelfEdgeID, s.opts.Observer,
			mesh.KindSNI, sniHost, "", visitor, br, head) {
			return
		}
		s.observeRequest("no_tunnel")
		return
	}
	sess, ok := target.Session.(*session.Session)
	if !ok {
		s.observeRequest("internal_error")
		return
	}

	// Security policy (server-authoritative IP allowlist). SNI is passthrough
	// — no plaintext channel to answer on, so a denied source is closed
	// silently (deferred visitor.Close on return). Source IP is available
	// pre-TLS from RemoteAddr.
	if p := sess.Proxy(target.ProxyID); p != nil {
		if pol := p.LoadPolicy(); pol != nil {
			if pol.HasIPRules() && !pol.AllowIPString(extractIP(visitor.RemoteAddr())) {
				s.observeRequest("ip_denied")
				return
			}
			if pol.HasRateLimit() && !pol.AllowRate() {
				s.observeRequest("rate_limited")
				return
			}
		}
	}

	// Anti-abuse gates (Phase A). SNI is TLS passthrough (raw TCP/TLS),
	// so it shares the TCP new-connection rate bucket. No plaintext
	// channel to the visitor here — over-limit connections are closed
	// silently (the deferred visitor.Close handles it on return).
	if err := sess.AllowTCPConn(); err != nil {
		s.observeRequest("rate_limited")
		return
	}
	// Per-day connection cap (daily_tcp_conns). Only free is finite today.
	if err := sess.AllowTCPConnDaily(); err != nil {
		s.observeRequest("daily_capped")
		return
	}
	release, err := sess.AcquireConn()
	if err != nil {
		s.observeRequest("conn_capped")
		return
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := sess.OpenProxyConn(ctx, &proto.NewConnRequest{
		ProxyID:      target.ProxyID,
		VisitorIP:    extractIP(visitor.RemoteAddr()),
		VisitorPort:  uint32(extractPort(visitor.RemoteAddr())),
		OriginalHost: sniHost,
		InitialBytes: head, // optional; the replay below also delivers them
	})
	if err != nil {
		s.logger.Info("open upstream",
			"err", err, "sni", sniHost, "session_id", target.SessionID)
		s.observeRequest("open_upstream_failed")
		return
	}
	defer stream.Close()

	// Replay the buffered ClientHello bytes verbatim so the client's
	// local TLS terminator sees a complete handshake.
	if _, err := stream.Write(head); err != nil {
		s.observeRequest("replay_head_failed")
		return
	}
	s.observeRequest("ok")
	s.observeBytes("visitor_to_client", int64(len(head)))
	// per-tunnel byte attribution (see metered.go / http.go).
	inC, outC := proxyMeters(sess, target.ProxyID)
	inC.Add(uint64(len(head)))

	s.logger.Info("proxying sni",
		"sni", sniHost,
		"session_id", target.SessionID, "proxy_id", target.ProxyID)

	// Per-session bandwidth limiter.
	lim := sess.Limiter()
	type result struct {
		dir   string
		bytes int64
		err   error
	}
	errCh := make(chan result, 2)
	// Live byte metering — see metered.go for the rationale.
	go func() {
		n, e := io.Copy(newBytesMeter(lim.Writer(stream), inC), br)
		errCh <- result{"visitor->stream", n, e}
	}()
	go func() {
		n, e := io.Copy(newBytesMeter(lim.Writer(visitor), outC), stream)
		errCh <- result{"stream->visitor", n, e}
	}()
	first := <-errCh
	switch first.dir {
	case "visitor->stream":
		s.observeBytes("visitor_to_client", first.bytes)
	case "stream->visitor":
		s.observeBytes("client_to_visitor", first.bytes)
	}
	s.logger.Debug("sni direction finished",
		"dir", first.dir, "bytes", first.bytes, "err", first.err,
		"proxy_id", target.ProxyID)
}

func (s *SNI) observeRequest(outcome string) {
	if s.opts.Observer != nil {
		s.opts.Observer.OnVisitorRequest("sni", outcome)
	}
}

func (s *SNI) observeBytes(direction string, n int64) {
	if s.opts.Observer != nil {
		s.opts.Observer.OnBytesTransferred("sni", direction, n)
	}
}

// ---- ClientHello parsing ------------------------------------------------

// peekSNI reads the leading ClientHello bytes and returns them verbatim
// along with the extracted SNI host (lowercased). Bytes consumed by Peek
// remain in br so the caller can io.Copy the raw stream onward.
//
// We implement the parser ourselves because crypto/tls does not expose
// SNI extraction without going through a real handshake (which would
// consume bytes and require terminating the TLS, breaking passthrough).
//
// References: RFC 5246 (Handshake / ClientHello),
// RFC 6066 (server_name extension).
func peekSNI(br *bufio.Reader) ([]byte, string, error) {
	// Step 1: the TLS record header is 5 bytes:
	//   ContentType(1) | ProtocolVersion(2) | Length(2)
	recordHdr, err := br.Peek(5)
	if err != nil {
		return nil, "", fmt.Errorf("peek record header: %w", err)
	}
	if recordHdr[0] != 22 { // 22 = handshake
		return nil, "", errors.New("not a TLS handshake (record type != 22)")
	}
	recLen := int(binary.BigEndian.Uint16(recordHdr[3:5]))
	if recLen < 4 || recLen > sniPeekBuf-5 {
		return nil, "", fmt.Errorf("implausible record length %d", recLen)
	}
	total := 5 + recLen
	hello, err := br.Peek(total)
	if err != nil {
		return nil, "", fmt.Errorf("peek full record: %w", err)
	}

	host, err := extractSNIFromHandshake(hello[5:total])
	if err != nil {
		return nil, "", err
	}
	// Return a copy of hello (Peek's slice is invalidated by next Read).
	head := make([]byte, total)
	copy(head, hello)
	// Consume the bytes we just peeked so the caller can io.Copy the
	// remainder of the stream without re-sending the ClientHello.
	// Mirrors the HTTP listener's sniffHTTP semantics: the manual
	// stream.Write(head) replays the head explicitly.
	if _, err := br.Discard(total); err != nil {
		return nil, "", fmt.Errorf("discard peeked bytes: %w", err)
	}
	return head, strings.ToLower(strings.TrimSpace(host)), nil
}

// extractSNIFromHandshake walks the body of a TLS handshake record looking
// for ClientHello (msg type 1) and pulls the SNI extension.
//
// This is the smallest correct parser we can write; it deliberately does
// NOT validate any other fields (we don't care about cipher suites etc.)
// because the client's local TLS terminator does the real validation.
func extractSNIFromHandshake(b []byte) (string, error) {
	// Handshake header: type(1) + length(3)
	if len(b) < 4 {
		return "", errors.New("handshake too short")
	}
	if b[0] != 1 {
		return "", fmt.Errorf("not ClientHello (handshake type %d)", b[0])
	}
	bodyLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if len(b) < 4+bodyLen {
		return "", errors.New("handshake body truncated")
	}
	body := b[4 : 4+bodyLen]

	// ClientHello layout (skipping past the bits we don't need):
	//   ProtocolVersion (2)
	//   Random          (32)
	//   SessionID len   (1) + bytes
	//   CipherSuites len(2) + bytes
	//   CompressionMethods len(1) + bytes
	//   Extensions      len(2) + entries
	if len(body) < 2+32+1 {
		return "", errors.New("client hello too short for fixed prefix")
	}
	body = body[2+32:] // skip version + random

	// SessionID
	if len(body) < 1 {
		return "", errors.New("missing session_id length")
	}
	sidLen := int(body[0])
	if len(body) < 1+sidLen {
		return "", errors.New("session_id truncated")
	}
	body = body[1+sidLen:]

	// CipherSuites
	if len(body) < 2 {
		return "", errors.New("missing cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(body[:2]))
	if len(body) < 2+csLen {
		return "", errors.New("cipher_suites truncated")
	}
	body = body[2+csLen:]

	// CompressionMethods
	if len(body) < 1 {
		return "", errors.New("missing compression_methods length")
	}
	cmLen := int(body[0])
	if len(body) < 1+cmLen {
		return "", errors.New("compression_methods truncated")
	}
	body = body[1+cmLen:]

	// Extensions
	if len(body) < 2 {
		// No extensions = no SNI. Legal TLS but useless for us.
		return "", errors.New("no extensions block (no SNI)")
	}
	extLen := int(binary.BigEndian.Uint16(body[:2]))
	if len(body) < 2+extLen {
		return "", errors.New("extensions truncated")
	}
	ext := body[2 : 2+extLen]

	for len(ext) >= 4 {
		typ := binary.BigEndian.Uint16(ext[0:2])
		ln := int(binary.BigEndian.Uint16(ext[2:4]))
		if 4+ln > len(ext) {
			return "", errors.New("extension entry overflows block")
		}
		data := ext[4 : 4+ln]
		ext = ext[4+ln:]
		if typ != 0 {
			continue // 0 = server_name
		}
		// server_name list: list_len(2) | entries
		// entry: NameType(1) | NameLen(2) | name
		if len(data) < 2 {
			return "", errors.New("server_name list too short")
		}
		listLen := int(binary.BigEndian.Uint16(data[:2]))
		if 2+listLen > len(data) {
			return "", errors.New("server_name list overflow")
		}
		entries := data[2 : 2+listLen]
		for len(entries) >= 3 {
			nameType := entries[0]
			nameLen := int(binary.BigEndian.Uint16(entries[1:3]))
			if 3+nameLen > len(entries) {
				return "", errors.New("server_name entry overflow")
			}
			if nameType == 0 { // host_name
				return string(entries[3 : 3+nameLen]), nil
			}
			entries = entries[3+nameLen:]
		}
	}
	return "", errors.New("server_name extension not present")
}
