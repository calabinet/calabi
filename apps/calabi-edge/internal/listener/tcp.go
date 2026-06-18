package listener

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/ratelimit"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// TCPObserver is the visitor-facing metrics surface for the TCP listener.
type TCPObserver interface {
	OnVisitorRequest(proxyType, outcome string)
	OnBytesTransferred(proxyType, direction string, n int64)
}

// StartTCPProxy opens a TCP listener on the requested remotePort and
// returns it as an io.Closer. A background goroutine accepts visitor
// connections and bridges each one to the client over a yamux data stream.
//
// The listener is owned by the caller -- typically stored on Proxy.Listener
// so the session's teardown logic closes it on disconnect / CLOSE_PROXY.
//
// Returns an error if the port is already taken or otherwise unbindable.
// obs may be nil.
func StartTCPProxy(logger *slog.Logger, remotePort uint32, sess *session.Session, proxyID string, obs TCPObserver, glob *ratelimit.GlobalLimiter) (io.Closer, error) {
	addr := fmt.Sprintf(":%d", remotePort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	tcpLog := logger.With(
		"component", "listener.tcp",
		"proxy_id", proxyID,
		"remote_port", remotePort,
	)
	tcpLog.Info("tcp proxy listening")

	go acceptTCP(tcpLog, ln, sess, proxyID, remotePort, obs, glob)

	return ln, nil
}

func acceptTCP(logger *slog.Logger, ln net.Listener, sess *session.Session, proxyID string, remotePort uint32, obs TCPObserver, glob *ratelimit.GlobalLimiter) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Net.errClosed is the expected signal on graceful teardown.
			if errors.Is(err, net.ErrClosed) {
				logger.Info("tcp proxy stopped")
				return
			}
			logger.Warn("accept", "err", err)
			// Avoid a busy-loop on persistent listener errors.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		// Phase B global backpressure: shed before spending a goroutine.
		rel, shed := globalAdmit(glob)
		if shed != "" {
			if obs != nil {
				obs.OnVisitorRequest("tcp", shed)
			}
			_ = conn.Close()
			continue
		}
		go func() {
			defer rel()
			handleTCPConn(logger, conn, sess, proxyID, remotePort, obs)
		}()
	}
}

func handleTCPConn(logger *slog.Logger, visitor net.Conn, sess *session.Session, proxyID string, remotePort uint32, obs TCPObserver) {
	defer visitor.Close()

	// Security policy (server-authoritative IP allowlist). Raw TCP has no
	// protocol to answer on, so a denied source is closed (deferred Close).
	if p := sess.Proxy(proxyID); p != nil {
		if pol := p.LoadPolicy(); pol != nil {
			if pol.HasIPRules() && !pol.AllowIPString(extractIP(visitor.RemoteAddr())) {
				if obs != nil {
					obs.OnVisitorRequest("tcp", "ip_denied")
				}
				return
			}
			if pol.HasRateLimit() && !pol.AllowRate() {
				if obs != nil {
					obs.OnVisitorRequest("tcp", "rate_limited")
				}
				return
			}
		}
	}

	// Anti-abuse gates (Phase A): raw TCP shares the TCP/TLS new-connection
	// rate bucket + the org-wide concurrent cap. Over-limit connections are
	// closed (no protocol to send a message on raw TCP). Unguarded sessions
	// pass through.
	if err := sess.AllowTCPConn(); err != nil {
		if obs != nil {
			obs.OnVisitorRequest("tcp", "rate_limited")
		}
		return
	}
	// Per-day connection cap (daily_tcp_conns). Only free is finite today.
	if err := sess.AllowTCPConnDaily(); err != nil {
		if obs != nil {
			obs.OnVisitorRequest("tcp", "daily_capped")
		}
		return
	}
	release, err := sess.AcquireConn()
	if err != nil {
		if obs != nil {
			obs.OnVisitorRequest("tcp", "conn_capped")
		}
		return
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := sess.OpenProxyConn(ctx, &proto.NewConnRequest{
		ProxyID:     proxyID,
		VisitorIP:   extractIP(visitor.RemoteAddr()),
		VisitorPort: uint32(extractPort(visitor.RemoteAddr())),
		// OriginalHost / OriginalPath stay empty for raw TCP.
	})
	if err != nil {
		logger.Info("open upstream", "err", err, "remote", visitor.RemoteAddr())
		if obs != nil {
			obs.OnVisitorRequest("tcp", "open_upstream_failed")
		}
		return
	}
	defer stream.Close()

	if obs != nil {
		obs.OnVisitorRequest("tcp", "ok")
	}
	logger.Debug("proxying tcp",
		"visitor", visitor.RemoteAddr().String())

	// Per-session bandwidth limiter.
	lim := sess.Limiter()
	// per-tunnel byte attribution (see metered.go / http.go).
	inC, outC := proxyMeters(sess, proxyID)
	type result struct {
		dir   string
		bytes int64
		err   error
	}
	errCh := make(chan result, 2)
	// Live byte metering — see metered.go for the rationale.
	go func() {
		n, e := io.Copy(newBytesMeter(lim.Writer(stream), inC), visitor)
		errCh <- result{"visitor->stream", n, e}
	}()
	go func() {
		n, e := io.Copy(newBytesMeter(lim.Writer(visitor), outC), stream)
		errCh <- result{"stream->visitor", n, e}
	}()
	first := <-errCh
	if obs != nil {
		switch first.dir {
		case "visitor->stream":
			obs.OnBytesTransferred("tcp", "visitor_to_client", first.bytes)
		case "stream->visitor":
			obs.OnBytesTransferred("tcp", "client_to_visitor", first.bytes)
		}
	}
	logger.Debug("tcp direction finished",
		"dir", first.dir, "bytes", first.bytes, "err", first.err)
}
