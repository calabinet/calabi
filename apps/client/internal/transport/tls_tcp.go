// Package transport dials the edge node and brings up a yamux client
// session. QUIC support; ships TLS+yamux only.
package transport

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// DialOptions configures Dial.
type DialOptions struct {
	Addr string // host:port of calabi-edge control listener
	// Insecure skips ALL TLS verification — the last-resort escape hatch
	// (CALABI_INSECURE=1). Default is false: the edge cert is verified
	// against the embedded edge-CA root (+ CACertFile) and the ServerName
	// derived from Addr's host.
	Insecure bool
	// CACertFile is an extra CA root to trust on top of the binary's
	// embedded edge-CA root. Empty = embedded only. Dev points this at
	// deploy/dev/certs/ca.crt via CALABI_EDGE_CA_FILE so a dev edge signed
	// by the dev CA verifies without baking the dev root into the binary.
	CACertFile string
	Timeout    time.Duration // overall dial+handshake timeout
}

// Mux pairs a yamux session with the control stream the client opened
// immediately after connect.
type Mux struct {
	Conn    net.Conn
	Session *yamux.Session
	Control io.ReadWriteCloser
}

// Close shuts everything down.
func (m *Mux) Close() error {
	_ = m.Control.Close()
	_ = m.Session.Close()
	return m.Conn.Close()
}

// RemoteIP returns the dotted-decimal IP this mux's underlying TCP/TLS
// connection is talking to, with the port stripped. Empty string when
// the connection address isn't a host:port pair (shouldn't happen with
// real net.TCPConn, but guard anyway). Used by the daemon's status
// state to render TCP/UDP tunnel public addrs as `<edge_ip>:<port>`.
//
// Why the resolved IP and not the dialed host: in dev users dial
// "localhost" and want to see "127.0.0.1:20000"; in prod they dial
// "edge.calabi.net" and want the actual public IP. RemoteAddr() returns
// the post-resolution IP either way, which is exactly the address a
// peer would use to reach the same edge.
func (m *Mux) RemoteIP() string {
	if m == nil || m.Conn == nil {
		return ""
	}
	addr := m.Conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// OpenDataStream opens a new data stream on the mux and writes the 8-byte
// big-endian stream-id preamble required by the protocol.
//
// The returned stream has the preamble already consumed; callers should
// treat it as a normal byte-stream from there on.
func (m *Mux) OpenDataStream(streamID uint64) (io.ReadWriteCloser, error) {
	s, err := m.Session.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := writeUint64BE(s, streamID); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Dial connects via TLS+yamux and returns a Mux.
func Dial(opts DialOptions) (*Mux, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: opts.Timeout}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"calabi/1"},
	}
	if opts.Insecure {
		// CALABI_INSECURE=1 — skip cert verification entirely. The cmd
		// layer is responsible for warning the user this is unsafe.
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	} else {
		pool, err := edgeRootCAs(opts.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("edge CA: %w", err)
		}
		tlsCfg.RootCAs = pool
		// ServerName left empty on purpose: tls.DialWithDialer fills it
		// from the host part of opts.Addr, so a domain endpoint
		// (edge.calabi.net) or localhost verifies against the cert SAN
		// automatically.
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", opts.Addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", opts.Addr, err)
	}

	sess, err := yamux.Client(conn, nil)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("yamux client: %w", err)
	}
	ctrl, err := sess.OpenStream()
	if err != nil {
		_ = sess.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("open control stream: %w", err)
	}

	return &Mux{Conn: conn, Session: sess, Control: ctrl}, nil
}

func writeUint64BE(w io.Writer, v uint64) error {
	var b [8]byte
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
	_, err := w.Write(b[:])
	return err
}
