package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// TLS on the relay's data port.
//
// One port, two protocols, told apart by the first byte a device sends: 0x16
// opens a TLS handshake (a ClientHello record), anything else is the plaintext
// protocol, whose first frame is ClientInfo (type 0x01). Devices whose relay map
// marks this relay as TLS dial TLS; older ones keep speaking plaintext until the
// relay refuses it (mesh.require_tls).
//
// The certificate is the node's own control certificate — the one its tunnel
// control listener serves (resolveControlCert), re-read when its files change.
// No second certificate and nothing new to configure: devices check it the way
// they check that node's :7443. TLS 1.3 only: no RSA key exchange to turn into
// a decryption oracle, and the 1.3 CertificateVerify signatures carry a
// server/client context string, so nothing a relay signs here can stand in for
// the node's own signature as an mTLS client of the control plane.
//
// Each TLS link reaches the hub with the certificate THIS handshake served
// (relay.Hub.ServeBound), and the hub accepts only proofs bound to it. "The
// certificate the node serves now" would not do: a renewal can land between a
// device's handshake and its proof, and the device's proof — correctly bound
// to what it was shown — would then be refused.
//
// This is the relay's own TLS, and it stays the relay's: the connection is
// handed to pkg/relay only after the handshake, and nothing here touches the
// tunnel's TLS-terminating listeners.

// tlsRecordHandshake is the first byte of every TLS connection: the record type
// of the ClientHello.
const tlsRecordHandshake = 0x16

// relayOpenTimeout bounds what a connection may take before the hub sees it:
// its first byte, and the whole TLS handshake. A device sends its ClientInfo or
// ClientHello the moment it connects, so this only ever cuts off a connection
// that sends nothing.
var relayOpenTimeout = 15 * time.Second

// errPlaintextRefused is a plaintext connection on a relay that requires TLS.
var errPlaintextRefused = errors.New("plaintext refused (mesh.require_tls)")

// relayTLS is how the relay port opens a connection.
type relayTLS struct {
	// cert is the node's control certificate as its listener serves it
	// (controlCert.certificate). nil: this relay serves plaintext only.
	cert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// requireTLS refuses the plaintext protocol.
	requireTLS bool
	logger     *slog.Logger
	stats      relayLinkStats
}

// relayLinkStats counts how devices reach the relay. Its hourly line is what
// tells an operator when the plaintext devices are gone and require_tls can be
// turned on.
type relayLinkStats struct {
	tls, plaintext, refused, failed atomic.Int64
	warnedRefusal                   atomic.Bool
}

// open reads the first byte of conn and returns what to hand the hub: conn
// itself for the plaintext protocol, or the TLS connection over it together
// with the binding of the certificate this handshake served. An error means
// close conn.
func (t *relayTLS) open(ctx context.Context, conn net.Conn) (net.Conn, *meshproto.DERPBinding, error) {
	_ = conn.SetDeadline(time.Now().Add(relayOpenTimeout))
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return nil, nil, fmt.Errorf("read first byte: %w", err)
	}
	link := &peekedConn{Conn: conn, head: first[:]}
	if first[0] != tlsRecordHandshake || t.cert == nil {
		if t.requireTLS {
			t.stats.refused.Add(1)
			return nil, nil, errPlaintextRefused
		}
		t.stats.plaintext.Add(1)
		_ = conn.SetDeadline(time.Time{})
		return link, nil, nil
	}

	var served *tls.Certificate
	tc := tls.Server(link, &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{meshproto.DERPALPN},
		// Recorded per connection: the binding must be the certificate THIS
		// handshake presented, whatever the listener would serve a moment later.
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := t.cert(hello)
			if err == nil {
				served = c
			}
			return c, err
		},
	})
	hctx, cancel := context.WithTimeout(ctx, relayOpenTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		t.stats.failed.Add(1)
		return nil, nil, fmt.Errorf("TLS handshake: %w", err)
	}
	leaf, err := relayCertLeaf(served)
	if err != nil {
		t.stats.failed.Add(1)
		return nil, nil, err
	}
	b := meshproto.DERPBindingOf(leaf)
	t.stats.tls.Add(1)
	_ = conn.SetDeadline(time.Time{})
	return &relayTLSConn{Conn: tc, raw: conn}, &b, nil
}

// relayCertLeaf is the parsed leaf of a certificate the listener served.
func relayCertLeaf(c *tls.Certificate) (*x509.Certificate, error) {
	if c == nil || len(c.Certificate) == 0 {
		return nil, errors.New("the handshake completed without a certificate")
	}
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	return x509.ParseCertificate(c.Certificate[0])
}

// accept opens conn and hands it to the current hub, closing it when it cannot
// be opened.
func (t *relayTLS) accept(ctx context.Context, conn net.Conn, gens *relayGens) {
	link, binding, err := t.open(ctx, conn)
	if err != nil {
		_ = conn.Close()
		if errors.Is(err, errPlaintextRefused) && t.stats.warnedRefusal.CompareAndSwap(false, true) {
			t.logger.Warn("mesh relay: refusing a device that speaks plaintext (mesh.require_tls); devices older than relay TLS cannot use this relay, and the hourly relay-links line counts them",
				"remote", conn.RemoteAddr().String())
			return
		}
		t.logger.Debug("mesh relay: connection not opened", "remote", conn.RemoteAddr().String(), "err", err)
		return
	}
	gens.serve(link, binding)
}

// relayLinkStatsEvery is how often the relay says how devices reached it.
var relayLinkStatsEvery = time.Hour

// logLoop reports the counts every relayLinkStatsEvery, and only when there is
// something to report.
func (t *relayTLS) logLoop(ctx context.Context) {
	tick := time.NewTicker(relayLinkStatsEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		tlsN, plain := t.stats.tls.Swap(0), t.stats.plaintext.Swap(0)
		refused, failed := t.stats.refused.Swap(0), t.stats.failed.Swap(0)
		if tlsN+plain+refused+failed == 0 {
			continue
		}
		t.logger.Info("mesh relay: links opened", "over", relayLinkStatsEvery,
			"tls", tlsN, "plaintext", plain, "plaintext_refused", refused, "tls_failed", failed,
			"require_tls", t.requireTLS)
	}
}

// peekedConn gives back the byte open read to tell the protocols apart.
type peekedConn struct {
	net.Conn
	head []byte
}

func (c *peekedConn) Read(p []byte) (int, error) {
	if len(c.head) > 0 {
		n := copy(p, c.head)
		c.head = c.head[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// relayTLSConn is a TLS link as the hub sees it. Close drops the TCP connection
// at once rather than first sending close_notify, as tls.Conn's own Close does:
// that write can wait up to five seconds on a peer that has stopped reading,
// and the hub closes a replaced link while holding its lock (pkg/relay hub.add).
// The DERP stream is framed, so nothing depends on a clean TLS shutdown.
type relayTLSConn struct {
	*tls.Conn
	raw net.Conn
}

func (c *relayTLSConn) Close() error { return c.raw.Close() }
