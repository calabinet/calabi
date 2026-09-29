package derp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// handshakeTLS runs the TLS handshake of a relay link over raw and returns the
// connection to carry frames on, with the binding of the certificate the relay
// presented — the leaf tlsCfg has just verified, and so the one every proof on
// this link is bound to.
//
// TLS 1.3 only, as the relay listens, and only the relay's protocol: a relay
// map pointing at some other TLS server (an edge's :7443, a proxy) fails here
// instead of being sent DERP frames.
func handshakeTLS(ctx context.Context, raw net.Conn, tlsCfg *tls.Config) (net.Conn, meshproto.DERPBinding, error) {
	cfg := tlsCfg.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{meshproto.DERPALPN}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, meshproto.DERPBinding{}, err
	}
	cs := tc.ConnectionState()
	if cs.NegotiatedProtocol != meshproto.DERPALPN {
		return nil, meshproto.DERPBinding{}, fmt.Errorf("the server does not speak the relay protocol (negotiated %q)", cs.NegotiatedProtocol)
	}
	if len(cs.PeerCertificates) == 0 {
		return nil, meshproto.DERPBinding{}, errors.New("the relay presented no certificate")
	}
	return &tlsLink{Conn: tc, raw: raw}, meshproto.DERPBindingOf(cs.PeerCertificates[0]), nil
}

// tlsLink is a relay link's TLS connection. Close drops the TCP connection at
// once instead of first sending close_notify, which tls.Conn's own Close does
// and which can wait up to five seconds on a relay that has stopped reading —
// the case in which the pool is tearing the link down. The DERP stream is
// framed; nothing depends on a clean TLS shutdown.
type tlsLink struct {
	*tls.Conn
	raw net.Conn
}

func (l *tlsLink) Close() error { return l.raw.Close() }
