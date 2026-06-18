package session

import (
	"crypto/tls"
	"net"
	"time"

	proto "github.com/calabi/calabi/pkg/protocol"
)

// dialUpstream opens the connection to the local upstream described by t.
//
// HTTP / TCP / SNI tunnels get a plain TCP dial — the bytes coming over
// the tunnel are forwarded verbatim, so the upstream protocol layer
// (HTTP plain, raw TCP, or pre-TLS-ed bytes in the SNI case) is the
// caller's problem.
//
// HTTPS tunnels get a TLS-wrapped dial. The mental model that matches
// what users (and ngrok, frp, cloudflared) expect:
//
//	"HTTPS 隧道" = my local upstream itself speaks TLS, please re-encrypt
//	               toward it, regardless of whether the visitor reached
//	               edge via http:// or https://.
//
// Why InsecureSkipVerify: local upstreams in this context are almost
// always self-signed (Home Assistant, Synology, Unifi, dev servers
// running mkcert / openssl-generated certs). MITM on a loopback or
// private-network dial isn't the threat we're defending against —
// the value here is "make it work without making the user babysit a
// trust store". Mirrors probe.health's reasoning.
//
// ServerName is set to the upstream host so SNI-routed local servers
// (rare but real) pick the right backend; cert verification is off so
// it doesn't gate the connection.
//
// Timeout budget: 5s for the underlying TCP connect, plus the TLS
// handshake inside the same 5s wall clock — tls.DialWithDialer
// applies the dialer's Timeout to the whole operation.
func dialUpstream(t Tunnel) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if t.Type == proto.ProxyKindHTTPS {
		serverName, _, err := net.SplitHostPort(t.LocalAddr)
		if err != nil {
			// LocalAddr without port: pass through, tls.Dial will
			// error consistently with the plain-dial path.
			serverName = t.LocalAddr
		}
		return tls.DialWithDialer(dialer, "tcp", t.LocalAddr, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS12,
		})
	}
	return dialer.Dial("tcp", t.LocalAddr)
}
