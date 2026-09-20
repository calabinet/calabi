// Package selfhosted is what the phone and the desktop share about joining a
// server someone runs themselves instead of calabi.net: reading an invite link, looking at
// the certificate a server presents before anything is sent to it, and telling
// "the server is down" from "the server's certificate is not the one we trust".
package selfhosted

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/hostnet"
	"github.com/calabinet/calabi/apps/client/internal/trust"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// The application protocols the two kinds of server speak. A handshake offering
// the wrong one is refused by a Go server, so a probe offers the right one.
var (
	CoordALPN = []string{"h2"}       // the coordinator (gRPC)
	EdgeALPN  = []string{"calabi/1"} // an edge's control listener
)

// Invite is what a device needs to join a coordinator: a calabi://join link, or
// the same typed in by hand.
type Invite struct {
	Server    string
	Key       string
	Pin       string
	Plaintext bool
}

// ParseInvite reads a calabi://join link (calabi-coord invite prints them):
// v=1, s=host:port, k=key, and fp=<pin> or tls=off.
func ParseInvite(link string) (Invite, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Scheme != "calabi" || (u.Host != "join" && u.Opaque != "join" && !strings.HasPrefix(u.Opaque, "join")) {
		return Invite{}, errors.New("not a calabi://join link")
	}
	q := u.Query()
	if v := q.Get("v"); v != "" && v != "1" {
		return Invite{}, fmt.Errorf("this invite is format %s; update the app", v)
	}
	inv := Invite{Server: q.Get("s"), Key: q.Get("k"), Pin: q.Get("fp"), Plaintext: q.Get("tls") == "off"}
	if inv.Server == "" || inv.Key == "" {
		return Invite{}, errors.New("the invite has no server or no key")
	}
	return inv, nil
}

// Probe is what the server at an address presents.
type Probe struct {
	Server string `json:"server"`
	// TLS false: the server answered, but not with TLS.
	TLS bool `json:"tls"`
	// SystemTrusted: the certificate chains to a root this device trusts, for
	// this name. Then nothing needs confirming.
	SystemTrusted bool   `json:"system_trusted"`
	Pin           string `json:"pin,omitempty"`
	Subject       string `json:"subject,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	NotAfter      string `json:"not_after,omitempty"`
}

// ProbeServer connects to server once and reports its certificate, without
// trusting or refusing it: a person compares the fingerprint with what the
// server prints. Outside the VPN, like every socket the client opens for
// the control plane.
func ProbeServer(ctx context.Context, server string, alpn []string) (Probe, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return Probe{}, fmt.Errorf("%q is not host:port", server)
	}
	out := Probe{Server: server}
	raw, err := hostnet.Dialer().DialContext(ctx, "tcp", server)
	if err != nil {
		return out, err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName: host, NextProtos: alpn, MinVersion: tls.VersionTLS12,
		// Only to read the certificate; the verdict is made below, and the
		// connection is closed without a byte of application data.
		InsecureSkipVerify: true,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		var rec tls.RecordHeaderError
		if errors.As(err, &rec) {
			return out, nil // it speaks, but not TLS
		}
		return out, err
	}
	out.TLS = true
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return out, errors.New("the server presented no certificate")
	}
	leaf := chain[0]
	out.Pin = meshproto.CertPin(leaf)
	out.Subject, out.Issuer = leaf.Subject.String(), leaf.Issuer.String()
	out.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
	out.SystemTrusted = verr == nil
	return out, nil
}

// handshake makes the real handshake with the given trust.
func handshake(ctx context.Context, server string, t trust.Config, alpn []string) error {
	tlsCfg, err := t.TLS(server)
	if err != nil {
		return err
	}
	if tlsCfg == nil {
		return errors.New("plaintext: no handshake")
	}
	tlsCfg = tlsCfg.Clone()
	tlsCfg.NextProtos = alpn
	raw, err := hostnet.Dialer().DialContext(ctx, "tcp", server)
	if err != nil {
		return err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	return tls.Client(raw, tlsCfg).HandshakeContext(ctx)
}

// PinnedInChain makes the real, pinned handshake: true when some certificate in
// the server's chain matches. A probe compares only the leaf; a pin may name a
// CA in the chain.
func PinnedInChain(ctx context.Context, server string, t trust.Config, alpn []string) bool {
	return handshake(ctx, server, t, alpn) == nil
}

// CertRefused makes one handshake with the saved trust and returns the
// fingerprint the server presents when that trust refuses it; "" when the
// handshake passes, or fails for any reason but the certificate (the network).
// It is how a connection that keeps failing tells "the server is down" from
// "the server's certificate changed", which only a person can accept.
func CertRefused(ctx context.Context, server string, t trust.Config, alpn []string) string {
	if t.Mode == trust.Plaintext {
		return ""
	}
	herr := handshake(ctx, server, t, alpn)
	var mismatch *trust.PinMismatchError
	var unverified *tls.CertificateVerificationError
	if !errors.As(herr, &mismatch) && !errors.As(herr, &unverified) {
		return ""
	}
	pr, err := ProbeServer(ctx, server, alpn)
	if err != nil || !pr.TLS {
		return ""
	}
	return pr.Pin
}
