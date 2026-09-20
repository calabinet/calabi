// Package trust decides how a client checks the certificate of a server it
// connects to — per connection, because a self-hosted server and calabi.net must
// not share a trust root.
//
// Until 2026-09 every coordinator connection trusted the CA compiled into the
// client (plus CALABI_EDGE_CA_FILE). For calabi.net that is the point. For a
// self-hosted coordinator it meant the client also accepted any certificate that
// CA signed — the platform's in a release build, our development CA in a build
// from the public tree — so we could have stood in for a server that is supposed
// to be the user's alone. A self-hosted connection now names its own trust.
package trust

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/calabinet/calabi/apps/client/internal/transport"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// Mode is how a server's certificate is checked.
type Mode string

const (
	// Platform: the CA compiled into this client (plus CALABI_EDGE_CA_FILE). For
	// calabi.net only; a self-hosted connection never uses it.
	Platform Mode = "platform"
	// System: the operating system's roots and the host name — a server with a
	// certificate from a public CA such as Let's Encrypt.
	System Mode = "system"
	// Pin: some certificate in the server's chain has a public key whose hash is
	// one of Pins (meshproto.CertPin). The host name is not checked: the pin IS
	// the server's identity, the way an SSH host key is.
	Pin Mode = "pin"
	// CA: only the CA in CAPEM, plus the host name.
	CA Mode = "ca"
	// Plaintext: no TLS. Only ever by the user's explicit choice — whatever
	// crosses the connection, the auth key included, crosses it in the clear.
	Plaintext Mode = "plaintext"
)

// Config is one connection's trust.
type Config struct {
	Mode Mode `json:"mode"`
	// Pins for Mode Pin, in meshproto.CertPin's form. More than one lets a
	// server roll to a new key without cutting its devices off.
	Pins []string `json:"pins,omitempty"`
	// CAPEM for Mode CA.
	CAPEM string `json:"ca_pem,omitempty"`
}

// PinMismatchError is a Pin connection whose server presented none of the
// pinned keys. Presented lists the pins it did present, leaf first, so a person
// can compare them with what the server says its fingerprint is.
type PinMismatchError struct {
	Presented []string
}

func (e *PinMismatchError) Error() string {
	return fmt.Sprintf("the server's certificate does not match the pinned fingerprint (it presented %s)", strings.Join(e.Presented, ", "))
}

// TLS returns the tls.Config for connecting to addr (host:port or a bare host),
// or nil for Plaintext.
func (c Config) TLS(addr string) (*tls.Config, error) {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	switch c.Mode {
	case Platform:
		pool, err := transport.EdgeRootCAs()
		if err != nil {
			return nil, fmt.Errorf("trust: the compiled-in CA: %w", err)
		}
		return &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}, nil
	case System:
		return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}, nil
	case CA:
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return nil, errors.New("trust: ca: no certificate in the CA PEM")
		}
		return &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}, nil
	case Pin:
		want := make(map[string]bool, len(c.Pins))
		for _, p := range c.Pins {
			pin, err := meshproto.ParseCertPin(p)
			if err != nil {
				return nil, fmt.Errorf("trust: %w", err)
			}
			want[pin] = true
		}
		if len(want) == 0 {
			return nil, errors.New("trust: pin: no fingerprint to pin")
		}
		return &tls.Config{
			ServerName: host, // still sent, as SNI
			// The chain and name checks are replaced, not dropped: the
			// VerifyConnection below runs on every handshake whatever this says,
			// and refuses one that matches no pin.
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				presented := make([]string, 0, len(cs.PeerCertificates))
				for _, cert := range cs.PeerCertificates {
					pin := meshproto.CertPin(cert)
					if want[pin] {
						return nil
					}
					presented = append(presented, pin)
				}
				return &PinMismatchError{Presented: presented}
			},
			MinVersion: tls.VersionTLS12,
		}, nil
	case Plaintext:
		return nil, nil
	case "":
		return nil, errors.New("trust: no mode set")
	}
	return nil, fmt.Errorf("trust: unknown mode %q (want system, pin, ca, plaintext or platform)", c.Mode)
}

// ParseMode reads a mode as a person writes it in a config file or a flag.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case Platform, System, Pin, CA, Plaintext:
		return m, nil
	}
	return "", fmt.Errorf("unknown trust %q (want system, pin, ca, plaintext or platform)", s)
}
