package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/config"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/tlsutil"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// The control listener's certificate — what clients check before they send the
// edge their token.
//
//   - control.cert_pem + key_pem: that one (generated there on first start if
//     neither file exists yet, as before).
//   - Neither, with state.dir: a self-signed certificate generated once and kept
//     in state.dir, so its fingerprint survives a restart. A self-hosting client
//     pins that fingerprint;
//     `calabi-edge -fingerprint` prints it and the start-up log carries it.
//   - Neither, no state.dir: a new self-signed certificate every start, as
//     before, with a warning — nothing can pin a certificate that changes.
//
// Until 2026-09 the middle case was the last one too: a standalone edge without
// cert paths made a new certificate at every start, so the only way a client
// could connect at all was to skip verifying it, and its token went to whichever
// server answered.

// Files the self-signed certificate is kept in, inside state.dir.
const (
	controlCertName = "control.crt"
	controlKeyName  = "control.key"
)

// controlCert is the resolved control-listener certificate.
type controlCert struct {
	cert   tls.Certificate
	source string // where it came from, for the log
	fresh  bool   // generated just now
	// ephemeral: generated in memory, gone at the next start.
	ephemeral bool
}

func (c controlCert) pin() string {
	leaf := c.cert.Leaf
	if leaf == nil && len(c.cert.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(c.cert.Certificate[0])
	}
	if leaf == nil {
		return ""
	}
	return meshproto.CertPin(leaf)
}

// resolveControlCert decides what the control listener serves (see above).
func resolveControlCert(cfg config.Config) (controlCert, error) {
	certPath, keyPath := cfg.Control.CertPEM, cfg.Control.KeyPEM
	switch {
	case certPath != "" && keyPath != "":
		cert, err := tlsutil.LoadOrGenerate(certPath, keyPath)
		if err != nil {
			return controlCert{}, err
		}
		return controlCert{cert: cert, source: certPath}, nil
	case certPath != "" || keyPath != "":
		return controlCert{}, errors.New("control.cert_pem and control.key_pem must both be set or both empty")
	case cfg.State.Dir == "":
		cert, err := tlsutil.LoadOrGenerate("", "")
		if err != nil {
			return controlCert{}, err
		}
		return controlCert{cert: cert, source: "memory", fresh: true, ephemeral: true}, nil
	}
	cert, fresh, err := loadOrCreateControlCert(cfg.State.Dir, func() ([]string, []net.IP) { return controlCertNames(cfg) })
	if err != nil {
		return controlCert{}, fmt.Errorf("self-signed control certificate in %s: %w", cfg.State.Dir, err)
	}
	return controlCert{cert: cert, source: filepath.Join(cfg.State.Dir, controlCertName), fresh: fresh}, nil
}

// controlCertNames are the names a new self-signed certificate carries: the
// base domain and the public address as well as the local ones, so a client
// that trusts this certificate as its own CA (trust: ca) can check the name it
// dials. A pinning client checks only the key.
func controlCertNames(cfg config.Config) (dns []string, ips []net.IP) {
	dns = []string{"localhost"}
	ips = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	add := func(host string) {
		if host == "" {
			return
		}
		if ip := net.ParseIP(host); ip != nil {
			for _, have := range ips {
				if have.Equal(ip) {
					return
				}
			}
			ips = append(ips, ip)
			return
		}
		for _, have := range dns {
			if have == host {
				return
			}
		}
		dns = append(dns, host)
	}
	add(cfg.HTTP.BaseDomain)
	if host, _, err := net.SplitHostPort(cfg.Public.Addr); err == nil {
		add(host)
	} else {
		add(cfg.Public.Addr)
	}
	if h, err := os.Hostname(); err == nil {
		add(h)
	}
	return dns, ips
}

// loadOrCreateControlCert reads the certificate and key in dir, or generates and
// writes them when neither exists. One without the other, or either unreadable,
// is an error and never a reason to generate: a new key is a new fingerprint,
// and every client that pinned the old one would stop connecting. The names only
// matter to a new certificate; an existing one keeps its own even when the
// config's base domain or address has changed since — its key is its identity.
func loadOrCreateControlCert(dir string, names func() ([]string, []net.IP)) (tls.Certificate, bool, error) {
	certPath, keyPath := filepath.Join(dir, controlCertName), filepath.Join(dir, controlKeyName)
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		return cert, false, err
	case certErr != nil && !os.IsNotExist(certErr):
		return tls.Certificate{}, false, certErr
	case keyErr != nil && !os.IsNotExist(keyErr):
		return tls.Certificate{}, false, keyErr
	case certErr == nil || keyErr == nil:
		return tls.Certificate{}, false, fmt.Errorf("found only one of %s and %s; restore the other rather than generate a new certificate (clients pinned the old one)", controlCertName, controlKeyName)
	}
	dns, ips := names()
	certPEM, keyPEM, err := newControlCertPEM(dns, ips)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, false, err
	}
	// Key first: a crash between the two writes leaves a key without a
	// certificate, which the next start refuses instead of minting a second
	// identity.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, false, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, false, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	return cert, true, err
}

// newControlCertPEM makes the edge's own control certificate. Long-lived like
// the coordinator's: clients trust it by its key, so an expiry would only be a
// scheduled outage.
func newControlCertPEM(dns []string, ips []net.IP) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "calabi-edge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(20, 0, 0),
		DNSNames:     dns,
		IPAddresses:  ips,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// printControlFingerprint is `calabi-edge -fingerprint`: the fingerprint clients
// pin, from the certificate the control listener serves — generated now if this
// is the first run, so it can be handed out before the edge has started.
func printControlFingerprint(cfg config.Config) error {
	c, err := resolveControlCert(cfg)
	if err != nil {
		return err
	}
	if c.ephemeral {
		return errors.New("no state.dir and no control.cert_pem: the edge makes a new certificate at every start, so there is nothing to pin (set state.dir)")
	}
	fmt.Println(c.pin())
	return nil
}
