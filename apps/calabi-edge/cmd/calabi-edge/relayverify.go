package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
)

// Whether devices may be told to reach this relay over TLS.
//
// On calabi.net a device checks a relay the way it checks that node's :7443:
// the edge CA compiled into it, and the host name it dialed. A relay marked TLS
// in the DERP map is then reached over TLS ONLY — a device never falls back to
// plaintext on it — so the node reports TLS in its heartbeat only when the
// certificate its relay port serves right now would pass exactly that check:
// it verifies against multi_region.ca (the same edge CA, handed to the node
// with its certificate) for the relay's host, as a server certificate. Anything
// else — a self-signed fallback, a certificate issued without the public
// address, a CA file that cannot be read — reports false, and the relay's
// devices keep the plaintext protocol it also speaks.
//
// Checked at every heartbeat, because the answer can change under a running
// node: its certificate renews (fileCert re-reads it) and the CA can roll.

// hostOfAddr is the host of the host:port a node registers; a bare host is
// returned as it is.
func hostOfAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// relayTLSCheck answers the question for one relay.
type relayTLSCheck struct {
	// cert is what the relay port serves (controlCert.certificate).
	cert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// caFile is multi_region.ca.
	caFile string
	// host is the relay's host as devices dial it: the host part of the address
	// the node registers.
	host   string
	logger *slog.Logger

	mu     sync.Mutex
	logged bool
	last   bool
}

// ok is the answer for this heartbeat. The first answer, and every change, is
// logged with the reason, so "why do my devices still use plaintext" has a line
// to find.
func (c *relayTLSCheck) ok() bool {
	if c == nil {
		return false
	}
	err := c.verify()
	ok := err == nil
	c.mu.Lock()
	changed := !c.logged || c.last != ok
	c.logged, c.last = true, ok
	c.mu.Unlock()
	if changed && c.logger != nil {
		if ok {
			c.logger.Info("mesh relay: devices will reach this relay over TLS: its certificate verifies against the platform CA for its host",
				"host", c.host)
		} else {
			c.logger.Warn("mesh relay: devices keep reaching this relay in plaintext: its certificate would not pass their check. Re-issue this node's certificate with its public address to give the relay TLS",
				"host", c.host, "reason", err)
		}
	}
	return ok
}

// verify is the check itself: nil when a device checking against the platform
// CA would accept what the relay serves now.
func (c *relayTLSCheck) verify() error {
	if c.cert == nil {
		return errors.New("the relay serves no certificate")
	}
	if strings.TrimSpace(c.host) == "" {
		return errors.New("no public host to check the certificate against")
	}
	if strings.TrimSpace(c.caFile) == "" {
		return errors.New("no multi_region.ca to check the certificate against")
	}
	served, err := c.cert(&tls.ClientHelloInfo{})
	if err != nil {
		return fmt.Errorf("the relay's certificate: %w", err)
	}
	if served == nil || len(served.Certificate) == 0 {
		return errors.New("the relay serves no certificate")
	}
	leaf := served.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(served.Certificate[0]); err != nil {
			return fmt.Errorf("parse the relay's certificate: %w", err)
		}
	}
	caPEM, err := os.ReadFile(c.caFile)
	if err != nil {
		return fmt.Errorf("read multi_region.ca: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("multi_region.ca %s holds no certificate", c.caFile)
	}
	inter := x509.NewCertPool()
	for _, der := range served.Certificate[1:] {
		if ic, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(ic)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, DNSName: c.host,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return err
	}
	return nil
}
