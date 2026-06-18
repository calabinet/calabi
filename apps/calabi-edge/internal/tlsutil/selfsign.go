// Package tlsutil provides TLS bootstrap helpers for dev mode.
//
// Production uses cert-svc to push certificates issued by Let's Encrypt or
// TrustAsia. ships with a self-signed cert generator so the demo runs
// out of the box.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// LoadOrGenerate returns a tls.Certificate for the control listener.
//
// If certPath and keyPath both exist on disk, they are loaded. Otherwise a
// 1-year self-signed ECDSA P-256 certificate is generated in-memory for
// "localhost" and "127.0.0.1"; if both paths are non-empty the generated
// cert is also written to disk for reuse.
func LoadOrGenerate(certPath, keyPath string) (tls.Certificate, error) {
	return loadOrGenerate(certPath, keyPath, "calabi-edge-dev",
		[]string{"localhost", "edge.local.calabi.app"},
		[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
}

// LoadOrGenerateWildcard returns a tls.Certificate for the *visitor*
// HTTPS listener in dev. Distinct from LoadOrGenerate (which serves the
// control listener on a hard-coded "localhost") because the visitor
// listener fronts arbitrary subdomains under baseDomain — a visitor
// hitting u000123.localtest.me must see a cert that validates that
// SNI name, not just "localhost".
//
// SAN list:
//   - baseDomain itself (`localtest.me`)
//   - `*.<baseDomain>` wildcard (covers `u000123.localtest.me`,
//     `whatever.localtest.me`, ...)
//   - `localhost` + 127.0.0.1 / ::1 for the direct-IP curl smoke
//
// Browsers will still warn (it's self-signed); for a frictionless dev
// experience the user imports the.crt into their OS trust store once.
// The cert is regenerated only if certPath/keyPath don't both exist on
// disk, so the trust import survives restarts.
func LoadOrGenerateWildcard(certPath, keyPath, baseDomain string) (tls.Certificate, error) {
	if baseDomain == "" {
		return tls.Certificate{}, fmt.Errorf("baseDomain required for wildcard cert")
	}
	cn := "calabi-edge-dev-wildcard-" + baseDomain
	dns := []string{baseDomain, "*." + baseDomain, "localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	return loadOrGenerate(certPath, keyPath, cn, dns, ips)
}

// loadOrGenerate is the shared implementation behind LoadOrGenerate and
// LoadOrGenerateWildcard.
func loadOrGenerate(certPath, keyPath, cn string, dnsSANs []string, ipSANs []net.IP) (tls.Certificate, error) {
	if certPath != "" && keyPath != "" {
		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				return tls.LoadX509KeyPair(certPath, keyPath)
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsSANs,
		IPAddresses:  ipSANs,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if certPath != "" && keyPath != "" {
		_ = os.WriteFile(certPath, certPEM, 0o644)
		_ = os.WriteFile(keyPath, keyPEM, 0o600)
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}
