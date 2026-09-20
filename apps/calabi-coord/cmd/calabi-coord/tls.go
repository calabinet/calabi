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
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// Coord's gRPC is the one control-plane surface a client dials directly over the
// public internet, and a node sends its auth key over it on every enrollment, so
// it serves TLS itself. Which certificate:
//
//   - CALABI_COORD_TLS_CERT_FILE + _KEY_FILE: that one. The hosted platform gives
//     coord a server certificate signed by the platform EDGE CA, which the
//     daemon already embeds to verify the edge :7443 listener, so it verifies
//     coord with no extra trust distribution. Give it a SERVER-only certificate
//     (serverAuth EKU, no clientAuth, no SPIFFE org SAN) — one from cert-svc's
//     IssueServerCert, NOT an edge leaf: an edge leaf doubles as a control-plane
//     CLIENT credential (mTLS into bff-edge), which would widen the blast radius
//     of a coord compromise. One of the two set without the other aborts.
//   - Neither set: a self-signed certificate, generated once and kept in
//     CALABI_COORD_TLS_DIR (default./coord-tls) so its fingerprint survives a
//     restart. Devices pin that fingerprint (`calabi-coord fingerprint` prints
//     it; invite links carry it) —
//     Until 2026-09 this case served PLAINTEXT, and the auth key crossed the
//     network in the clear unless the operator had arranged a certificate.
//   - CALABI_COORD_TLS=off: plaintext, for a dev stack or a deployment that
//     terminates TLS in front.

// Files the self-signed certificate is kept in, inside CALABI_COORD_TLS_DIR.
const (
	selfSignedCertName = "coord.crt"
	selfSignedKeyName  = "coord.key"
)

// coordTLS is the resolved listener security. cert nil = plaintext.
type coordTLS struct {
	cert   *tls.Certificate
	mode   string // "files", "self-signed" or "off" — core.ListenerTLS.Mode
	source string // for the log: where the certificate came from
	fresh  bool   // the self-signed certificate was generated just now
}

// resolveCoordTLS decides what the gRPC listener serves (see the note above).
func resolveCoordTLS() (coordTLS, error) {
	certFile := strings.TrimSpace(os.Getenv("CALABI_COORD_TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("CALABI_COORD_TLS_KEY_FILE"))
	switch {
	case certFile != "" && keyFile != "":
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return coordTLS{}, fmt.Errorf("load the gRPC server certificate %s: %w", certFile, err)
		}
		return coordTLS{cert: &cert, mode: "files", source: certFile}, nil
	case certFile != "" || keyFile != "":
		return coordTLS{}, errors.New("CALABI_COORD_TLS_CERT_FILE and _KEY_FILE must both be set or both empty; refusing to start half-configured")
	}
	switch mode := strings.ToLower(env("TLS")); mode {
	case "off":
		return coordTLS{mode: "off"}, nil
	case "", "self-signed":
	default:
		return coordTLS{}, fmt.Errorf("CALABI_COORD_TLS=%q: want off or self-signed (or set CALABI_COORD_TLS_CERT_FILE/_KEY_FILE)", mode)
	}
	dir := env("TLS_DIR")
	if dir == "" {
		dir = "coord-tls"
	}
	cert, fresh, err := loadOrCreateSelfSigned(dir)
	if err != nil {
		return coordTLS{}, fmt.Errorf("self-signed certificate in %s: %w (set CALABI_COORD_TLS_DIR to a writable directory, or CALABI_COORD_TLS=off)", dir, err)
	}
	return coordTLS{cert: &cert, mode: "self-signed", source: filepath.Join(dir, selfSignedCertName), fresh: fresh}, nil
}

// pin is the certificate's fingerprint as devices pin it; "" for plaintext.
func (c coordTLS) pin() string {
	if c.cert == nil || c.cert.Leaf == nil {
		return ""
	}
	return meshproto.CertPin(c.cert.Leaf)
}

// listener is what the admin API reports about this listener
// (GET /admin/tls): what `calabi-coord invite` puts in a link comes from the
// coordinator that is actually running, not from whatever directory the command
// happens to be run in.
func (c coordTLS) listener() core.ListenerTLS {
	return core.ListenerTLS{Mode: c.mode, Pin: c.pin()}
}

// coordServerCreds builds the gRPC server options for the resolved listener
// security (resolveCoordTLS, which main calls once and exits on an error).
func coordServerCreds(logger *slog.Logger, t coordTLS) []grpc.ServerOption {
	if t.cert == nil {
		logger.Warn("coord gRPC is PLAINTEXT (CALABI_COORD_TLS=off) — devices send their auth key over it. Only behind a TLS-terminating proxy or on a network you trust")
		return nil
	}
	if t.fresh {
		logger.Info("coord: generated a self-signed gRPC certificate; devices pin its fingerprint", "cert", t.source, "fingerprint", t.pin())
	} else {
		logger.Info("coord gRPC serving TLS", "cert", t.source, "fingerprint", t.pin())
	}
	return []grpc.ServerOption{grpc.Creds(credentials.NewServerTLSFromCert(t.cert))}
}

// loadOrCreateSelfSigned reads the certificate and key in dir, or generates and
// writes them when neither exists. One without the other, or either unreadable,
// is an ERROR and never a reason to generate: a new key is a new fingerprint,
// and every device that pinned the old one would stop connecting (the same rule
// as the relay grant key, relaygrantkey.go).
func loadOrCreateSelfSigned(dir string) (tls.Certificate, bool, error) {
	certPath, keyPath := filepath.Join(dir, selfSignedCertName), filepath.Join(dir, selfSignedKeyName)
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, false, err
		}
		return cert, false, nil
	case !os.IsNotExist(certErr) && certErr != nil:
		return tls.Certificate{}, false, certErr
	case !os.IsNotExist(keyErr) && keyErr != nil:
		return tls.Certificate{}, false, keyErr
	case certErr == nil || keyErr == nil:
		return tls.Certificate{}, false, fmt.Errorf("found only one of %s and %s; restore the other rather than generate a new certificate (devices pinned the old one)", selfSignedCertName, selfSignedKeyName)
	}

	certPEM, keyPEM, err := newSelfSignedPEM()
	if err != nil {
		return tls.Certificate{}, false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, false, err
	}
	// Key first: a crash between the two writes leaves a key without a
	// certificate, which the next start refuses loudly instead of silently
	// minting a second identity.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, false, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, false, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	return cert, true, err
}

// newSelfSignedPEM makes the coordinator's own certificate. Long-lived on
// purpose: devices trust it by its key (a pin), not by its dates or names, so
// an expiry would only be a scheduled outage. The names are for a person
// reading it.
func newSelfSignedPEM() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	names := []string{"localhost"}
	if h, err := os.Hostname(); err == nil && h != "" {
		names = append(names, h)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "calabi-coord"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(20, 0, 0),
		DNSNames:     names,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
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

// runFingerprint is `calabi-coord fingerprint`: print the fingerprint devices
// pin, from the same certificate the listener would serve — generating the
// self-signed one if this is the first run, so the value can be handed out
// before the coordinator has ever started.
func runFingerprint() int {
	t, err := resolveCoordTLS()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi-coord fingerprint:", err)
		return 1
	}
	if t.cert == nil {
		fmt.Fprintln(os.Stderr, "calabi-coord fingerprint: TLS is off (CALABI_COORD_TLS=off), so there is no certificate to pin")
		return 1
	}
	fmt.Println(t.pin())
	return 0
}
