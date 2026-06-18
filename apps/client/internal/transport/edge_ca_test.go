package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeCAAndLeaf mints a CA plus a serverAuth leaf (SAN: localhost) signed
// by it — the shape devcerts produces for the edge-control cert and
// cert-svc's edge CA produces in prod.
func makeCAAndLeaf(t *testing.T) (caPEM []byte, leaf tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-edge-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "edge-control"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	leaf, err = tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}),
	)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return caPEM, leaf
}

// TestEdgeRootCAs_VerifiesLeaf is the Phase 1 end-to-end check: the client
// verify path (edgeRootCAs pool + ServerName derived from the dial host)
// accepts a CA-signed serverAuth leaf and rejects the same leaf when the
// CA isn't trusted. This is exactly what daemon↔edge :7443 now does.
func TestEdgeRootCAs_VerifiesLeaf(t *testing.T) {
	caPEM, leaf := makeCAAndLeaf(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Positive: trust the CA via edgeRootCAs(extraFile) -> handshake OK.
	pool, err := edgeRootCAs(caFile)
	if err != nil {
		t.Fatalf("edgeRootCAs: %v", err)
	}
	conn, err := tls.Dial("tcp", "localhost:"+port, &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("verify against dev CA should pass: %v", err)
	}
	_ = conn.Close()

	// Negative: an empty pool (no trusted root) must reject the same leaf.
	if _, err := tls.Dial("tcp", "localhost:"+port, &tls.Config{
		RootCAs:    x509.NewCertPool(),
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
	}); err == nil {
		t.Fatal("verify against an empty pool should fail")
	}
}

// TestEdgeRootCAs_FailsClosed proves we error rather than silently trust
// nothing when neither an embedded root nor a CA file is available. Skips
// on a production build whose certs/edge-ca.pem holds a real root.
func TestEdgeRootCAs_FailsClosed(t *testing.T) {
	if len(embeddedEdgeCA) > 0 {
		p := x509.NewCertPool()
		if p.AppendCertsFromPEM(embeddedEdgeCA) {
			t.Skip("binary has a real embedded edge CA; fail-closed path not exercised")
		}
	}
	if _, err := edgeRootCAs(""); err == nil {
		t.Fatal(`edgeRootCAs("") with the placeholder embed should fail closed`)
	}
}

// hasEmbeddedRoot reports whether this build carries a real embedded edge CA
// (true for dev/release, false for the OSS placeholder).
func hasEmbeddedRoot() bool {
	return len(embeddedEdgeCA) > 0 && x509.NewCertPool().AppendCertsFromPEM(embeddedEdgeCA)
}

// TestEdgeRootCAs_StaleExtraFileTolerated: with a real embedded root, a
// CALABI_EDGE_CA_FILE that points at a missing path is NON-FATAL — the
// embedded root already provides trust, so a stale/relative env var left over
// from a dev shell must not break the dial. (Regression: the daemon used to
// hard-fail "read CALABI_EDGE_CA_FILE ...: cannot find the path".)
func TestEdgeRootCAs_StaleExtraFileTolerated(t *testing.T) {
	if !hasEmbeddedRoot() {
		t.Skip("placeholder build has no embedded root; the extra file is the only trust")
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist", "ca.crt")
	pool, err := edgeRootCAs(missing)
	if err != nil {
		t.Fatalf("a stale CALABI_EDGE_CA_FILE should be tolerated when embedded root is present: %v", err)
	}
	if pool == nil {
		t.Fatal("expected the embedded-root pool, got nil")
	}
}

// TestEdgeRootCAs_MalformedExtraFileFails: a file that IS present but contains
// no PEM certs is a real misconfiguration and still errors, even with an
// embedded root — we only tolerate *absence*, not garbage.
func TestEdgeRootCAs_MalformedExtraFileFails(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(bad, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := edgeRootCAs(bad); err == nil {
		t.Fatal("a present-but-malformed CALABI_EDGE_CA_FILE should fail")
	}
}
