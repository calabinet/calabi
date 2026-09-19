package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	pool, err := edgeRootCAs(embeddedEdgeCA, caFile)
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

// trusts reports whether pool verifies leaf for localhost — i.e. the pool
// really holds leaf's CA, which a bare non-nil check can't tell.
func trusts(t *testing.T, pool *x509.CertPool, leaf tls.Certificate) bool {
	t.Helper()
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost"})
	return err == nil
}

// TestEdgeRootCAs_FailsClosed covers a build with no embedded root, where
// CALABI_EDGE_CA_FILE is the only possible trust. No build we ship is like
// that (the tree carries the dev CA, releases the real root), so the root is
// handed in empty rather than read from certs/edge-ca.pem — otherwise this
// could only ever skip.
//
// The error cases check WHICH error came back, not just that one did: a
// broken branch falls through to the final "no edge CA root available",
// which would still be an error and still name CALABI_EDGE_CA_FILE.
func TestEdgeRootCAs_FailsClosed(t *testing.T) {
	caPEM, leaf := makeCAAndLeaf(t)
	dir := t.TempDir()
	goodCA := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(goodCA, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		extraFile string
		wantErr   string // substring; "" means a pool is expected
		wantIs    error
	}{
		{"no extra file", "", "no edge CA root available", nil},
		{"missing extra file", filepath.Join(dir, "does-not-exist", "ca.crt"), "CALABI_EDGE_CA_FILE", fs.ErrNotExist},
		{"extra file without PEM", junk, "no PEM certificates", nil},
		{"valid extra file", goodCA, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := edgeRootCAs(nil, tc.extraFile)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("a readable CA file should be enough trust on its own: %v", err)
				}
				if !trusts(t, pool, leaf) {
					t.Fatal("pool does not trust the CALABI_EDGE_CA_FILE root")
				}
				return
			}
			if err == nil {
				t.Fatalf("want an error containing %q, got a pool — fail-open", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("error %q does not wrap %v", err, tc.wantIs)
			}
		})
	}
}

// TestEdgeRootCAs_StaleExtraFileTolerated: with an embedded root, a
// CALABI_EDGE_CA_FILE that points at a missing path is NON-FATAL — the
// embedded root already provides trust, so a stale/relative env var left over
// from a dev shell must not break the dial. (Regression: the daemon used to
// hard-fail "read CALABI_EDGE_CA_FILE ...: cannot find the path".) The root is
// minted here so the test doesn't depend on what certs/edge-ca.pem holds.
func TestEdgeRootCAs_StaleExtraFileTolerated(t *testing.T) {
	rootPEM, leaf := makeCAAndLeaf(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist", "ca.crt")
	pool, err := edgeRootCAs(rootPEM, missing)
	if err != nil {
		t.Fatalf("a stale CALABI_EDGE_CA_FILE should be tolerated when embedded root is present: %v", err)
	}
	if !trusts(t, pool, leaf) {
		t.Fatal("expected the embedded-root pool")
	}
}

// TestEdgeRootCAs_MalformedExtraFileFails: a file that IS present but contains
// no PEM certs is a real misconfiguration and still errors, even with an
// embedded root — we only tolerate *absence*, not garbage.
func TestEdgeRootCAs_MalformedExtraFileFails(t *testing.T) {
	rootPEM, _ := makeCAAndLeaf(t)
	bad := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(bad, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := edgeRootCAs(rootPEM, bad); err == nil {
		t.Fatal("a present-but-malformed CALABI_EDGE_CA_FILE should fail")
	}
}
