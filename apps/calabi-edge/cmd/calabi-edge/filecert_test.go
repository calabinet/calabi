package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/config"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/tlsutil"
)

// Nothing restarts the edge when its control certificate is replaced, and on a
// BYOI node something replaces it on its own: the leaf is valid 90 days and
// renews with 30 left, writing the new PEM over the same path. A listener
// holding the boot-time copy would go on presenting a certificate that expires
// a month after a fresh one is already on disk — the node healthy on every other
// axis, and every device failing the handshake on day 90.
func TestControlCertPicksUpARotation(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")

	cfg := config.Default()
	cfg.Tunnel.ControlCertPEM, cfg.Tunnel.ControlKeyPEM = certPath, keyPath
	ctrl, err := resolveControlCert(cfg) // generates the first pair
	if err != nil {
		t.Fatal(err)
	}
	first := servedLeaf(t, ctrl)

	// Rotate: a different key pair at the same paths, with an mtime that cannot
	// tie with the first write.
	rotateTo(t, certPath, keyPath)

	second := servedLeaf(t, ctrl)
	if second.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("the listener is still serving the certificate it read at boot")
	}
}

// A rotation is two files written a moment apart, so a handshake can land
// between them. Refusing there would turn a transient mismatch into a refused
// device; the old certificate is still valid, so keep serving it and try again
// on the next handshake.
func TestAHalfWrittenRotationKeepsServingTheOldCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")

	cfg := config.Default()
	cfg.Tunnel.ControlCertPEM, cfg.Tunnel.ControlKeyPEM = certPath, keyPath
	ctrl, err := resolveControlCert(cfg)
	if err != nil {
		t.Fatal(err)
	}
	before := servedLeaf(t, ctrl)

	// The new certificate has landed; its key has not.
	newCert, _ := generatePair(t)
	writeAt(t, certPath, newCert, time.Now().Add(2*time.Second))

	got, err := ctrl.certificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("a half-written rotation must not fail the handshake: %v", err)
	}
	if leafOfCert(t, got).SerialNumber.Cmp(before.SerialNumber) != 0 {
		t.Fatal("served something other than the certificate that still works")
	}

	// Once the key lands, the pair is picked up.
	rotateTo(t, certPath, keyPath)
	if leafOfCert(t, mustServe(t, ctrl)).SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Fatal("the completed rotation was not picked up")
	}
}

// A generated in-memory certificate has no file to watch; it is served as is.
func TestAnEphemeralCertIsServedAsIs(t *testing.T) {
	cfg := config.Default()
	cfg.Tunnel.ControlCertPEM, cfg.Tunnel.ControlKeyPEM = "", ""
	cfg.State.Dir = ""
	ctrl, err := resolveControlCert(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !ctrl.ephemeral || ctrl.files != nil {
		t.Fatalf("ephemeral=%v files=%v, want an in-memory certificate with nothing to watch", ctrl.ephemeral, ctrl.files != nil)
	}
	if leafOfCert(t, mustServe(t, ctrl)).SerialNumber.Cmp(leafOf(t, ctrl).SerialNumber) != 0 {
		t.Fatal("served a different certificate than it resolved")
	}
}

// ---------- helpers ----------

func servedLeaf(t *testing.T, c controlCert) *x509.Certificate {
	t.Helper()
	return leafOfCert(t, mustServe(t, c))
}

func mustServe(t *testing.T, c controlCert) *tls.Certificate {
	t.Helper()
	got, err := c.certificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	return got
}

func leafOfCert(t *testing.T, c *tls.Certificate) *x509.Certificate {
	t.Helper()
	if c.Leaf != nil {
		return c.Leaf
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

// generatePair makes a fresh self-signed pair by letting tlsutil write one to a
// scratch directory, then reading the bytes back.
func generatePair(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	dir := t.TempDir()
	c, k := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if _, err := tlsutil.LoadOrGenerate(c, k); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(c)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err = os.ReadFile(k)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM
}

// rotateTo replaces both files with a new pair, stamped far enough ahead that
// the change cannot be missed for want of clock resolution.
func rotateTo(t *testing.T, certPath, keyPath string) {
	t.Helper()
	certPEM, keyPEM := generatePair(t)
	when := time.Now().Add(4 * time.Second)
	writeAt(t, certPath, certPEM, when)
	writeAt(t, keyPath, keyPEM, when)
}

func writeAt(t *testing.T, path string, data []byte, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}
