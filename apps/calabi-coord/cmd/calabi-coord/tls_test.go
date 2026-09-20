package main

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// clearCoordTLSEnv isolates a test from whatever the machine running it has set.
func clearCoordTLSEnv(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "coord-tls")
	for _, k := range []string{"CALABI_COORD_TLS_CERT_FILE", "CALABI_COORD_TLS_KEY_FILE", "CALABI_COORD_TLS", "COORD_SVC_TLS", "COORD_SVC_TLS_DIR"} {
		t.Setenv(k, "")
	}
	t.Setenv("CALABI_COORD_TLS_DIR", dir)
	return dir
}

// With nothing configured the coordinator serves TLS on a certificate it keeps:
// the second start must present the same key, or every device that pinned the
// first would be locked out by a restart.
func TestSelfSignedByDefaultAndStableAcrossRestarts(t *testing.T) {
	dir := clearCoordTLSEnv(t)
	first, err := resolveCoordTLS()
	if err != nil {
		t.Fatal(err)
	}
	if first.cert == nil || !first.fresh || first.pin() == "" {
		t.Fatalf("first start: cert=%v fresh=%v pin=%q; want a freshly generated certificate", first.cert != nil, first.fresh, first.pin())
	}
	if info, err := os.Stat(filepath.Join(dir, selfSignedKeyName)); err != nil || (info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Fatalf("key file: %v, %v", info, err)
	}
	second, err := resolveCoordTLS()
	if err != nil {
		t.Fatal(err)
	}
	if second.fresh || second.pin() != first.pin() {
		t.Fatalf("restart: fresh=%v pin=%s; want the stored certificate %s", second.fresh, second.pin(), first.pin())
	}
}

// What the listener serves is what `calabi-coord fingerprint` prints.
func TestServedCertificateMatchesThePrintedFingerprint(t *testing.T) {
	clearCoordTLSEnv(t)
	want, err := resolveCoordTLS()
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(coordServerCreds(quietLogger(), want)...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatalf("the listener does not speak TLS: %v", err)
	}
	defer conn.Close()
	got := meshproto.CertPin(conn.ConnectionState().PeerCertificates[0])
	if got != want.pin() {
		t.Fatalf("served %s, fingerprint says %s", got, want.pin())
	}
}

// Half a stored identity is restored, never replaced.
func TestSelfSignedRefusesToReplaceHalfAnIdentity(t *testing.T) {
	for _, keep := range []string{selfSignedCertName, selfSignedKeyName} {
		dir := clearCoordTLSEnv(t)
		if _, err := resolveCoordTLS(); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{selfSignedCertName, selfSignedKeyName} {
			if name != keep {
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
		}
		if got, err := resolveCoordTLS(); err == nil {
			t.Errorf("only %s left: resolved %v, want an error", keep, got.pin())
		}
	}
}

func TestCoordTLSConfigurations(t *testing.T) {
	clearCoordTLSEnv(t)
	t.Setenv("CALABI_COORD_TLS", "off")
	if got, err := resolveCoordTLS(); err != nil || got.cert != nil {
		t.Fatalf("off: cert=%v err=%v; want plaintext", got.cert != nil, err)
	}
	t.Setenv("CALABI_COORD_TLS", "maybe")
	if _, err := resolveCoordTLS(); err == nil {
		t.Fatal("an unknown CALABI_COORD_TLS was accepted")
	}

	// Explicit files win over the default, and over "off".
	dir := t.TempDir()
	certPEM, keyPEM, err := newSelfSignedPEM()
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(certFile, certPEM, 0o600)
	_ = os.WriteFile(keyFile, keyPEM, 0o600)
	t.Setenv("CALABI_COORD_TLS_CERT_FILE", certFile)
	t.Setenv("CALABI_COORD_TLS_KEY_FILE", keyFile)
	got, err := resolveCoordTLS()
	if err != nil || got.cert == nil || got.source != certFile {
		t.Fatalf("files: source=%q err=%v", got.source, err)
	}
	t.Setenv("CALABI_COORD_TLS_KEY_FILE", "")
	if _, err := resolveCoordTLS(); err == nil {
		t.Fatal("a certificate without its key was accepted")
	}
}
