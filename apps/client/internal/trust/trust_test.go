package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// testCA is a CA that can sign server certificates for 127.0.0.1.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newCA(t *testing.T, name string) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// issue signs a server certificate for 127.0.0.1 (and "coord.example").
func (ca testCA) issue(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "coord"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"coord.example"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// serve runs a TLS server presenting cert and returns its address.
func serve(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()
	return ln.Addr().String()
}

// handshake dials addr with cfg's TLS and reports the handshake error.
func handshake(t *testing.T, cfg Config, addr string) error {
	t.Helper()
	tc, err := cfg.TLS(addr)
	if err != nil {
		t.Fatalf("TLS(%v): %v", cfg.Mode, err)
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, tc)
	if err != nil {
		return err
	}
	c.Close()
	return nil
}

func TestPinAcceptsThePinnedKeyWhateverTheName(t *testing.T) {
	ca := newCA(t, "self")
	cert := ca.issue(t)
	addr := serve(t, cert)
	pin := meshproto.CertPin(cert.Leaf)

	if err := handshake(t, Config{Mode: Pin, Pins: []string{pin}}, addr); err != nil {
		t.Fatalf("pinned leaf refused: %v", err)
	}
	// A pin written the way people copy it still matches.
	if err := handshake(t, Config{Mode: Pin, Pins: []string{"SHA256:" + pin[len("sha256:"):]}}, addr); err != nil {
		t.Fatalf("pinned leaf (typed) refused: %v", err)
	}
	// The name is not checked: dialing by a name the certificate does not carry
	// is still the pinned server.
	tc, _ := Config{Mode: Pin, Pins: []string{pin}}.TLS("not-in-the-cert.example:7012")
	c, err := tls.Dial("tcp", addr, tc)
	if err != nil {
		t.Fatalf("pin with a foreign name refused: %v", err)
	}
	c.Close()
}

func TestPinRefusesAnotherKeyAndSaysWhatItSaw(t *testing.T) {
	ca := newCA(t, "self")
	cert := ca.issue(t)
	addr := serve(t, cert)
	other := newCA(t, "other").issue(t)

	err := handshake(t, Config{Mode: Pin, Pins: []string{meshproto.CertPin(other.Leaf)}}, addr)
	var mismatch *PinMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want a PinMismatchError", err)
	}
	if len(mismatch.Presented) == 0 || mismatch.Presented[0] != meshproto.CertPin(cert.Leaf) {
		t.Fatalf("Presented = %v, want the server's leaf pin %s first", mismatch.Presented, meshproto.CertPin(cert.Leaf))
	}
}

func TestCATrustsOnlyItsOwnCA(t *testing.T) {
	ca := newCA(t, "mine")
	addr := serve(t, ca.issue(t))
	if err := handshake(t, Config{Mode: CA, CAPEM: ca.pem}, addr); err != nil {
		t.Fatalf("own CA refused: %v", err)
	}
	if err := handshake(t, Config{Mode: CA, CAPEM: newCA(t, "someone else").pem}, addr); err == nil {
		t.Fatal("a certificate from another CA was accepted")
	}
}

func TestSystemRefusesAPrivateCA(t *testing.T) {
	addr := serve(t, newCA(t, "private").issue(t))
	if err := handshake(t, Config{Mode: System}, addr); err == nil {
		t.Fatal("system trust accepted a private CA's certificate")
	}
}

// The reason this package exists: a server whose certificate chains to the CA
// the client trusts for calabi.net must NOT be accepted by a self-hosted trust.
// CALABI_EDGE_CA_FILE feeds that same platform pool, so pointing it at a test CA
// stands in for the compiled-in one.
func TestSelfHostedModesNeverTrustThePlatformCA(t *testing.T) {
	platformCA := newCA(t, "platform")
	caFile := filepath.Join(t.TempDir(), "platform-ca.pem")
	if err := os.WriteFile(caFile, []byte(platformCA.pem), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CALABI_EDGE_CA_FILE", caFile)
	addr := serve(t, platformCA.issue(t))

	if err := handshake(t, Config{Mode: Platform}, addr); err != nil {
		t.Fatalf("control: the platform mode should accept its own CA: %v", err)
	}
	someoneElse := newCA(t, "user")
	for _, cfg := range []Config{
		{Mode: System},
		{Mode: CA, CAPEM: someoneElse.pem},
		{Mode: Pin, Pins: []string{meshproto.CertPin(someoneElse.issue(t).Leaf)}},
	} {
		if err := handshake(t, cfg, addr); err == nil {
			t.Errorf("mode %s accepted a certificate from the platform CA", cfg.Mode)
		}
	}
}

func TestPlaintextHasNoTLSAndBadConfigsAreRefused(t *testing.T) {
	if tc, err := (Config{Mode: Plaintext}).TLS("h:1"); tc != nil || err != nil {
		t.Fatalf("plaintext = %v, %v; want nil, nil", tc, err)
	}
	for _, cfg := range []Config{
		{},
		{Mode: "tofu"},
		{Mode: Pin},
		{Mode: Pin, Pins: []string{"not-a-pin"}},
		{Mode: CA},
		{Mode: CA, CAPEM: "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"},
	} {
		if _, err := cfg.TLS("h:1"); err == nil {
			t.Errorf("TLS(%+v) accepted a config it cannot honour", cfg)
		}
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"system": System, " PIN ": Pin, "Ca": CA, "plaintext": Plaintext, "platform": Platform} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "insecure", "tofu"} {
		if _, err := ParseMode(bad); err == nil {
			t.Errorf("ParseMode(%q) accepted", bad)
		}
	}
}
