package selfhosted

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/calabi/calabi/apps/client/internal/trust"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func TestParseInvite(t *testing.T) {
	inv, err := ParseInvite("calabi://join?fp=sha256%3Aab&k=ck_x&s=coord.example.com%3A7012&v=1")
	if err != nil || inv.Server != "coord.example.com:7012" || inv.Key != "ck_x" || inv.Pin != "sha256:ab" || inv.Plaintext {
		t.Fatalf("%+v %v", inv, err)
	}
	if inv, err := ParseInvite("calabi://join?s=10.0.0.5:7012&k=ck_x&tls=off"); err != nil || !inv.Plaintext {
		t.Fatalf("plaintext: %+v %v", inv, err)
	}
	for _, bad := range []string{"", "https://join?s=a:1&k=b", "calabi://other?s=a:1&k=b", "calabi://join?k=b", "calabi://join?s=a:1", "calabi://join?v=2&s=a:1&k=b"} {
		if _, err := ParseInvite(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "calabi-edge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, meshproto.CertPin(leaf)
}

// serve runs a TLS server that speaks only alpn, the way an edge's control
// listener refuses a client offering another protocol.
func serve(t *testing.T, cert tls.Certificate, alpn []string) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: alpn, MinVersion: tls.VersionTLS13})
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
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestProbeAnEdge(t *testing.T) {
	cert, pin := selfSigned(t)
	addr := serve(t, cert, EdgeALPN)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pr, err := ProbeServer(ctx, addr, EdgeALPN)
	if err != nil || !pr.TLS || pr.SystemTrusted || pr.Pin != pin {
		t.Fatalf("probe: %+v %v; want TLS, not system-trusted, pin %s", pr, err, pin)
	}
	// Offering the coordinator's protocol to an edge fails the handshake, which
	// is why the probe takes the protocol.
	if _, err := ProbeServer(ctx, addr, CoordALPN); err == nil {
		t.Fatal("probing an edge with the coordinator's ALPN succeeded; the test server does not refuse other protocols")
	}
}

// The saved trust refuses the certificate: CertRefused names what the server
// presents now. The trust accepts it, or nobody answers: "".
func TestCertRefused(t *testing.T) {
	cert, pin := selfSigned(t)
	addr := serve(t, cert, EdgeALPN)
	_, other := selfSigned(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if got := CertRefused(ctx, addr, trust.Config{Mode: trust.Pin, Pins: []string{other}}, EdgeALPN); got != pin {
		t.Fatalf("pinned to another key: CertRefused = %q, want the presented %q", got, pin)
	}
	if got := CertRefused(ctx, addr, trust.Config{Mode: trust.System}, EdgeALPN); got != pin {
		t.Fatalf("system roots: CertRefused = %q, want the presented %q", got, pin)
	}
	if got := CertRefused(ctx, addr, trust.Config{Mode: trust.Pin, Pins: []string{pin}}, EdgeALPN); got != "" {
		t.Fatalf("pinned to its own key: CertRefused = %q, want \"\"", got)
	}
	if !PinnedInChain(ctx, addr, trust.Config{Mode: trust.Pin, Pins: []string{pin}}, EdgeALPN) {
		t.Fatal("PinnedInChain: its own pin did not match")
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	down := ln.Addr().String()
	ln.Close()
	if got := CertRefused(ctx, down, trust.Config{Mode: trust.Pin, Pins: []string{other}}, EdgeALPN); got != "" {
		t.Fatalf("nobody listening: CertRefused = %q, want \"\" (the network, not the certificate)", got)
	}
}
