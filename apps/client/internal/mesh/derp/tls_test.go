package derp

// A relay link over real TLS, against the real relay hub (pkg/relay), behind a
// listener that opens connections the way calabi-edge does
// (apps/calabi-edge/cmd/calabi-edge/relaytls.go): the first byte decides, TLS
// is 1.3 with the relay's protocol name, and the hub gets the binding of the
// certificate THIS handshake served. The client checks the certificate through
// internal/trust, as the relay pool does.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/trust"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/relay"
)

// selfSignedRelayCert is the kind of certificate a relay with no other falls
// back to: self-signed, for 127.0.0.1, trusted by its fingerprint.
func selfSignedRelayCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "calabi-edge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// tlsRelay is the real hub behind a relay-style listener. plaintext counts the
// connections that did NOT open with TLS: a client that fell back would show up
// there.
type tlsRelay struct {
	hub       *relay.Hub
	addr      string
	plaintext atomic.Int64
}

func startTLSRelay(t *testing.T, cert tls.Certificate, alpn string, auth relay.AuthConfig) *tlsRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	r := &tlsRelay{hub: relay.NewHub(slog.New(slog.NewTextHandler(io.Discard, nil)), auth), addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.open(conn, cert, alpn)
		}
	}()
	return r
}

func (r *tlsRelay) open(conn net.Conn, cert tls.Certificate, alpn string) {
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil || first[0] != 0x16 {
		r.plaintext.Add(1)
		_ = conn.Close()
		return
	}
	var served *tls.Certificate
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c := cert
			served = &c
			return served, nil
		},
	}
	if alpn != "" {
		cfg.NextProtos = []string{alpn}
	}
	tc := tls.Server(&replayed{Conn: conn, head: first[:]}, cfg)
	if err := tc.Handshake(); err != nil {
		_ = conn.Close()
		return
	}
	r.hub.ServeBound(tc, meshproto.DERPBindingOf(served.Leaf))
}

type replayed struct {
	net.Conn
	head []byte
}

func (c *replayed) Read(p []byte) (int, error) {
	if len(c.head) > 0 {
		n := copy(p, c.head)
		c.head = c.head[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// relayAuth is a relay requiring grants from one coordinator, and a function
// that signs one for a node.
func relayAuth(t *testing.T) (relay.AuthConfig, func(meshproto.NodeKey) []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(k meshproto.NodeKey) []byte {
		g, err := meshproto.SignRelayGrant(priv, meshproto.RelayGrant{
			Node: k, Meshnet: 7, Scope: meshproto.RelayScopeAll, Expiry: time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	return relay.AuthConfig{Require: true, CoordPub: pub, Kind: meshproto.RelayKindPlatform}, sign
}

func pinned(t *testing.T, addr string, pins ...string) *tls.Config {
	t.Helper()
	cfg, err := trust.Config{Mode: trust.Pin, Pins: pins}.TLS(addr)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func waitConnected(t *testing.T, h *relay.Hub, k meshproto.NodeKey) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !h.Connected(k) {
		if time.Now().After(deadline) {
			t.Fatal("the relay never admitted the link")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The whole path: two nodes pin the relay's certificate, dial it over TLS, prove
// themselves with proofs bound to that certificate (a relay requiring grants
// admits nothing else on a TLS link), and a packet crosses from one to the other.
func TestTLSRelayRoundTripWithAPinnedCertificate(t *testing.T) {
	cert := selfSignedRelayCert(t)
	auth, sign := relayAuth(t)
	r := startTLSRelay(t, cert, meshproto.DERPALPN, auth)
	pin := meshproto.CertPin(cert.Leaf)

	keyA, privA := nodeKeys(t)
	keyB, privB := nodeKeys(t)
	got := make(chan []byte, 1)
	a, err := DialTLS(context.Background(), r.addr, pinned(t, r.addr, pin), keyA,
		Auth{Priv: privA, Grant: func() []byte { return sign(keyA) }}, nil, slog.Default())
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := DialTLS(context.Background(), r.addr, pinned(t, r.addr, pin), keyB,
		Auth{Priv: privB, Grant: func() []byte { return sign(keyB) }},
		func(src meshproto.NodeKey, ct []byte) {
			if src.Equal(keyA) {
				got <- append([]byte(nil), ct...)
			}
		}, slog.Default())
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	waitConnected(t, r.hub, keyA)
	waitConnected(t, r.hub, keyB)

	if err := a.Send(keyB, []byte("wg-ciphertext")); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case ct := <-got:
		if string(ct) != "wg-ciphertext" {
			t.Fatalf("B got %q", ct)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the packet never crossed the relay")
	}
	if n := r.plaintext.Load(); n != 0 {
		t.Fatalf("%d plaintext connection(s) reached the relay", n)
	}
}

// A relay presenting a certificate the pin does not name is refused at the
// handshake, with the fingerprint it did present in the error — and nothing
// falls back to plaintext: the relay sees no connection it could serve.
func TestTLSRelayWithAnotherCertificateIsRefusedWithoutFallback(t *testing.T) {
	cert := selfSignedRelayCert(t)
	auth, sign := relayAuth(t)
	r := startTLSRelay(t, cert, meshproto.DERPALPN, auth)
	other := selfSignedRelayCert(t)

	self, priv := nodeKeys(t)
	_, err := DialTLS(context.Background(), r.addr, pinned(t, r.addr, meshproto.CertPin(other.Leaf)), self,
		Auth{Priv: priv, Grant: func() []byte { return sign(self) }}, nil, slog.Default())
	var mismatch *trust.PinMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want a PinMismatchError", err)
	}
	if mismatch.Presented[0] != meshproto.CertPin(cert.Leaf) {
		t.Fatalf("Presented = %v, want the relay's own fingerprint", mismatch.Presented)
	}
	time.Sleep(100 * time.Millisecond)
	if r.hub.Connected(self) || r.plaintext.Load() != 0 {
		t.Fatalf("connected=%v plaintext=%d: the refused dial reached the relay anyway", r.hub.Connected(self), r.plaintext.Load())
	}
}

// A TLS server that is not a relay is refused rather than sent DERP frames: one
// that names another protocol (an edge's control listener says calabi/1), and
// one that names none at all — a server that ignores ALPN finishes the
// handshake, so only the client's own check stops it.
func TestTLSToSomethingThatIsNotARelayIsRefused(t *testing.T) {
	for _, alpn := range []string{"calabi/1", ""} {
		t.Run("alpn "+alpn, func(t *testing.T) {
			cert := selfSignedRelayCert(t)
			r := startTLSRelay(t, cert, alpn, relay.AuthConfig{})
			self, _ := nodeKeys(t)
			if _, err := DialTLS(context.Background(), r.addr, pinned(t, r.addr, meshproto.CertPin(cert.Leaf)), self, Auth{}, nil, slog.Default()); err == nil {
				t.Fatal("a server that does not speak the relay protocol was accepted as a relay")
			}
		})
	}
}
