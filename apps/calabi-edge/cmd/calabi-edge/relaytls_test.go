package main

// The relay port speaks TLS and plaintext side by side (relaytls.go). These
// drive runRelay over a real loopback listener: a device opens TLS or not by
// its first byte, and on TLS answers challenges with a proof bound to the
// certificate its handshake was shown (meshproto SealBoundDERPAuthProof).

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/config"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// relayCert makes a certificate of the kind resolveControlCert generates.
func relayCert(t *testing.T) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := newControlCertPEM([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func serving(c tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &c, nil }
}

// authedRelay is a relay that checks grants against coord, with no platform in
// the picture: a standalone node's, or one whose config names the key.
func authedRelay(coord testSigner) config.MeshService {
	rc := relayOnlyNoSTUN
	rc.RequireAuth = true
	rc.CoordPubKey = base64.StdEncoding.EncodeToString(coord.pub)
	return rc
}

// dialTLS opens TLS to the relay the way a device does — TLS 1.3, the relay's
// protocol name — and speaks the relay protocol over it. Its answers are bound
// to bindTo, or, when that is nil, to the certificate the handshake presented,
// which is what an honest device does. The certificate is not checked: which
// certificates a device trusts is the client's business, tested there.
func (d testDevice) dialTLS(t *testing.T, addr string, grant []byte, bindTo *meshproto.DERPBinding) (challenged, admitted bool, presented *x509.Certificate) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // the relay's side is under test
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{meshproto.DERPALPN},
	})
	if err != nil {
		t.Fatalf("TLS to the relay: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	presented = conn.ConnectionState().PeerCertificates[0]
	binding := meshproto.DERPBindingOf(presented)
	if bindTo != nil {
		binding = *bindTo
	}
	challenged, admitted = d.speak(t, conn, func(ch meshproto.DERPAuthChallenge) ([]byte, error) {
		return meshproto.SealBoundDERPAuthProof(ch, d.key, d.priv, grant, binding)
	})
	return challenged, admitted, presented
}

// One port, both protocols: an old device speaking plaintext and a new one
// speaking TLS are both served, each proving itself the way its transport
// requires.
func TestRelayPortServesTLSAndPlaintextSideBySide(t *testing.T) {
	coord := newSigner(t)
	cert := relayCert(t)
	addr := listeningWithin(t, startRelay(t, authedRelay(coord), relayWiring{cert: serving(cert)}), 2*time.Second)

	oldDevice, newDevice := newDevice(t), newDevice(t)
	if challenged, admitted, _ := oldDevice.dial(t, addr, coord.grant(t, oldDevice, testOrg)); !challenged || !admitted {
		t.Fatalf("plaintext device: challenged=%v admitted=%v, want both", challenged, admitted)
	}
	challenged, admitted, presented := newDevice.dialTLS(t, addr, coord.grant(t, newDevice, testOrg), nil)
	if !challenged || !admitted {
		t.Fatalf("TLS device: challenged=%v admitted=%v, want both", challenged, admitted)
	}
	if meshproto.CertPin(presented) != meshproto.CertPin(cert.Leaf) {
		t.Fatalf("the relay presented %s, want the node's control certificate %s", meshproto.CertPin(presented), meshproto.CertPin(cert.Leaf))
	}
}

// End to end: an answer bound to some other relay's certificate —
// what a malicious relay collects from a device connected to it — does not get
// in over this relay's TLS, even with a valid grant.
func TestRelayTLSRefusesAProofBoundToAnotherRelay(t *testing.T) {
	coord := newSigner(t)
	addr := listeningWithin(t, startRelay(t, authedRelay(coord), relayWiring{cert: serving(relayCert(t))}), 2*time.Second)

	elsewhere := meshproto.DERPBindingOf(relayCert(t).Leaf)
	d := newDevice(t)
	if challenged, admitted, _ := d.dialTLS(t, addr, coord.grant(t, d, testOrg), &elsewhere); !challenged || admitted {
		t.Fatalf("challenged=%v admitted=%v, want challenged and refused", challenged, admitted)
	}
}

// flipping serves first for exactly one handshake and then — as if a renewal
// landed the moment it was handed out — next.
type flipping struct {
	mu          sync.Mutex
	first, next tls.Certificate
	flipped     bool
}

func (f *flipping) certificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.flipped {
		c := f.next
		return &c, nil
	}
	f.flipped = true
	c := f.first
	return &c, nil
}

// The certificate is re-read when its files change (fileCert), so a renewal can
// land between a device's handshake and its proof. The device binds to what it
// was shown; the relay must check against the same certificate — the one THIS
// handshake served — and not against whatever it would serve now.
func TestRelayTLSBindsTheCertificateThisHandshakeServed(t *testing.T) {
	coord := newSigner(t)
	src := &flipping{first: relayCert(t), next: relayCert(t)}
	addr := listeningWithin(t, startRelay(t, authedRelay(coord), relayWiring{cert: src.certificate}), 2*time.Second)

	before := newDevice(t)
	challenged, admitted, shown := before.dialTLS(t, addr, coord.grant(t, before, testOrg), nil)
	if meshproto.CertPin(shown) != meshproto.CertPin(src.first.Leaf) {
		t.Fatal("setup: the first handshake was not served the first certificate")
	}
	if !challenged || !admitted {
		t.Fatalf("device shown the certificate before the renewal: challenged=%v admitted=%v, want both", challenged, admitted)
	}
	after := newDevice(t)
	_, admitted, shown = after.dialTLS(t, addr, coord.grant(t, after, testOrg), nil)
	if meshproto.CertPin(shown) != meshproto.CertPin(src.next.Leaf) || !admitted {
		t.Fatalf("device after the renewal: admitted=%v shown %s, want admitted on the renewed certificate", admitted, meshproto.CertPin(shown))
	}
}

// require_tls refuses the plaintext protocol outright — no challenge, no
// frames — and leaves TLS alone.
func TestRelayRequireTLSRefusesPlaintext(t *testing.T) {
	coord := newSigner(t)
	rc := authedRelay(coord)
	rc.RequireTLS = true
	addr := listeningWithin(t, startRelay(t, rc, relayWiring{cert: serving(relayCert(t))}), 2*time.Second)

	d := newDevice(t)
	if challenged, admitted, _ := d.dial(t, addr, coord.grant(t, d, testOrg)); challenged || admitted {
		t.Fatalf("plaintext device: challenged=%v admitted=%v, want refused before a challenge", challenged, admitted)
	}
	if _, admitted, _ := d.dialTLS(t, addr, coord.grant(t, d, testOrg), nil); !admitted {
		t.Fatal("TLS device refused with require_tls")
	}
}

// TLS 1.3 only, and only for the relay protocol: a device that offers TLS 1.2
// at most, or another protocol name (the control listener's), fails the
// handshake instead of being served.
func TestRelayTLSIsTLS13ForTheRelayProtocolOnly(t *testing.T) {
	addr := listeningWithin(t, startRelay(t, relayOnlyNoSTUN, relayWiring{cert: serving(relayCert(t))}), 2*time.Second)
	for _, tc := range []struct {
		name string
		cfg  *tls.Config
	}{
		{"TLS 1.2", &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, NextProtos: []string{meshproto.DERPALPN}}}, //nolint:gosec
		{"another protocol", &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"calabi/1"}}},                              //nolint:gosec
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, tc.cfg)
			if err == nil {
				_ = conn.Close()
				t.Fatal("handshake succeeded")
			}
		})
	}
}

// A connection that sends nothing is cut off rather than held forever.
func TestRelayCutsOffAConnectionThatSendsNothing(t *testing.T) {
	orig := relayOpenTimeout
	relayOpenTimeout = 200 * time.Millisecond
	t.Cleanup(func() { relayOpenTimeout = orig })
	addr := listeningWithin(t, startRelay(t, relayOnlyNoSTUN, relayWiring{cert: serving(relayCert(t))}), 2*time.Second)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if !waitClosed(conn, 3*time.Second) {
		t.Fatal("a silent connection was still open after the open timeout")
	}
}
