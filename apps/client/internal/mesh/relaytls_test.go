package mesh

import (
	"context"
	"crypto/ecdsa"
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
	"sync"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"github.com/calabinet/calabi/pkg/relay"
)

// A relay the map marks TLS is reached over TLS and nothing else (relaytls.go).
// These drive the relay pool against the real relay hub behind a listener that
// tells the two protocols apart by the first byte, as calabi-edge does, and
// count which one each connection used.

func relayCertForTest(t *testing.T) tls.Certificate {
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
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

type sniffingRelay struct {
	addr string
	hub  *relay.Hub

	mu             sync.Mutex
	plaintext, tls int
}

func startSniffingRelay(t *testing.T, cert tls.Certificate) *sniffingRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	r := &sniffingRelay{addr: ln.Addr().String(), hub: relay.NewHub(slog.New(slog.NewTextHandler(io.Discard, nil)), relay.AuthConfig{})}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.open(conn, cert)
		}
	}()
	return r
}

func (r *sniffingRelay) open(conn net.Conn, cert tls.Certificate) {
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		_ = conn.Close()
		return
	}
	link := &firstByteConn{Conn: conn, head: first[:]}
	if first[0] != 0x16 {
		r.count(&r.plaintext)
		r.hub.Serve(link)
		return
	}
	tc := tls.Server(link, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{meshproto.DERPALPN},
		Certificates: []tls.Certificate{cert}})
	if err := tc.Handshake(); err != nil {
		_ = conn.Close()
		return
	}
	r.count(&r.tls)
	r.hub.ServeBound(tc, meshproto.DERPBindingOf(cert.Leaf))
}

func (r *sniffingRelay) count(n *int) {
	r.mu.Lock()
	*n++
	r.mu.Unlock()
}

func (r *sniffingRelay) counts() (plaintext, tlsN int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.plaintext, r.tls
}

type firstByteConn struct {
	net.Conn
	head []byte
}

func (c *firstByteConn) Read(p []byte) (int, error) {
	if len(c.head) > 0 {
		n := copy(p, c.head)
		c.head = c.head[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func quietPool(t *testing.T) *relayPool {
	t.Helper()
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Sweeps an hour apart: nothing here may be re-dialed behind the test's back.
	p := newRelayPoolTimed(priv.Public(), [meshproto.KeyLen]byte(priv), nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour, time.Hour)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// Which trusts a relay map entry may name, and which this node can apply. The
// CA compiled into the client is for calabi.net only.
func TestRelayTLSConfigTakesOnlyTrustsItCanApply(t *testing.T) {
	pin := meshproto.CertPin(relayCertForTest(t).Leaf)
	for _, tc := range []struct {
		name     string
		tls      RelayTLS
		platform bool
		ok       bool
	}{
		{"platform, signed in to calabi.net", RelayTLS{Trust: meshproto.RelayTrustPlatform}, true, true},
		{"platform, signed in to a self-hosted server", RelayTLS{Trust: meshproto.RelayTrustPlatform}, false, false},
		{"system", RelayTLS{Trust: meshproto.RelayTrustSystem}, false, true},
		{"pin", RelayTLS{Trust: meshproto.RelayTrustPin, Pins: []string{pin}}, false, true},
		{"pin with no fingerprint", RelayTLS{Trust: meshproto.RelayTrustPin}, false, false},
		{"a trust this client does not know", RelayTLS{Trust: "dane"}, true, false},
		{"TLS with no trust named", RelayTLS{Trust: relayTrustUnnamed}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := relayTLSConfig("127.0.0.1:3340", tc.tls, tc.platform)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err == nil && cfg == nil {
				t.Fatal("no TLS config for a relay marked TLS")
			}
		})
	}
}

// An entry that says TLS but names no trust is still TLS: read as plaintext, a
// map that lost a field in transit would downgrade the relay.
func TestARelayMapTLSEntryWithoutATrustIsNotPlaintext(t *testing.T) {
	m := derpFromProto(&meshpb.DERPMap{Regions: []*meshpb.DERPRegion{{Code: "lax", Nodes: []*meshpb.DERPNode{
		{HostName: "relay.example", DerpPort: 3340, Tls: &meshpb.DERPNodeTLS{}},
		{HostName: "old.example", DerpPort: 3340},
	}}}})
	byAddr := relayTLSByAddr(m)
	if got := byAddr["relay.example:3340"]; !got.Enabled() {
		t.Fatalf("TLS entry with no trust read as %+v", got)
	}
	if _, ok := byAddr["old.example:3340"]; ok {
		t.Fatal("a relay with no TLS entry was marked TLS")
	}
}

// The bootstrap link is dialed before the first netmap, in plaintext. Once the
// map marks that relay TLS the link is replaced by a TLS one — kept, it would
// go on carrying the device's metadata in the clear and answering challenges
// with a proof that names no relay.
func TestRelayPoolReplacesAPlaintextLinkOnceTheMapMarksTheRelayTLS(t *testing.T) {
	cert := relayCertForTest(t)
	r := startSniffingRelay(t, cert)
	p := quietPool(t)

	if err := p.DialHome(context.Background(), r.addr); err != nil {
		t.Fatalf("bootstrap dial: %v", err)
	}
	waitAdmitted(t, p, r.addr)
	if plain, tlsN := r.counts(); plain != 1 || tlsN != 0 {
		t.Fatalf("bootstrap: plaintext=%d tls=%d, want one plaintext link", plain, tlsN)
	}

	p.SetTransports(map[string]RelayTLS{r.addr: {Trust: meshproto.RelayTrustPin, Pins: []string{meshproto.CertPin(cert.Leaf)}}}, false)
	deadline := time.Now().Add(3 * time.Second)
	for {
		p.mu.Lock()
		via, c := p.via[r.addr], p.clients[r.addr]
		p.mu.Unlock()
		if _, tlsN := r.counts(); tlsN == 1 && c != nil && via.Enabled() && c.IsReady() {
			break
		}
		if time.Now().After(deadline) {
			plain, tlsN := r.counts()
			t.Fatalf("the home link was not replaced by a TLS one: plaintext=%d tls=%d via=%+v", plain, tlsN, via)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The same map again replaces nothing.
	p.SetTransports(map[string]RelayTLS{r.addr: {Trust: meshproto.RelayTrustPin, Pins: []string{meshproto.CertPin(cert.Leaf)}}}, false)
	time.Sleep(100 * time.Millisecond)
	if plain, tlsN := r.counts(); plain != 1 || tlsN != 1 {
		t.Fatalf("an unchanged map re-dialed: plaintext=%d tls=%d", plain, tlsN)
	}
}

// A relay marked TLS whose certificate fails the check is not reached at all:
// no plaintext attempt follows the failed handshake.
func TestRelayPoolNeverFallsBackToPlaintext(t *testing.T) {
	r := startSniffingRelay(t, relayCertForTest(t))
	for _, tc := range []struct {
		name     string
		tls      RelayTLS
		platform bool
	}{
		{"the certificate does not match the pin", RelayTLS{Trust: meshproto.RelayTrustPin, Pins: []string{meshproto.CertPin(relayCertForTest(t).Leaf)}}, false},
		{"calabi.net's CA asked of a self-hosted device", RelayTLS{Trust: meshproto.RelayTrustPlatform}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := quietPool(t)
			p.SetTransports(map[string]RelayTLS{r.addr: tc.tls}, tc.platform)
			err := p.DialHome(context.Background(), r.addr)
			if err == nil {
				t.Fatal("the dial succeeded")
			}
			if tc.tls.Trust == meshproto.RelayTrustPlatform && !errors.Is(err, errPlatformTrustElsewhere) {
				t.Fatalf("err = %v, want errPlatformTrustElsewhere", err)
			}
			time.Sleep(100 * time.Millisecond)
			if plain, tlsN := r.counts(); plain != 0 || tlsN != 0 {
				t.Fatalf("plaintext=%d tls=%d: something reached the relay", plain, tlsN)
			}
		})
	}
}
