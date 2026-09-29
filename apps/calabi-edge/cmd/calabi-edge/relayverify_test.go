package main

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

	bffedge "github.com/calabinet/calabi/pkg/edge-proto/edgepb"
)

// A node tells the platform its relay speaks TLS only when a device checking
// the certificate the way it checks the node's :7443 — the platform CA and the
// host name, as a server certificate — would accept it. A device told TLS never
// falls back, so every doubt is a "no".

type edgeCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	file string
}

func newEdgeCA(t *testing.T) edgeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "calabi edge CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	file := filepath.Join(t.TempDir(), "edge-ca.crt")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return edgeCA{cert: cert, key: key, file: file}
}

// leaf is what cert-svc issues a node: signed by the edge CA, client auth, and —
// when the node's public address was given — server auth plus that address.
func (ca edgeCA) leaf(t *testing.T, ip string, serverAuth bool, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "edge-1000400000-ap-tokyo"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if serverAuth {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		tmpl.IPAddresses = []net.IP{net.ParseIP(ip)}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestRelayTLSCheckSaysYesOnlyToWhatADeviceWouldAccept(t *testing.T) {
	ca := newEdgeCA(t)
	later := time.Now().Add(24 * time.Hour)
	for _, tc := range []struct {
		name   string
		cert   tls.Certificate
		host   string
		caFile string
		want   bool
	}{
		{"the node's own leaf, issued with its public address", ca.leaf(t, "203.0.113.9", true, later), "203.0.113.9", ca.file, true},
		{"issued for another address", ca.leaf(t, "198.51.100.4", true, later), "203.0.113.9", ca.file, false},
		{"issued without the public address (client auth only)", ca.leaf(t, "", false, later), "203.0.113.9", ca.file, false},
		{"self-signed fallback", relayCert(t), "127.0.0.1", ca.file, false},
		{"expired", ca.leaf(t, "203.0.113.9", true, time.Now().Add(-time.Minute)), "203.0.113.9", ca.file, false},
		{"no CA file to check against", ca.leaf(t, "203.0.113.9", true, later), "203.0.113.9", "", false},
		{"a CA file that is not there", ca.leaf(t, "203.0.113.9", true, later), "203.0.113.9", filepath.Join(t.TempDir(), "missing.crt"), false},
		{"another CA", ca.leaf(t, "203.0.113.9", true, later), "203.0.113.9", newEdgeCA(t).file, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &relayTLSCheck{cert: serving(tc.cert), caFile: tc.caFile, host: tc.host, logger: quietLog()}
			if got := c.ok(); got != tc.want {
				t.Fatalf("ok = %v, want %v (verify: %v)", got, tc.want, c.verify())
			}
		})
	}
}

// The answer follows the certificate the relay serves NOW: a node whose
// certificate is re-issued with its public address starts reporting TLS at its
// next heartbeat, without a restart — and one that loses it stops.
func TestRelayTLSCheckFollowsTheServedCertificate(t *testing.T) {
	ca := newEdgeCA(t)
	serves := ca.leaf(t, "", false, time.Now().Add(time.Hour))
	c := &relayTLSCheck{
		cert:   func(*tls.ClientHelloInfo) (*tls.Certificate, error) { s := serves; return &s, nil },
		caFile: ca.file, host: "203.0.113.9", logger: quietLog(),
	}
	if c.ok() {
		t.Fatal("a client-auth-only certificate passed")
	}
	serves = ca.leaf(t, "203.0.113.9", true, time.Now().Add(time.Hour))
	if !c.ok() {
		t.Fatalf("the re-issued certificate did not pass: %v", c.verify())
	}
}

// Each relay heartbeat carries this heartbeat's answer, and only that.
func TestWithRelayTLSKeepsTheRelayAndSetsTheAnswer(t *testing.T) {
	req := &bffedge.RegisterRelayRequest{Label: "tokyo", Host: "203.0.113.9", DerpPort: 3340, StunPort: 3478}
	for _, want := range []bool{true, false} {
		got := withRelayTLS(req, want)
		if got.GetTls() != want || got.GetLabel() != "tokyo" || got.GetHost() != "203.0.113.9" ||
			got.GetDerpPort() != 3340 || got.GetStunPort() != 3478 {
			t.Fatalf("withRelayTLS(%v) = %v", want, got)
		}
	}
	if req.GetTls() {
		t.Fatal("the template request was changed")
	}
}
