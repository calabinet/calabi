// Package filetransfer implements opt-in file transfer over existing mesh TCP
// paths. It never creates a new relay transport, bypasses ACLs or grants quota.
package filetransfer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/netip"
	"strings"
	"time"
)

// Identity is a dedicated transfer identity, never a WireGuard key. NewIdentity
// is ephemeral; LoadIdentity persists the v1 user's separate TLS key.
type Identity struct {
	Certificate tls.Certificate
	Fingerprint string
	historyID   string
	directory   string
}

// HistoryID stays stable across explicit certificate/key maintenance. It is
// local bookkeeping only and must never be used as a TLS trust fingerprint.
func (i *Identity) HistoryID() string {
	if i.historyID != "" {
		return i.historyID
	}
	return i.Fingerprint
}

func NewIdentity() (*Identity, error) {
	return newIdentity(24 * time.Hour)
}

func newIdentity(lifetime time.Duration) (*Identity, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return identityWithKey(key, lifetime)
}

func identityWithKey(key ed25519.PrivateKey, lifetime time.Duration) (*Identity, error) {
	pub := key.Public().(ed25519.PublicKey)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Calabi file transfer"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(lifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(der)
	return &Identity{Certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, Fingerprint: hex.EncodeToString(h[:])}, nil
}

// Peer binds a manually verified certificate to one exact mesh device IP.
type Peer struct {
	IP          netip.Addr
	Fingerprint string
}

func (p Peer) Validate() error {
	if !p.IP.IsValid() || p.IP.IsUnspecified() || p.IP.IsMulticast() || p.IP.Zone() != "" {
		return errors.New("invalid peer IP")
	}
	b, err := hex.DecodeString(p.Fingerprint)
	if err != nil || len(b) != sha256.Size {
		return errors.New("fingerprint must be 64 hexadecimal characters")
	}
	return nil
}

func checkCertificate(cs tls.ConnectionState, fingerprint string) error {
	if len(cs.PeerCertificates) != 1 {
		return errors.New("exactly one pinned transfer certificate required")
	}
	cert := cs.PeerCertificates[0]
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("transfer certificate expired or not yet valid")
	}
	want, err := hex.DecodeString(fingerprint)
	if err != nil {
		return err
	}
	got := sha256.Sum256(cert.Raw)
	if subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return errors.New("transfer certificate fingerprint mismatch")
	}
	return nil
}

func (i *Identity) ClientTLS(peer Peer) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{i.Certificate},
		// Trust is the explicitly paired certificate, not the system CA store.
		InsecureSkipVerify: true, // checked by VerifyConnection, including resumption
		VerifyConnection:   func(cs tls.ConnectionState) error { return checkCertificate(cs, peer.Fingerprint) },
		NextProtos:         []string{"http/1.1"},
	}
}

func (i *Identity) ServerTLS(peer Peer) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{i.Certificate},
		ClientAuth:       tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error { return checkCertificate(cs, peer.Fingerprint) },
		NextProtos:       []string{"http/1.1"},
	}
}

func validName(name string) bool {
	if name == "" || len(name) > 255 || name == "." || name == ".." || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if r < 32 || r == 127 || strings.ContainsRune(`/\:`, r) {
			return false
		}
	}
	// Display names are never used as disk paths, including Windows device names.
	return true
}
