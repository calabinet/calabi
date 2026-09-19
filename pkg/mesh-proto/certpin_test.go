package meshproto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func selfSigned(t *testing.T, key *ecdsa.PrivateKey, serial int64) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "pin-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The pin is the hash of the public key, not of the certificate: re-issuing for
// the same key must keep it, and it must be the number openssl's
// "-pubkey | pkey -outform der | sha256sum" recipe gives.
func TestCertPinHashesThePublicKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a, b := selfSigned(t, key, 1), selfSigned(t, key, 2)
	if CertPin(a) != CertPin(b) {
		t.Fatalf("same key, different pins: %s vs %s", CertPin(a), CertPin(b))
	}
	sum := sha256.Sum256(a.RawSubjectPublicKeyInfo)
	if want := "sha256:" + hex.EncodeToString(sum[:]); CertPin(a) != want {
		t.Fatalf("CertPin = %s, want %s", CertPin(a), want)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if CertPin(selfSigned(t, other, 1)) == CertPin(a) {
		t.Fatal("different keys, same pin")
	}
}

func TestParseCertPinAcceptsWhatPeopleType(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pin := CertPin(selfSigned(t, key, 1))
	digits := strings.TrimPrefix(pin, "sha256:")
	var grouped []string
	for i := 0; i < len(digits); i += 2 {
		grouped = append(grouped, strings.ToUpper(digits[i:i+2]))
	}
	for _, in := range []string{
		pin,
		digits,
		"SHA256:" + strings.ToUpper(digits),
		"  " + pin + "\n",
		strings.Join(grouped, ":"),
		strings.Join(grouped, " "),
	} {
		got, err := ParseCertPin(in)
		if err != nil || got != pin {
			t.Errorf("ParseCertPin(%q) = %q, %v; want %q", in, got, err, pin)
		}
	}
	for _, bad := range []string{"", "sha256:", digits[:63], digits + "0", strings.Replace(digits, digits[:1], "z", 1)} {
		if got, err := ParseCertPin(bad); err == nil {
			t.Errorf("ParseCertPin(%q) = %q, want an error", bad, got)
		}
	}
}
