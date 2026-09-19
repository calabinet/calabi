package meshproto

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// Certificate pins: how a client that does not trust a server's CA can still
// recognise the server.
//
// A pin is the SHA-256 of a certificate's SubjectPublicKeyInfo, written
// "sha256:" + 64 lowercase hex digits. The public key rather than the whole
// certificate, so a certificate re-issued for the same key keeps its pin. The
// coordinator prints it (`calabi-coord fingerprint`), invite links carry it, and
// the client compares against it — all through these two functions, so the
// three can never disagree on the format.
//
// The same number falls out of stock tooling, for anyone who wants to check:
//
//	openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der | sha256sum

// pinPrefix names the hash so the format can grow without ambiguity.
const pinPrefix = "sha256:"

// CertPin returns the pin for cert.
func CertPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return pinPrefix + hex.EncodeToString(sum[:])
}

// ParseCertPin normalises a pin a person typed or pasted: the "sha256:" prefix
// is optional and case-insensitive, and colons, spaces and dashes between the
// digits are ignored (fingerprints are usually shown grouped). The result is in
// CertPin's form.
func ParseCertPin(s string) (string, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	t = strings.TrimPrefix(t, pinPrefix)
	t = strings.NewReplacer(":", "", " ", "", "-", "").Replace(t)
	if len(t) != sha256.Size*2 {
		return "", fmt.Errorf("certificate pin %q: want 64 hex digits of a SHA-256, got %d characters", s, len(t))
	}
	if _, err := hex.DecodeString(t); err != nil {
		return "", fmt.Errorf("certificate pin %q: not hex", s)
	}
	return pinPrefix + t, nil
}
