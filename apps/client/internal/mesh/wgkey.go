package mesh

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// PrivateKey is a node's WireGuard private key (Curve25519). It stays on the
// node — never sent to the coordinator or a relay. The matching public key is
// the meshproto.NodeKey used for enrollment and relay routing.
type PrivateKey [meshproto.KeyLen]byte

// GenerateKey returns a fresh random private key. WireGuard clamps the scalar
// internally, so the raw random bytes are a valid private key as-is.
func GenerateKey() (PrivateKey, error) {
	var k PrivateKey
	if _, err := rand.Read(k[:]); err != nil {
		return PrivateKey{}, fmt.Errorf("mesh: generate key: %w", err)
	}
	return k, nil
}

// Public derives the public key (X25519 clamps as part of the scalar mult, so
// this matches WireGuard's own derivation from the same private bytes).
func (k PrivateKey) Public() meshproto.NodeKey {
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		// X25519 only errors on a low-order/all-zero result; a random key never
		// hits it. Return zero so callers can detect the (practically impossible) case.
		return meshproto.NodeKey{}
	}
	var out meshproto.NodeKey
	copy(out[:], pub)
	return out
}

// Hex encodes the private key as the 64-char hex string the WireGuard UAPI wants.
func (k PrivateKey) Hex() string { return hex.EncodeToString(k[:]) }

// LoadOrCreateKey reads a private key from path, or generates + persists one if
// path doesn't exist. The file is written 0600 (owner-only). This gives the node
// a STABLE identity across restarts — its NodeKey stays registered with the
// coordinator.
func LoadOrCreateKey(path string) (PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		return parseKeyFile(raw)
	}
	if !os.IsNotExist(err) {
		return PrivateKey{}, fmt.Errorf("mesh: read key %s: %w", path, err)
	}
	k, err := GenerateKey()
	if err != nil {
		return PrivateKey{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return PrivateKey{}, fmt.Errorf("mesh: mkdir for key: %w", err)
	}
	if err := os.WriteFile(path, []byte(k.Hex()+"\n"), 0o600); err != nil {
		return PrivateKey{}, fmt.Errorf("mesh: write key %s: %w", path, err)
	}
	return k, nil
}

func parseKeyFile(raw []byte) (PrivateKey, error) {
	s := ""
	for _, b := range raw {
		if b == '\n' || b == '\r' || b == ' ' || b == '\t' {
			break
		}
		s += string(b)
	}
	dec, err := hex.DecodeString(s)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("mesh: key file not hex: %w", err)
	}
	if len(dec) != meshproto.KeyLen {
		return PrivateKey{}, fmt.Errorf("mesh: key file wrong length %d", len(dec))
	}
	var k PrivateKey
	copy(k[:], dec)
	return k, nil
}
