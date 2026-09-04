package mesh

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// DiscoPrivateKey is the private half of a node's DISCO keypair (Curve25519),
// deliberately SEPARATE from the WireGuard node key: it authenticates the
// NAT-traversal (hole-punching) probes without ever touching the traffic key, so
// it can rotate aggressively. We generate a FRESH one per mesh session (like
// Tailscale) rather than persisting it — the public half is re-advertised to the
// coordinator on each (re)registration, so peers always learn the current one.
// The private half stays on the node; only Public() crosses the wire.
type DiscoPrivateKey [meshproto.KeyLen]byte

// GenerateDiscoKey returns a fresh random DISCO private key.
func GenerateDiscoKey() (DiscoPrivateKey, error) {
	var k DiscoPrivateKey
	if _, err := rand.Read(k[:]); err != nil {
		return DiscoPrivateKey{}, fmt.Errorf("mesh: generate disco key: %w", err)
	}
	return k, nil
}

// Public derives the DISCO public key advertised to peers via the coordinator
// (Peer.disco_key). X25519 clamps the scalar internally, matching how the DISCO
// box will derive the shared secret in the hole-punching exchange.
func (k DiscoPrivateKey) Public() meshproto.DiscoKey {
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return meshproto.DiscoKey{}
	}
	var out meshproto.DiscoKey
	copy(out[:], pub)
	return out
}

// IsZero reports whether the key is unset (the all-zero value).
func (k DiscoPrivateKey) IsZero() bool { return k == DiscoPrivateKey{} }
