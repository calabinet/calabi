package meshproto

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeyLen is the length in bytes of a Curve25519 public key — the key type
// WireGuard (node traffic) and the DISCO layer (NAT traversal) both use.
const KeyLen = 32

// NodeKey is a node's long-lived WireGuard public key. It identifies the node
// on the mesh: peers encrypt to it, DERP relays route by it. The matching
// private key never leaves the node (not the coordinator, not a relay).
type NodeKey [KeyLen]byte

// DiscoKey is a node's short-lived discovery public key, used to authenticate
// the NAT-traversal (hole-punching) probes. It is deliberately SEPARATE from
// NodeKey so endpoint discovery can be exercised without exposing the traffic
// key. Rotated more aggressively than NodeKey. (Used from MESH.4 onward; the
// type is defined now so the coordination contract is stable.)
type DiscoKey [KeyLen]byte

// ErrBadKeyLen is returned when parsing a key of the wrong length.
var ErrBadKeyLen = errors.New("meshproto: key must be 32 bytes")

// keyText renders a raw 32-byte key as standard base64 (the WireGuard
// convention), so keys copy-paste cleanly into configs and logs.
func keyText(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func parseKey(s string, dst []byte) error {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("meshproto: parse key: %w", err)
	}
	if len(raw) != KeyLen {
		return ErrBadKeyLen
	}
	copy(dst, raw)
	return nil
}

// IsZero reports whether the key is the all-zero value (unset).
func (k NodeKey) IsZero() bool { return k == NodeKey{} }

// Equal is a constant-time comparison, so key checks don't leak timing.
func (k NodeKey) Equal(o NodeKey) bool { return subtle.ConstantTimeCompare(k[:], o[:]) == 1 }

func (k NodeKey) String() string            { return keyText(k[:]) }
func (k NodeKey) MarshalText() ([]byte, error) { return []byte(keyText(k[:])), nil }
func (k *NodeKey) UnmarshalText(b []byte) error { return parseKey(string(b), k[:]) }

// ParseNodeKey decodes a base64 (WireGuard-style) public key.
func ParseNodeKey(s string) (NodeKey, error) {
	var k NodeKey
	return k, parseKey(s, k[:])
}

func (k DiscoKey) IsZero() bool                  { return k == DiscoKey{} }
func (k DiscoKey) String() string                { return keyText(k[:]) }
func (k DiscoKey) MarshalText() ([]byte, error)  { return []byte(keyText(k[:])), nil }
func (k *DiscoKey) UnmarshalText(b []byte) error { return parseKey(string(b), k[:]) }

// ParseDiscoKey decodes a base64 discovery public key.
func ParseDiscoKey(s string) (DiscoKey, error) {
	var k DiscoKey
	return k, parseKey(s, k[:])
}
