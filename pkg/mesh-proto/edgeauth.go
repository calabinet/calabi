package meshproto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// Edge authentication: a device proves to a self-hosted edge that it holds its
// node key, and hands it the coordinator's grant saying that key belongs to one
// of the coordinator's meshnets.
// The grant is the relay grant — one calabi-edge is both a relay and a tunnel
// edge — so the proof is what this file adds.
//
//	edge -> device:  challenge   ephPub || nonce                (HELLO_ACK)
//	device -> edge:  proof       box(magic || node key || ephPub) + grant  (AUTH)
//
// The edge picks the challenge fresh for every connection and uses it once, so
// a recorded proof opens nothing later. The grant alone proves nothing: it is a
// signed statement anyone who saw it could replay.
//
// Its own magic, for the reason registerauth.go gives: with a magic shared
// between protocols, whoever runs one party could hand a device the challenge
// another party gave him and pass the answer on as that device.
var edgeProofMagic = [6]byte{'c', 'a', 'l', 'a', 'E', '1'}

const (
	// EdgeChallengeLen is the encoded challenge length.
	EdgeChallengeLen = KeyLen + DERPAuthNonceLen
	// edgeProofPlaintextLen is magic + claimed key + ephemeral key.
	edgeProofPlaintextLen = 6 + KeyLen + KeyLen
	// EdgeProofLen is the length of a sealed edge proof.
	EdgeProofLen = edgeProofPlaintextLen + box.Overhead
)

// AwaitingApproval is the message GetEdgeAccess refuses a device with while its
// meshnet requires approving devices and nobody has approved it yet. The code is
// FailedPrecondition, which a device that signed out also gets; the message is
// how the device tells "wait" from "join again".
const AwaitingApproval = "this device is waiting for approval"

// ErrEdgeProof is returned when a proof does not open, or opens to the wrong
// plaintext: the device does not hold the key it claimed.
var ErrEdgeProof = errors.New("meshproto: edge proof rejected")

// EdgeChallenge is the edge's half: a fresh ephemeral public key and nonce,
// good for one connection.
type EdgeChallenge struct {
	EphPub [KeyLen]byte
	Nonce  [DERPAuthNonceLen]byte
}

// NewEdgeChallenge generates a challenge and the ephemeral private key the edge
// keeps, for this connection only, to open the proof.
func NewEdgeChallenge() (ch EdgeChallenge, ephPriv [KeyLen]byte, err error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return ch, ephPriv, fmt.Errorf("meshproto: generate edge challenge key: %w", err)
	}
	if _, err := rand.Read(ch.Nonce[:]); err != nil {
		return ch, ephPriv, fmt.Errorf("meshproto: generate edge challenge nonce: %w", err)
	}
	ch.EphPub = *pub
	return ch, *priv, nil
}

// Encode renders the challenge for the wire.
func (c EdgeChallenge) Encode() []byte {
	out := make([]byte, 0, EdgeChallengeLen)
	out = append(out, c.EphPub[:]...)
	out = append(out, c.Nonce[:]...)
	return out
}

// ParseEdgeChallenge decodes a challenge.
func ParseEdgeChallenge(b []byte) (EdgeChallenge, error) {
	var c EdgeChallenge
	if len(b) != EdgeChallengeLen {
		return c, fmt.Errorf("meshproto: edge challenge length %d, want %d", len(b), EdgeChallengeLen)
	}
	copy(c.EphPub[:], b[:KeyLen])
	copy(c.Nonce[:], b[KeyLen:])
	return c, nil
}

func edgeProofPlaintext(self NodeKey, ephPub [KeyLen]byte) []byte {
	out := make([]byte, 0, edgeProofPlaintextLen)
	out = append(out, edgeProofMagic[:]...)
	out = append(out, self[:]...)
	out = append(out, ephPub[:]...)
	return out
}

// SealEdgeProof answers a challenge with the device's node private key.
func SealEdgeProof(ch EdgeChallenge, self NodeKey, priv [KeyLen]byte) []byte {
	return box.Seal(nil, edgeProofPlaintext(self, ch.EphPub), &ch.Nonce, &ch.EphPub, &priv)
}

// OpenEdgeProof verifies a proof against the challenge the edge sent and the
// node key the grant names. nil means exactly "the device holds the private key
// for claimed"; whether it may serve tunnels is the grant's business.
func OpenEdgeProof(ch EdgeChallenge, ephPriv [KeyLen]byte, claimed NodeKey, proof []byte) error {
	if len(proof) != EdgeProofLen {
		return fmt.Errorf("%w: proof length %d, want %d", ErrEdgeProof, len(proof), EdgeProofLen)
	}
	pub := [KeyLen]byte(claimed)
	opened, ok := box.Open(nil, proof, &ch.Nonce, &pub, &ephPriv)
	if !ok {
		return ErrEdgeProof
	}
	if !bytes.Equal(opened, edgeProofPlaintext(claimed, ch.EphPub)) {
		return fmt.Errorf("%w: proof plaintext mismatch", ErrEdgeProof)
	}
	return nil
}
