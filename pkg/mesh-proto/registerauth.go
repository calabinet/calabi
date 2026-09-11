package meshproto

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"errors"

	"golang.org/x/crypto/nacl/box"
)

// Registration proof (mesh protocol v2): a node proves to the coordinator that it
// holds the private half of the node key it enrolls with.
//
// Why: an org credential names a meshnet, not a device. Before v2 "my org key +
// your node key" was accepted as YOUR device re-enrolling, and a node key is
// public - every peer reads it in its netmap - so any member of an org could take
// over a colleague's device record: rename it, swap its disco key, point its
// endpoints and relay home elsewhere (security audit 1-C, same-org residual).
//
// The exchange mirrors the relay handshake in derpauth.go:
//
//	coordinator -> node:  challenge   ephPub || nonce            (GetRegisterChallenge)
//	node -> coordinator:  proof       box(magic || node key || ephPub)
//
//	box sealed to   (coordinator ephemeral public, node private)
//	box opened with (claimed node public, coordinator ephemeral private)
//
// The coordinator picks ephPub and nonce fresh for every challenge and keeps each
// challenge for one registration only, so a recorded proof is useless later.
//
// The magic is DIFFERENT from the relay's on purpose. With a shared magic a proof
// would be the same box in both protocols, and an org member running a relay (org
// members can register self-hosted relays) could hand a colleague's node the
// challenge the coordinator gave HIM, collect the answer as a relay proof, and
// replay it to the coordinator as that colleague.
var registerProofMagic = [6]byte{'c', 'a', 'l', 'a', 'R', '1'}

const (
	// RegisterChallengeLen is the encoded challenge length.
	RegisterChallengeLen = KeyLen + DERPAuthNonceLen
	// registerProofPlaintextLen is magic + claimed key + ephemeral key.
	registerProofPlaintextLen = 6 + KeyLen + KeyLen
	// RegisterProofLen is the length of a sealed registration proof.
	RegisterProofLen = registerProofPlaintextLen + box.Overhead
)

// ErrRegisterProof is returned when a registration proof does not open, or opens
// to the wrong plaintext: the caller does not hold the key it claimed.
var ErrRegisterProof = errors.New("meshproto: registration proof rejected")

// RegisterChallenge is the coordinator's half: a fresh ephemeral public key and
// nonce, good for exactly one registration.
type RegisterChallenge struct {
	EphPub [KeyLen]byte
	Nonce  [DERPAuthNonceLen]byte
}

// NewRegisterChallenge generates a challenge and the ephemeral private key the
// coordinator keeps to open the proof. The private key never leaves the
// coordinator and is discarded with the challenge.
func NewRegisterChallenge() (ch RegisterChallenge, ephPriv [KeyLen]byte, err error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return ch, ephPriv, fmt.Errorf("meshproto: generate registration challenge key: %w", err)
	}
	if _, err := rand.Read(ch.Nonce[:]); err != nil {
		return ch, ephPriv, fmt.Errorf("meshproto: generate registration challenge nonce: %w", err)
	}
	ch.EphPub = *pub
	return ch, *priv, nil
}

// Encode renders the challenge for the wire.
func (c RegisterChallenge) Encode() []byte {
	out := make([]byte, 0, RegisterChallengeLen)
	out = append(out, c.EphPub[:]...)
	out = append(out, c.Nonce[:]...)
	return out
}

// ParseRegisterChallenge decodes a challenge.
func ParseRegisterChallenge(b []byte) (RegisterChallenge, error) {
	var c RegisterChallenge
	if len(b) != RegisterChallengeLen {
		return c, fmt.Errorf("meshproto: registration challenge length %d, want %d", len(b), RegisterChallengeLen)
	}
	copy(c.EphPub[:], b[:KeyLen])
	copy(c.Nonce[:], b[KeyLen:])
	return c, nil
}

// registerProofPlaintext is what the box carries, built identically on both
// sides so sealing and opening cannot drift apart.
func registerProofPlaintext(self NodeKey, ephPub [KeyLen]byte) []byte {
	out := make([]byte, 0, registerProofPlaintextLen)
	out = append(out, registerProofMagic[:]...)
	out = append(out, self[:]...)
	out = append(out, ephPub[:]...)
	return out
}

// SealRegisterProof answers a challenge with the node's private key.
func SealRegisterProof(ch RegisterChallenge, self NodeKey, priv [KeyLen]byte) []byte {
	return box.Seal(nil, registerProofPlaintext(self, ch.EphPub), &ch.Nonce, &ch.EphPub, &priv)
}

// OpenRegisterProof verifies a proof against the challenge the coordinator issued
// and the node key the registration claims. nil means exactly "the caller holds
// the private key for claimed"; whether it may enroll is the auth key's job.
func OpenRegisterProof(ch RegisterChallenge, ephPriv [KeyLen]byte, claimed NodeKey, proof []byte) error {
	if len(proof) != RegisterProofLen {
		return fmt.Errorf("%w: proof length %d, want %d", ErrRegisterProof, len(proof), RegisterProofLen)
	}
	pub := [KeyLen]byte(claimed)
	opened, ok := box.Open(nil, proof, &ch.Nonce, &pub, &ephPriv)
	if !ok {
		return ErrRegisterProof
	}
	// The box already authenticates the sender; re-checking the plaintext binds
	// the proof to THIS challenge, THIS claimed key and THIS protocol - which is
	// what keeps a relay proof for the same challenge from passing here.
	if !bytes.Equal(opened, registerProofPlaintext(claimed, ch.EphPub)) {
		return fmt.Errorf("%w: proof plaintext mismatch", ErrRegisterProof)
	}
	return nil
}
