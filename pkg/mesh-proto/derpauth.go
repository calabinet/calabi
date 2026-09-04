package meshproto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// DERP relay authentication (R0′) — the handshake that turns ClientInfo from a
// claim into a verified identity.
//
// The problem it fixes: a relay used to index its clients by the node key in
// ClientInfo, with no proof attached, and a reconnect with the same key evicted
// the older link. A node key is public — every peer sees it in its netmap — so
// anyone who knew one could knock that node off the relay and take over its
// inbound. That is a persistent denial of service plus ciphertext and metadata
// takeover, and it applies to the platform's relays as they run today.
//
// The exchange (relay speaks first, right after ClientInfo):
//
//	relay -> node:  AuthChallenge  ephPub || nonce
//	node  -> relay: AuthProof      grant || box(proof plaintext)
//
//	proof plaintext = magic || claimed node key || ephPub
//	box sealed to   (relay ephemeral public, node private)
//	box opened with (claimed node public, relay ephemeral private)
//
// Opening the box proves the sender holds the private half of the key it
// claimed: only that key (or the relay's own ephemeral key) can produce a box
// that opens this way. The relay picks ephPub and nonce fresh per connection,
// so a recorded proof is useless on any other connection.
//
// The grant travels in the same frame because the two answer different
// questions and BOTH are needed — see relaygrant.go.
//
// Compatibility, in both directions, deliberately:
//
//   - old node + new relay: the node never answers, the relay times out and
//     closes. That is the intended outcome, which is why relays gate the whole
//     requirement behind an explicit switch during rollout.
//   - new node + old relay: the challenge never arrives. The node must NOT wait
//     for one — it sends ClientInfo and proceeds, answering a challenge only if
//     one shows up. That also makes re-authentication free: a relay may
//     challenge again at any time on a live link, and the node answers with
//     whatever grant it holds right then.
var derpProofMagic = [6]byte{'c', 'a', 'l', 'a', 'P', '1'}

const (
	// DERPAuthNonceLen is the NaCl box nonce length.
	DERPAuthNonceLen = 24
	// DERPAuthChallengeLen is the encoded challenge length.
	DERPAuthChallengeLen = KeyLen + DERPAuthNonceLen
	// derpProofPlaintextLen is magic + claimed key + ephemeral key.
	derpProofPlaintextLen = 6 + KeyLen + KeyLen
	// derpProofSealedLen is the plaintext plus the box overhead.
	derpProofSealedLen = derpProofPlaintextLen + box.Overhead
)

var (
	// ErrAuthMalformed is returned for a challenge or proof that doesn't decode.
	ErrAuthMalformed = errors.New("meshproto: malformed DERP auth frame")
	// ErrAuthProof is returned when a proof does not open, or opens to the wrong
	// plaintext — i.e. the peer does not hold the key it claimed.
	ErrAuthProof = errors.New("meshproto: DERP auth proof rejected")
)

// DERPAuthChallenge is the relay's half: a per-connection ephemeral public key
// and nonce.
type DERPAuthChallenge struct {
	EphPub [KeyLen]byte
	Nonce  [DERPAuthNonceLen]byte
}

// NewDERPAuthChallenge generates a fresh challenge and the ephemeral private key
// the relay keeps to open the proof. The private key never leaves the relay and
// dies with the connection.
func NewDERPAuthChallenge() (ch DERPAuthChallenge, ephPriv [KeyLen]byte, err error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return ch, ephPriv, fmt.Errorf("meshproto: generate challenge key: %w", err)
	}
	if _, err := rand.Read(ch.Nonce[:]); err != nil {
		return ch, ephPriv, fmt.Errorf("meshproto: generate challenge nonce: %w", err)
	}
	ch.EphPub = *pub
	return ch, *priv, nil
}

// Encode renders the challenge as a frame payload.
func (c DERPAuthChallenge) Encode() []byte {
	out := make([]byte, 0, DERPAuthChallengeLen)
	out = append(out, c.EphPub[:]...)
	out = append(out, c.Nonce[:]...)
	return out
}

// ParseDERPAuthChallenge decodes a challenge frame payload.
func ParseDERPAuthChallenge(b []byte) (DERPAuthChallenge, error) {
	var c DERPAuthChallenge
	if len(b) != DERPAuthChallengeLen {
		return c, fmt.Errorf("%w: challenge length %d, want %d", ErrAuthMalformed, len(b), DERPAuthChallengeLen)
	}
	copy(c.EphPub[:], b[:KeyLen])
	copy(c.Nonce[:], b[KeyLen:])
	return c, nil
}

// derpProofPlaintext is what the box carries. Built identically on both sides so
// sealing and opening can never drift apart.
func derpProofPlaintext(self NodeKey, ephPub [KeyLen]byte) []byte {
	out := make([]byte, 0, derpProofPlaintextLen)
	out = append(out, derpProofMagic[:]...)
	out = append(out, self[:]...)
	out = append(out, ephPub[:]...)
	return out
}

// SealDERPAuthProof builds the proof frame payload for a challenge. grant may be
// empty — a node with no grant yet still proves possession of its key, which is
// enough for a relay that doesn't require grants.
func SealDERPAuthProof(ch DERPAuthChallenge, self NodeKey, priv [KeyLen]byte, grant []byte) ([]byte, error) {
	if len(grant) > MaxDERPFrameLen-derpProofSealedLen-2 {
		return nil, fmt.Errorf("%w: grant too long (%d)", ErrAuthMalformed, len(grant))
	}
	sealed := box.Seal(nil, derpProofPlaintext(self, ch.EphPub), (*[DERPAuthNonceLen]byte)(&ch.Nonce),
		(*[KeyLen]byte)(&ch.EphPub), (*[KeyLen]byte)(&priv))
	out := make([]byte, 2, 2+len(grant)+len(sealed))
	binary.BigEndian.PutUint16(out, uint16(len(grant)))
	out = append(out, grant...)
	out = append(out, sealed...)
	return out, nil
}

// OpenDERPAuthProof verifies a proof against the challenge the relay issued and
// the node key the connection claimed, and returns the grant blob it carried
// (empty when the node had none).
//
// A successful return means only "this peer holds the private key for claimed".
// Whether it may then USE this relay is the grant's job, which the caller checks
// separately — VerifyRelayGrant plus the node-key and scope checks that
// relaygrant.go documents.
func OpenDERPAuthProof(ch DERPAuthChallenge, ephPriv [KeyLen]byte, claimed NodeKey, payload []byte) ([]byte, error) {
	if len(payload) < 2 {
		return nil, fmt.Errorf("%w: proof shorter than its length prefix", ErrAuthMalformed)
	}
	grantLen := int(binary.BigEndian.Uint16(payload[:2]))
	if len(payload) != 2+grantLen+derpProofSealedLen {
		return nil, fmt.Errorf("%w: proof length %d, want %d for a %d-byte grant",
			ErrAuthMalformed, len(payload), 2+grantLen+derpProofSealedLen, grantLen)
	}
	grant := payload[2 : 2+grantLen]
	sealed := payload[2+grantLen:]

	opened, ok := box.Open(nil, sealed, (*[DERPAuthNonceLen]byte)(&ch.Nonce),
		(*[KeyLen]byte)(&claimed), (*[KeyLen]byte)(&ephPriv))
	if !ok {
		return nil, ErrAuthProof
	}
	// The box already authenticates the sender; re-checking the plaintext binds
	// the proof to THIS challenge and THIS claimed key, so a box captured from
	// another exchange can't be pasted in.
	want := derpProofPlaintext(claimed, ch.EphPub)
	if len(opened) != len(want) {
		return nil, fmt.Errorf("%w: proof plaintext length", ErrAuthProof)
	}
	for i := range want {
		if opened[i] != want[i] {
			return nil, fmt.Errorf("%w: proof plaintext mismatch", ErrAuthProof)
		}
	}
	out := make([]byte, len(grant))
	copy(out, grant)
	return out, nil
}
