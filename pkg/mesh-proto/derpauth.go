package meshproto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// DERP relay authentication — the handshake that turns ClientInfo from a
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

// Binding the proof to the relay.
//
// The proof above names no relay. ephPub and nonce are whatever the challenger
// chose, so a relay a node is connected to can pass down a challenge ANOTHER
// relay issued, collect the node's answer — proof and live grant — and replay it
// there to log in as the node. That is the takeover relay authentication
// exists to stop, done through the victim instead of by forging its key.
//
// On a TLS link the answer is therefore bound to the relay: the plaintext also
// carries the SHA-256 of the SubjectPublicKeyInfo of the certificate the relay
// presented in THAT handshake, under a magic of its own:
//
//	bound proof plaintext = magicP2 || claimed node key || ephPub || binding
//
// The node takes the binding from the leaf it has just verified; the relay
// takes it from the certificate it served on that connection — never from "its
// current certificate", which a hot reload can change between the handshake and
// the proof. A relay passing down another relay's challenge gets back an answer
// bound to its OWN certificate, and the other relay refuses it.
//
// The two formats never stand in for each other. A relay opens a proof from a
// TLS link with the bound opener and one from a plaintext link with the legacy
// one, and a proof of the other kind fails the length check before it fails
// the magic check. A node on a TLS link produces only bound proofs, so nothing
// it says there opens on a plaintext link either. What a node says on a
// PLAINTEXT link stays replayable: that is the legacy protocol, kept for nodes
// and relays that have not upgraded, and a relay that refuses plaintext closes
// it for good.
var derpBoundProofMagic = [6]byte{'c', 'a', 'l', 'a', 'P', '2'}

const (
	// DERPAuthNonceLen is the NaCl box nonce length.
	DERPAuthNonceLen = 24
	// DERPAuthChallengeLen is the encoded challenge length.
	DERPAuthChallengeLen = KeyLen + DERPAuthNonceLen
	// derpProofPlaintextLen is magic + claimed key + ephemeral key.
	derpProofPlaintextLen = 6 + KeyLen + KeyLen
	// derpBoundProofPlaintextLen adds the binding.
	derpBoundProofPlaintextLen = derpProofPlaintextLen + sha256.Size
)

var (
	// ErrAuthMalformed is returned for a challenge or proof that doesn't decode.
	ErrAuthMalformed = errors.New("meshproto: malformed DERP auth frame")
	// ErrAuthProof is returned when a proof does not open, or opens to the wrong
	// plaintext — i.e. the peer does not hold the key it claimed, or the proof
	// was made for a different relay.
	ErrAuthProof = errors.New("meshproto: DERP auth proof rejected")
)

// DERPBinding names the certificate a relay presented on a TLS link: the
// SHA-256 of its SubjectPublicKeyInfo, i.e. CertPin's number as raw bytes. The
// public key rather than the whole certificate, like a pin, so a certificate
// re-issued for the same key binds the same way.
type DERPBinding [sha256.Size]byte

// DERPBindingOf returns the binding for a certificate a relay presented.
func DERPBindingOf(cert *x509.Certificate) DERPBinding {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

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

// derpBoundProofPlaintext is the bound form: its own magic, the binding last.
func derpBoundProofPlaintext(self NodeKey, ephPub [KeyLen]byte, binding DERPBinding) []byte {
	out := make([]byte, 0, derpBoundProofPlaintextLen)
	out = append(out, derpBoundProofMagic[:]...)
	out = append(out, self[:]...)
	out = append(out, ephPub[:]...)
	out = append(out, binding[:]...)
	return out
}

// SealDERPAuthProof builds the proof frame payload for a challenge on a
// PLAINTEXT link. grant may be empty — a node with no grant yet still proves
// possession of its key, which is enough for a relay that doesn't require
// grants.
func SealDERPAuthProof(ch DERPAuthChallenge, self NodeKey, priv [KeyLen]byte, grant []byte) ([]byte, error) {
	return sealDERPProof(ch, priv, grant, derpProofPlaintext(self, ch.EphPub))
}

// SealBoundDERPAuthProof builds the proof for a challenge on a TLS link, bound
// to the certificate the relay presented in that link's handshake. It opens
// only at a relay that presented that certificate, and only through
// OpenBoundDERPAuthProof.
func SealBoundDERPAuthProof(ch DERPAuthChallenge, self NodeKey, priv [KeyLen]byte, grant []byte, binding DERPBinding) ([]byte, error) {
	return sealDERPProof(ch, priv, grant, derpBoundProofPlaintext(self, ch.EphPub, binding))
}

func sealDERPProof(ch DERPAuthChallenge, priv [KeyLen]byte, grant, plaintext []byte) ([]byte, error) {
	if len(grant) > MaxDERPFrameLen-(len(plaintext)+box.Overhead)-2 {
		return nil, fmt.Errorf("%w: grant too long (%d)", ErrAuthMalformed, len(grant))
	}
	sealed := box.Seal(nil, plaintext, (*[DERPAuthNonceLen]byte)(&ch.Nonce),
		(*[KeyLen]byte)(&ch.EphPub), (*[KeyLen]byte)(&priv))
	out := make([]byte, 2, 2+len(grant)+len(sealed))
	binary.BigEndian.PutUint16(out, uint16(len(grant)))
	out = append(out, grant...)
	out = append(out, sealed...)
	return out, nil
}

// OpenDERPAuthProof verifies a proof from a PLAINTEXT link against the
// challenge the relay issued and the node key the connection claimed, and
// returns the grant blob it carried (empty when the node had none). A bound
// proof does not open here.
//
// A successful return means only "this peer holds the private key for claimed".
// Whether it may then USE this relay is the grant's job, which the caller checks
// separately — VerifyRelayGrant plus the node-key and scope checks that
// relaygrant.go documents.
func OpenDERPAuthProof(ch DERPAuthChallenge, ephPriv [KeyLen]byte, claimed NodeKey, payload []byte) ([]byte, error) {
	return openDERPProof(ch, ephPriv, claimed, payload, derpProofPlaintext(claimed, ch.EphPub), 0)
}

// OpenBoundDERPAuthProof verifies a proof from a TLS link: as OpenDERPAuthProof,
// and the proof must be bound to binding — the certificate THIS relay presented
// on that link. A legacy proof does not open here, and neither does one bound
// to any other certificate, which is what a relay passing down this relay's
// challenge would collect.
func OpenBoundDERPAuthProof(ch DERPAuthChallenge, ephPriv [KeyLen]byte, claimed NodeKey, payload []byte, binding DERPBinding) ([]byte, error) {
	return openDERPProof(ch, ephPriv, claimed, payload, derpBoundProofPlaintext(claimed, ch.EphPub, binding), len(binding))
}

// openDERPProof opens payload and checks it carries exactly want. The last
// bindingLen bytes of want are the binding, checked last so that a proof made
// for another relay says so in the log rather than looking like a forgery.
func openDERPProof(ch DERPAuthChallenge, ephPriv [KeyLen]byte, claimed NodeKey, payload, want []byte, bindingLen int) ([]byte, error) {
	sealedLen := len(want) + box.Overhead
	if len(payload) < 2 {
		return nil, fmt.Errorf("%w: proof shorter than its length prefix", ErrAuthMalformed)
	}
	grantLen := int(binary.BigEndian.Uint16(payload[:2]))
	if len(payload) != 2+grantLen+sealedLen {
		return nil, fmt.Errorf("%w: proof length %d, want %d for a %d-byte grant",
			ErrAuthMalformed, len(payload), 2+grantLen+sealedLen, grantLen)
	}
	grant := payload[2 : 2+grantLen]
	sealed := payload[2+grantLen:]

	opened, ok := box.Open(nil, sealed, (*[DERPAuthNonceLen]byte)(&ch.Nonce),
		(*[KeyLen]byte)(&claimed), (*[KeyLen]byte)(&ephPriv))
	if !ok {
		return nil, ErrAuthProof
	}
	// The box already authenticates the sender; re-checking the plaintext binds
	// the proof to THIS challenge and THIS claimed key (and, bound, THIS relay's
	// certificate), so a box captured from another exchange can't be pasted in.
	if len(opened) != len(want) {
		return nil, fmt.Errorf("%w: proof plaintext length", ErrAuthProof)
	}
	head := len(want) - bindingLen
	if !bytes.Equal(opened[:head], want[:head]) {
		return nil, fmt.Errorf("%w: proof plaintext mismatch", ErrAuthProof)
	}
	if !bytes.Equal(opened[head:], want[head:]) {
		return nil, fmt.Errorf("%w: proof is bound to another relay's certificate", ErrAuthProof)
	}
	out := make([]byte, len(grant))
	copy(out, grant)
	return out, nil
}
