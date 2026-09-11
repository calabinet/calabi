package meshproto

import (
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func regKeys(t *testing.T) (NodeKey, [KeyLen]byte) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return NodeKey(*pub), *priv
}

func newChallenge(t *testing.T) (RegisterChallenge, [KeyLen]byte) {
	t.Helper()
	ch, eph, err := NewRegisterChallenge()
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	return ch, eph
}

func TestRegisterProofRoundTrip(t *testing.T) {
	pub, priv := regKeys(t)
	ch, eph := newChallenge(t)
	wire, err := ParseRegisterChallenge(ch.Encode())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := OpenRegisterProof(ch, eph, pub, SealRegisterProof(wire, pub, priv)); err != nil {
		t.Fatalf("a proof sealed with the right key was rejected: %v", err)
	}
}

// THE property: knowing a node key (every peer does) is not enough to answer for
// it. Mallory claims the victim's key but can only seal with her own.
func TestRegisterProofNeedsThePrivateKeyOfTheClaimedNode(t *testing.T) {
	victim, _ := regKeys(t)
	_, mallory := regKeys(t)
	ch, eph := newChallenge(t)
	if err := OpenRegisterProof(ch, eph, victim, SealRegisterProof(ch, victim, mallory)); !errors.Is(err, ErrRegisterProof) {
		t.Fatalf("err = %v, want ErrRegisterProof", err)
	}
}

func TestRegisterProofIsBoundToItsChallenge(t *testing.T) {
	pub, priv := regKeys(t)
	first, _ := newChallenge(t)
	second, eph2 := newChallenge(t)
	if err := OpenRegisterProof(second, eph2, pub, SealRegisterProof(first, pub, priv)); !errors.Is(err, ErrRegisterProof) {
		t.Fatalf("a proof for one challenge opened against another: err = %v", err)
	}
}

// A proof a node gives a RELAY must never pass as a registration proof, even for
// the very same ephemeral key and nonce - that is the relay-in-the-middle a shared
// magic would allow (see registerauth.go).
func TestRelayProofIsNotARegistrationProof(t *testing.T) {
	pub, priv := regKeys(t)
	ch, eph := newChallenge(t)
	relayProof, err := SealDERPAuthProof(DERPAuthChallenge{EphPub: ch.EphPub, Nonce: ch.Nonce}, pub, priv, nil)
	if err != nil {
		t.Fatalf("seal relay proof: %v", err)
	}
	sealed := relayProof[2:] // empty grant: a 2-byte length prefix, then the box
	if err := OpenRegisterProof(ch, eph, pub, sealed); !errors.Is(err, ErrRegisterProof) {
		t.Fatalf("a relay proof passed as a registration proof: err = %v", err)
	}
}

func TestParseRegisterChallengeRejectsWrongLength(t *testing.T) {
	if _, err := ParseRegisterChallenge(make([]byte, RegisterChallengeLen-1)); err == nil {
		t.Fatal("a short challenge parsed")
	}
}
