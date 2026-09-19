package meshproto

import (
	"errors"
	"testing"
)

func newEdgeChallenge(t *testing.T) (EdgeChallenge, [KeyLen]byte) {
	t.Helper()
	ch, eph, err := NewEdgeChallenge()
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	return ch, eph
}

func TestEdgeProofRoundTrip(t *testing.T) {
	pub, priv := regKeys(t)
	ch, eph := newEdgeChallenge(t)
	wire, err := ParseEdgeChallenge(ch.Encode())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := OpenEdgeProof(ch, eph, pub, SealEdgeProof(wire, pub, priv)); err != nil {
		t.Fatalf("a proof sealed with the right key was rejected: %v", err)
	}
}

// Knowing a node key — every peer in the meshnet does, and so does anyone who
// saw its grant — is not enough to answer for it.
func TestEdgeProofNeedsThePrivateKeyOfTheClaimedNode(t *testing.T) {
	victim, _ := regKeys(t)
	_, mallory := regKeys(t)
	ch, eph := newEdgeChallenge(t)
	if err := OpenEdgeProof(ch, eph, victim, SealEdgeProof(ch, victim, mallory)); !errors.Is(err, ErrEdgeProof) {
		t.Fatalf("err = %v, want ErrEdgeProof", err)
	}
}

// A proof answers one challenge: another connection's challenge does not open it.
func TestEdgeProofIsBoundToItsChallenge(t *testing.T) {
	pub, priv := regKeys(t)
	ch1, _ := newEdgeChallenge(t)
	ch2, eph2 := newEdgeChallenge(t)
	if err := OpenEdgeProof(ch2, eph2, pub, SealEdgeProof(ch1, pub, priv)); !errors.Is(err, ErrEdgeProof) {
		t.Fatalf("err = %v, want ErrEdgeProof", err)
	}
}

// Whoever runs an edge must not be able to turn a device's edge proof into a
// registration proof (or a relay proof) for the same challenge values, or back.
func TestEdgeProofDoesNotCrossProtocols(t *testing.T) {
	pub, priv := regKeys(t)
	ech, eeph := newEdgeChallenge(t)
	rch := RegisterChallenge{EphPub: ech.EphPub, Nonce: ech.Nonce}
	if err := OpenRegisterProof(rch, eeph, pub, SealEdgeProof(ech, pub, priv)); !errors.Is(err, ErrRegisterProof) {
		t.Fatalf("an edge proof passed as a registration proof: %v", err)
	}
	if err := OpenEdgeProof(ech, eeph, pub, SealRegisterProof(rch, pub, priv)); !errors.Is(err, ErrEdgeProof) {
		t.Fatalf("a registration proof passed as an edge proof: %v", err)
	}
	dch := DERPAuthChallenge{EphPub: ech.EphPub, Nonce: ech.Nonce}
	relayProof, err := SealDERPAuthProof(dch, pub, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := OpenEdgeProof(ech, eeph, pub, relayProof); err == nil {
		t.Fatal("a relay proof passed as an edge proof")
	}
}
