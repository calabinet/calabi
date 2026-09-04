package meshproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// node makes a Curve25519 keypair in the shape a mesh node uses: the public half
// IS the NodeKey peers and relays see.
func node(t *testing.T) (NodeKey, [KeyLen]byte) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}
	return NodeKey(*pub), *priv
}

func coordKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate coordinator key: %v", err)
	}
	return pub, priv
}

func TestRelayGrantRoundTrip(t *testing.T) {
	pub, priv := coordKey(t)
	nk, _ := node(t)
	exp := time.Now().Add(time.Hour).Truncate(time.Second).UTC()

	blob, err := SignRelayGrant(priv, RelayGrant{Node: nk, Meshnet: 42, Scope: RelayScopeAll, Expiry: exp})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(blob) != RelayGrantLen {
		t.Fatalf("grant is %d bytes, want %d", len(blob), RelayGrantLen)
	}
	got, err := VerifyRelayGrant(pub, blob, time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Node != nk || got.Meshnet != 42 || got.Scope != RelayScopeAll || !got.Expiry.Equal(exp) {
		t.Fatalf("round trip lost fields: %+v", got)
	}
}

// A grant signed by anyone other than the coordinator the relay is configured
// with must not verify — otherwise "the control plane decides who may relay"
// would be decided by whoever generated a key.
func TestRelayGrantRejectsForeignSigner(t *testing.T) {
	pub, _ := coordKey(t)
	_, otherPriv := coordKey(t)
	nk, _ := node(t)

	blob, err := SignRelayGrant(otherPriv, RelayGrant{Node: nk, Meshnet: 1, Scope: RelayScopeAll, Expiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := VerifyRelayGrant(pub, blob, time.Now()); !errors.Is(err, ErrGrantSignature) {
		t.Fatalf("foreign signature accepted (err=%v)", err)
	}
}

// The attack this specifically blocks: take a grant legitimately issued to
// yourself and rewrite the node key to a victim's. Every byte that decides
// anything must be inside the signature.
func TestRelayGrantRejectsRewrittenFields(t *testing.T) {
	pub, priv := coordKey(t)
	mine, _ := node(t)
	victim, _ := node(t)

	blob, err := SignRelayGrant(priv, RelayGrant{Node: mine, Meshnet: 7, Scope: RelayScopeSelfHosted, Expiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(b []byte)
	}{
		{"node key", func(b []byte) { copy(b[7:7+KeyLen], victim[:]) }},
		{"meshnet", func(b []byte) { b[7+KeyLen] ^= 0xff }},
		{"scope widened", func(b []byte) { b[7+KeyLen+8] = byte(RelayScopeAll) }},
		{"expiry extended", func(b []byte) { b[7+KeyLen+9] ^= 0x7f }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := append([]byte(nil), blob...)
			tc.mutate(tampered)
			if _, err := VerifyRelayGrant(pub, tampered, time.Now()); !errors.Is(err, ErrGrantSignature) {
				t.Fatalf("rewritten %s accepted (err=%v)", tc.name, err)
			}
		})
	}
}

func TestRelayGrantExpiry(t *testing.T) {
	pub, priv := coordKey(t)
	nk, _ := node(t)
	exp := time.Now().Add(-time.Second)

	blob, err := SignRelayGrant(priv, RelayGrant{Node: nk, Meshnet: 1, Scope: RelayScopeAll, Expiry: exp})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := VerifyRelayGrant(pub, blob, time.Now()); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("expired grant accepted (err=%v)", err)
	}
	// Same blob, evaluated before it lapsed.
	if _, err := VerifyRelayGrant(pub, blob, exp.Add(-time.Minute)); err != nil {
		t.Fatalf("grant rejected while still valid: %v", err)
	}
}

func TestRelayScopePermits(t *testing.T) {
	for _, tc := range []struct {
		scope RelayScope
		kind  RelayKind
		want  bool
	}{
		{RelayScopeAll, RelayKindPlatform, true},
		{RelayScopeAll, RelayKindSelfHosted, true},
		// The quota case: cut off the platform's relays, keep the org's own.
		{RelayScopeSelfHosted, RelayKindPlatform, false},
		{RelayScopeSelfHosted, RelayKindSelfHosted, true},
		// An unknown scope from a newer coordinator must fail closed, not open.
		{RelayScope(99), RelayKindPlatform, false},
		{RelayScope(99), RelayKindSelfHosted, false},
		{RelayScopeInvalid, RelayKindSelfHosted, false},
	} {
		if got := tc.scope.Permits(tc.kind); got != tc.want {
			t.Errorf("scope %v on %v relay = %v, want %v", tc.scope, tc.kind, got, tc.want)
		}
	}
}

func TestDERPAuthProofRoundTrip(t *testing.T) {
	nk, priv := node(t)
	ch, ephPriv, err := NewDERPAuthChallenge()
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	for _, grant := range [][]byte{nil, []byte("a-grant-blob")} {
		proof, err := SealDERPAuthProof(ch, nk, priv, grant)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		got, err := OpenDERPAuthProof(ch, ephPriv, nk, proof)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if string(got) != string(grant) {
			t.Fatalf("grant round trip: got %q want %q", got, grant)
		}
	}
}

// THE regression this whole slice exists for. An attacker knows the victim's
// node key — every peer does, it's in the netmap — and may even have captured a
// valid grant issued to the victim. Neither lets them connect as the victim, so
// they cannot evict the victim's link or take over its inbound relay traffic.
func TestDERPAuthProofRejectsImpostorWhoKnowsThePublicKey(t *testing.T) {
	victim, _ := node(t)
	_, attackerPriv := node(t)

	ch, ephPriv, err := NewDERPAuthChallenge()
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	// The attacker claims the victim's key and signs with its own private key.
	proof, err := SealDERPAuthProof(ch, victim, attackerPriv, []byte("stolen-grant"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := OpenDERPAuthProof(ch, ephPriv, victim, proof); !errors.Is(err, ErrAuthProof) {
		t.Fatalf("impostor accepted (err=%v)", err)
	}
}

// A proof is bound to the challenge it answered, so one recorded off the wire is
// worthless on the next connection.
func TestDERPAuthProofRejectsReplayOnAnotherChallenge(t *testing.T) {
	nk, priv := node(t)
	first, _, err := NewDERPAuthChallenge()
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	second, secondEphPriv, err := NewDERPAuthChallenge()
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	proof, err := SealDERPAuthProof(first, nk, priv, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := OpenDERPAuthProof(second, secondEphPriv, nk, proof); !errors.Is(err, ErrAuthProof) {
		t.Fatalf("replayed proof accepted (err=%v)", err)
	}
}

func TestDERPAuthChallengeCodec(t *testing.T) {
	ch, _, err := NewDERPAuthChallenge()
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	got, err := ParseDERPAuthChallenge(ch.Encode())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != ch {
		t.Fatalf("challenge round trip mismatch")
	}
	for _, bad := range [][]byte{nil, make([]byte, DERPAuthChallengeLen-1), make([]byte, DERPAuthChallengeLen+1)} {
		if _, err := ParseDERPAuthChallenge(bad); !errors.Is(err, ErrAuthMalformed) {
			t.Fatalf("challenge of length %d accepted", len(bad))
		}
	}
}

func TestDERPAuthProofRejectsMalformedPayloads(t *testing.T) {
	nk, priv := node(t)
	ch, ephPriv, err := NewDERPAuthChallenge()
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	proof, err := SealDERPAuthProof(ch, nk, priv, []byte("grant"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for name, bad := range map[string][]byte{
		"empty":            nil,
		"prefix only":      proof[:2],
		"truncated":        proof[:len(proof)-1],
		"trailing garbage": append(append([]byte(nil), proof...), 0),
		"lying length prefix": func() []byte {
			b := append([]byte(nil), proof...)
			b[0], b[1] = 0xff, 0xff
			return b
		}(),
	} {
		if _, err := OpenDERPAuthProof(ch, ephPriv, nk, bad); err == nil {
			t.Fatalf("%s payload accepted", name)
		}
	}
}
