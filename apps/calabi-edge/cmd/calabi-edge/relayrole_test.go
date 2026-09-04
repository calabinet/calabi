package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/calabi/calabi/apps/calabi-edge/internal/config"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func TestRelayAuthConfig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	// Default kind = self: a merged BYOI node's relay is the org's own relay.
	if auth, err := relayAuthConfig(config.RelayRole{}); err != nil {
		t.Fatalf("empty relay role: %v", err)
	} else if auth.Kind != meshproto.RelayKindSelfHosted || auth.Require {
		t.Errorf("default auth = %+v, want kind=self require=false", auth)
	}

	// Explicit platform kind.
	if auth, err := relayAuthConfig(config.RelayRole{Kind: "platform"}); err != nil {
		t.Fatalf("platform kind: %v", err)
	} else if auth.Kind != meshproto.RelayKindPlatform {
		t.Errorf("kind=platform gave %v", auth.Kind)
	}

	// Bad kind is rejected.
	if _, err := relayAuthConfig(config.RelayRole{Kind: "gateway"}); err == nil {
		t.Error("kind=gateway should be rejected")
	}

	// require_auth without a coord pubkey would black-hole every connection.
	if _, err := relayAuthConfig(config.RelayRole{RequireAuth: true}); err == nil {
		t.Error("require_auth without coord_pubkey should be rejected")
	}

	// Valid pubkey is decoded onto CoordPub.
	if auth, err := relayAuthConfig(config.RelayRole{RequireAuth: true, CoordPubKey: pubB64}); err != nil {
		t.Fatalf("valid pubkey: %v", err)
	} else if len(auth.CoordPub) != ed25519.PublicKeySize {
		t.Errorf("coord pubkey not decoded: len=%d", len(auth.CoordPub))
	}

	// Malformed pubkey is rejected.
	if _, err := relayAuthConfig(config.RelayRole{CoordPubKey: "not-base64!!"}); err == nil {
		t.Error("malformed coord_pubkey should be rejected")
	}
}
