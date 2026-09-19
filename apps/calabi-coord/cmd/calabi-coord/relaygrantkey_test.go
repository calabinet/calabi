package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The key's public half is baked into every relay's configuration, so the file
// must be stable: bootstrapped once, then read back byte-identical forever.
func TestRelayGrantKeyIsStableAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "relay-grant.key")

	first, created, err := loadOrCreateRelayGrantKey(path)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if !created {
		t.Error("first call did not report creating the key")
	}
	second, created, err := loadOrCreateRelayGrantKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if created {
		t.Error("reload regenerated the key instead of reading it")
	}
	if !first.Equal(second) {
		t.Fatal("restart produced a different key; every relay's config would break")
	}
	if len(first.Public().(ed25519.PublicKey)) != ed25519.PublicKeySize {
		t.Fatal("bad public key")
	}
}

// A corrupt or truncated key file is an ERROR, never a reason to write a new
// one. Silently rotating would invalidate the whole fleet's configuration at
// once, and the only symptom would be nodes failing to connect to relays.
func TestRelayGrantKeyRefusesToRegenerateOverABadFile(t *testing.T) {
	for name, content := range map[string]string{
		"not base64":   "!!!!not-base64!!!!",
		"wrong length": "c2hvcnQ=",
		"empty":        "",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "relay-grant.key")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("seed file: %v", err)
			}
			if _, _, err := loadOrCreateRelayGrantKey(path); err == nil {
				t.Fatal("a broken key file was accepted")
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if string(got) != content {
				t.Fatalf("the broken file was overwritten: %q", got)
			}
		})
	}
}

// A self-hosted coordinator signs without being told to: its edge accepts
// devices by nothing else. The platform keeps grants opt-in.
func TestSelfHostedCoordinatorSignsByDefault(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(envPrefix+"_"+relayGrantKeyEnv, "")
	pubOut := filepath.Join("shared", "coord.pub")
	t.Setenv(envPrefix+"_"+grantPubkeyFileEnv, pubOut)

	if relayGrantIssuer(quietLogger(), nil, false) != nil {
		t.Fatal("a platform coordinator with no key file signs")
	}
	if _, err := os.Stat(defaultGrantKeyFile); !os.IsNotExist(err) {
		t.Fatalf("the platform path created %s", defaultGrantKeyFile)
	}

	iss := relayGrantIssuer(quietLogger(), nil, true)
	signer, ok := iss.(interface{ PublicKey() ed25519.PublicKey })
	if !ok || len(signer.PublicKey()) != ed25519.PublicKeySize {
		t.Fatalf("self-hosted issuer = %#v, want one that signs", iss)
	}
	onDisk, err := readGrantPubkey(defaultGrantKeyFile)
	if err != nil {
		t.Fatalf("the key is not at the default path: %v", err)
	}
	if want := base64.StdEncoding.EncodeToString(signer.PublicKey()); onDisk != want {
		t.Fatalf("key file holds %s, issuer signs with %s", onDisk, want)
	}
	exported, err := os.ReadFile(pubOut)
	if err != nil {
		t.Fatalf("public key not exported for the edge: %v", err)
	}
	if strings.TrimSpace(string(exported)) != onDisk {
		t.Fatalf("exported %q, want %s", exported, onDisk)
	}
}

// `calabi-coord pubkey` reads; it never makes a key the coordinator does not
// sign with.
func TestReadGrantPubkeyNeverCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord-grant.key")
	if _, err := readGrantPubkey(path); err == nil {
		t.Fatal("no error for a missing key")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("reading the public key created a key file")
	}
}
