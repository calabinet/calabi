package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
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
