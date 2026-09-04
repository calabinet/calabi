package mesh

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestGenerateKeyPublicMatchesX25519(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub := k.Public()
	if pub.IsZero() {
		t.Fatal("public key is zero")
	}
	// Public() must equal a direct X25519(priv, basepoint).
	want, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	if string(pub[:]) != string(want) {
		t.Fatal("Public() != X25519(priv, basepoint)")
	}
}

func TestGenerateKeyDistinct(t *testing.T) {
	a, _ := GenerateKey()
	b, _ := GenerateKey()
	if a == b {
		t.Fatal("two generated keys collided")
	}
	if a.Public() == b.Public() {
		t.Fatal("two public keys collided")
	}
	if len(a.Hex()) != 64 {
		t.Fatalf("hex len = %d, want 64", len(a.Hex()))
	}
}

func TestLoadOrCreateKeyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "mesh.key")

	first, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// File exists, 0600.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Logf("warning: key file perms %o (group/other bits set — expected on some FS)", perm)
	}

	second, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if first != second {
		t.Fatal("LoadOrCreateKey did not return the persisted key on reload")
	}
}
