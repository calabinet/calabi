package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		cur, cand string
		want      bool
	}{
		{"1.6.0", "1.7.0", true},
		{"1.6.0", "1.6.1", true},
		{"1.9.0", "1.10.0", true}, // numeric, not lexical
		{"1.6.0", "1.6.0", false},
		{"1.7.0", "1.6.0", false},
		{"1.6.1", "1.6.0", false},
		{"2.0.0", "1.9.9", false},
		{"dev", "1.7.0", false},   // dev builds never auto-update
		{"1.6.0", "garbage", false},
		{"1.6.0", "1.6.0-rc1", false}, // same base version
		{"1.6.0", "1.7.0-rc1", true},  // suffix ignored
		{"v1.6.0", "v1.7.0", true},    // leading v tolerated
	}
	for _, c := range cases {
		if got := IsNewer(c.cur, c.cand); got != c.want {
			t.Errorf("IsNewer(%q,%q)=%v want %v", c.cur, c.cand, got, c.want)
		}
	}
}

func TestPlatformKey(t *testing.T) {
	if k := PlatformKey(); k == "" {
		t.Fatal("PlatformKey empty")
	}
	// arch normalisation
	if got := normalizeArch("amd64"); got != "x86_64" {
		t.Errorf("normalizeArch(amd64)=%q want x86_64", got)
	}
	if got := normalizeArch("arm64"); got != "aarch64" {
		t.Errorf("normalizeArch(arm64)=%q want aarch64", got)
	}
}

func TestVerifySHA256(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "blob")
	data := []byte("calabi installer bytes")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	good := hex.EncodeToString(sum[:])

	if err := VerifySHA256(p, good); err != nil {
		t.Errorf("VerifySHA256 good: %v", err)
	}
	if err := VerifySHA256(p, "ABCDEF"); err == nil {
		t.Error("VerifySHA256 should reject a mismatched digest")
	}
	// case-insensitive hex
	if err := VerifySHA256(p, hex.EncodeToString(sum[:])); err != nil {
		t.Errorf("VerifySHA256 lower: %v", err)
	}
}

func TestVerifySignature(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "blob")
	data := []byte("calabi installer bytes")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))

	if err := VerifySignature(p, sig, pub); err != nil {
		t.Errorf("VerifySignature valid: %v", err)
	}
	// tampered file → fail
	if err := os.WriteFile(p, append(data, '!'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(p, sig, pub); err == nil {
		t.Error("VerifySignature should fail on a tampered file")
	}
	// wrong key → fail
	otherPub, _, _ := ed25519.GenerateKey(nil)
	os.WriteFile(p, data, 0o600)
	if err := VerifySignature(p, sig, otherPub); err == nil {
		t.Error("VerifySignature should fail with the wrong public key")
	}
	// malformed key
	if err := VerifySignature(p, sig, ed25519.PublicKey{1, 2, 3}); err == nil {
		t.Error("VerifySignature should reject a malformed public key")
	}
}

func TestFetchManifestAndArtifact(t *testing.T) {
	body := fmt.Sprintf(`{
	  "version": "1.7.0",
	  "platforms": {
	    "%s": {"url":"https://example/installer","sha256":"deadbeef","signature":"c2ln"}
	  }
	}`, PlatformKey())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	m, err := FetchManifest(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "1.7.0" {
		t.Errorf("version=%q", m.Version)
	}
	a, ok := m.ArtifactForThisPlatform()
	if !ok {
		t.Fatalf("no artifact for platform %s", PlatformKey())
	}
	if a.URL != "https://example/installer" || a.SHA256 != "deadbeef" {
		t.Errorf("artifact=%+v", a)
	}
}

func TestFetchManifestHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := FetchManifest(context.Background(), srv.URL); err == nil {
		t.Error("FetchManifest should error on HTTP 404")
	}
}
