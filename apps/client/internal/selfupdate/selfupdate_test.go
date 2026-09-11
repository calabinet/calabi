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
		{"dev", "1.7.0", false}, // dev builds never auto-update
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

	m, raw, err := FetchManifest(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "1.7.0" {
		t.Errorf("version=%q", m.Version)
	}
	// The raw bytes must be exactly what the server sent: the signature is
	// checked against these, so any re-serialisation here would verify a
	// different byte string than the one that was downloaded.
	if string(raw) != body {
		t.Errorf("raw manifest bytes differ from the served body:\ngot  %q\nwant %q", raw, body)
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
	if _, _, err := FetchManifest(context.Background(), srv.URL); err == nil {
		t.Error("FetchManifest should error on HTTP 404")
	}
}

// VerifyManifestSignature is the gate that makes the manifest's own claims
// (which version, which platform, which sha256) trustworthy — see UPD-1.
func TestVerifyManifestSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"version":"1.7.0","platforms":{}}`)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))

	if err := VerifyManifestSignature(raw, sig, pub); err != nil {
		t.Errorf("valid manifest signature rejected: %v", err)
	}
	// One byte changed anywhere in the manifest breaks it.
	if err := VerifyManifestSignature(append(raw, ' '), sig, pub); err == nil {
		t.Error("a modified manifest passed verification")
	}
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := VerifyManifestSignature(raw, sig, otherPub); err == nil {
		t.Error("a manifest signed by another key passed verification")
	}
	if err := VerifyManifestSignature(raw, "!!not-base64!!", pub); err == nil {
		t.Error("a non-base64 signature passed verification")
	}
	if err := VerifyManifestSignature(raw, sig, ed25519.PublicKey{1, 2, 3}); err == nil {
		t.Error("a malformed public key passed verification")
	}
}

// The version floor is what makes REPLAYING a genuine older manifest useless.
func TestVersionFloor(t *testing.T) {
	dir := t.TempDir()

	// A fresh install has no floor and must not be wedged by that.
	if got := readVersionFloor(dir); got != "" {
		t.Errorf("fresh floor = %q, want empty", got)
	}
	writeVersionFloor(dir, "2.0.0")
	if got := readVersionFloor(dir); got != "2.0.0" {
		t.Errorf("floor = %q, want 2.0.0", got)
	}
	// A corrupt floor is ignored rather than blocking updates forever — the
	// file is local state, not an authority, and a machine that cannot read it
	// should still be able to update.
	if err := os.WriteFile(filepath.Join(dir, versionFloorFile), []byte("not-a-version"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readVersionFloor(dir); got != "" {
		t.Errorf("corrupt floor = %q, want it ignored", got)
	}
}
