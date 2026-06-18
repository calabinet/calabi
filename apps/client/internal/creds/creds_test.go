package creds

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CALABI_CONFIG", filepath.Join(dir, "nope.json"))
	c, err := Load()
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if c.AccessToken != "" || c.User.Email != "" {
		t.Errorf("expected empty Config, got %+v", c)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CALABI_CONFIG", filepath.Join(dir, "nested", "config.json"))

	c := &Config{
		Server:      "edge:7443",
		AccessToken: "usr_ABCDEFGH.0123456789abcdef0123456789abcdef",
		APIKey:      "tk_a1b2c3d4_aaaabbbbccccddddeeeeffff00001111",
	}
	c.User.ID = 42
	c.User.Email = "foo@example.com"

	if err := Save(c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.AccessToken != c.AccessToken {
		t.Errorf("AccessToken roundtrip = %q, want %q", loaded.AccessToken, c.AccessToken)
	}
	if loaded.APIKey != c.APIKey {
		t.Errorf("APIKey roundtrip = %q, want %q", loaded.APIKey, c.APIKey)
	}
	if loaded.User.Email != "foo@example.com" {
		t.Errorf("User.Email = %q", loaded.User.Email)
	}
}

func TestSaveMakesParents(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a", "b", "c", "config.json")
	t.Setenv("CALABI_CONFIG", target)
	if err := Save(&Config{AccessToken: "tk_zzzzzzzz_00000000000000000000000000000000"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("creds file not created: %v", err)
	}
}

// TestClearAuth covers the invariant: after the daemon detects
// device_deleted from the edge, only the auth-bearing fields are
// wiped. Email + fingerprint remain so the SPA login form pre-fills
// and the next register doesn't create a duplicate (user_id,
// fingerprint) row that the heal step would also rename
// — keeping them avoids a needless heal cycle.
func TestClearAuth(t *testing.T) {
	c := &Config{
		Server:       "edge:443",
		AccessToken:  "tok-abc",
		RefreshToken: "ref-xyz",
		APIKey:       "tk_secret",
		Fingerprint:  "fp_keepthis",
		DeviceID:     42,
		ActiveOrgID:  7,
	}
	c.User.ID = 99
	c.User.Email = "alice@example.com"

	c.ClearAuth()

	// Auth-bearing fields wiped.
	if c.AccessToken != "" || c.RefreshToken != "" || c.APIKey != "" {
		t.Fatalf("tokens not cleared: %+v", c)
	}
	if c.DeviceID != 0 || c.ActiveOrgID != 0 {
		t.Fatalf("device/org not cleared: device=%d active_org=%d", c.DeviceID, c.ActiveOrgID)
	}
	// Identity hints preserved.
	if c.User.Email != "alice@example.com" {
		t.Fatalf("email should remain for SPA pre-fill, got %q", c.User.Email)
	}
	if c.Fingerprint != "fp_keepthis" {
		t.Fatalf("fingerprint should remain (per-install stable id), got %q", c.Fingerprint)
	}
	if c.Server != "edge:443" {
		t.Fatalf("server preference should remain, got %q", c.Server)
	}
}

// TestClearAuth_NilSafe ensures the helper doesn't panic when the
// caller passes a zero / loaded-from-missing-file *Config.
func TestClearAuth_NilSafe(t *testing.T) {
	var c *Config
	c.ClearAuth() // must be a no-op, not a panic
}
