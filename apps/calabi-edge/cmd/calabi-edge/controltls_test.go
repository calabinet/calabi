package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/calabi/calabi/apps/calabi-edge/internal/config"
)

func leafOf(t *testing.T, c controlCert) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// A standalone edge with a state directory and no certificate of its own keeps
// the self-signed one it made, so what a client pinned still matches after the
// edge restarts. Before, every start made a new one and nothing could be pinned.
func TestControlCertSurvivesARestart(t *testing.T) {
	cfg := config.Default()
	cfg.State.Dir = t.TempDir()
	cfg.HTTP.BaseDomain = "tunnel.example.com"
	cfg.Public.Addr = "203.0.113.7:7443"

	first, err := resolveControlCert(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !first.fresh || first.ephemeral {
		t.Fatalf("first start: fresh=%v ephemeral=%v, want a new certificate kept on disk", first.fresh, first.ephemeral)
	}
	again, err := resolveControlCert(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if again.fresh || again.pin() != first.pin() {
		t.Fatalf("after a restart: fresh=%v pin %s, want the same certificate (%s)", again.fresh, again.pin(), first.pin())
	}

	// The names let a client that is given this file as its CA check the name it
	// dials: the base domain and the public address.
	leaf := leafOf(t, first)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	for _, name := range []string{"tunnel.example.com", "203.0.113.7"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Errorf("verify as %s with the certificate as its own root: %v", name, err)
		}
	}
}

// Half a pair is restored, never replaced: a new key would be a new fingerprint.
func TestControlCertRefusesHalfAPair(t *testing.T) {
	cfg := config.Default()
	cfg.State.Dir = t.TempDir()
	if _, err := resolveControlCert(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cfg.State.Dir, controlKeyName)); err != nil {
		t.Fatal(err)
	}
	if c, err := resolveControlCert(cfg); err == nil {
		t.Fatalf("with the key gone the edge made certificate %s; want an error", c.pin())
	}
}

// Without a state directory nothing can be kept, and the edge says so.
func TestControlCertWithoutStateDirIsEphemeral(t *testing.T) {
	cfg := config.Default()
	cfg.State.Dir = ""
	a, err := resolveControlCert(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := resolveControlCert(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !a.ephemeral || a.pin() == b.pin() {
		t.Fatalf("ephemeral=%v, pins %s / %s; want a new, ephemeral certificate each time", a.ephemeral, a.pin(), b.pin())
	}
	if err := printControlFingerprint(cfg); err == nil {
		t.Fatal("-fingerprint printed a fingerprint that the next start would not serve")
	}
}

// Configured certificate paths behave as before.
func TestControlCertFromConfiguredPaths(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.State.Dir = t.TempDir()
	cfg.Control.CertPEM = filepath.Join(dir, "c.pem")
	cfg.Control.KeyPEM = filepath.Join(dir, "k.pem")
	a, err := resolveControlCert(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := resolveControlCert(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if a.pin() != b.pin() || a.source != cfg.Control.CertPEM {
		t.Fatalf("configured paths: pins %s / %s from %s", a.pin(), b.pin(), a.source)
	}
	if _, err := os.Stat(filepath.Join(cfg.State.Dir, controlCertName)); err == nil {
		t.Fatal("a certificate was written to state.dir although the config names its own")
	}
}
