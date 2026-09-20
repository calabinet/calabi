package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/trust"
)

// testCAPEM returns a freshly made CA certificate, PEM-encoded.
func testCAPEM(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// clearTrustEnv runs the test without the two variables that change the
// default, whatever the machine running it has set.
func clearTrustEnv(t *testing.T) {
	t.Setenv("CALABI_INSECURE", "")
	t.Setenv("CALABI_EDGE_CA_FILE", "")
}

// The default is decided from what the node is joining. A self-hosted key gets
// the system's roots — never the CA compiled into the client, which is what it
// used to get, and which would have let a certificate we issued stand in for the
// user's own coordinator.
func TestCoordTrustDefaults(t *testing.T) {
	clearTrustEnv(t)
	for _, tc := range []struct {
		name string
		spec coordTrustSpec
		key  string
		want trust.Mode
	}{
		{"self-hosted key", coordTrustSpec{}, "my-secret-key", trust.System},
		{"tk_ key", coordTrustSpec{}, "tk_abc", trust.Platform},
		{"login token", coordTrustSpec{}, "eyJhbGciOi.x.y", trust.Platform},
		{"platform lease", coordTrustSpec{Platform: true}, "", trust.Platform},
		{"explicit wins over the key", coordTrustSpec{Mode: "system"}, "tk_abc", trust.System},
	} {
		got, err := coordTrust(tc.spec, tc.key)
		if err != nil || got.Mode != tc.want {
			t.Errorf("%s: coordTrust = %v, %v; want %s", tc.name, got.Mode, err, tc.want)
		}
	}
}

func TestCoordTrustEnvironment(t *testing.T) {
	clearTrustEnv(t)
	caPEM := testCAPEM(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte(caPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CALABI_EDGE_CA_FILE", caFile)
	got, err := coordTrust(coordTrustSpec{}, "my-secret-key")
	if err != nil || got.Mode != trust.CA || got.CAPEM != caPEM {
		t.Fatalf("CALABI_EDGE_CA_FILE: got %v (%d-byte CA), %v; want ca with the file's certificate", got.Mode, len(got.CAPEM), err)
	}
	// A platform key keeps the platform CA; the file is a self-hosted setting.
	if got, _ := coordTrust(coordTrustSpec{}, "tk_abc"); got.Mode != trust.Platform {
		t.Fatalf("tk_ key with CALABI_EDGE_CA_FILE set: got %s, want platform", got.Mode)
	}

	t.Setenv("CALABI_INSECURE", "1")
	for _, key := range []string{"my-secret-key", "tk_abc"} {
		if got, _ := coordTrust(coordTrustSpec{}, key); got.Mode != trust.Plaintext {
			t.Errorf("CALABI_INSECURE=1, key %q: got %s, want plaintext", key, got.Mode)
		}
	}
	if got, _ := coordTrust(coordTrustSpec{Platform: true}, ""); got.Mode != trust.Plaintext {
		t.Errorf("CALABI_INSECURE=1 on the platform lease: got %s, want plaintext (dev stacks)", got.Mode)
	}
	// A stated trust is not overridden by the environment.
	if got, _ := coordTrust(coordTrustSpec{Mode: "system"}, "k"); got.Mode != trust.System {
		t.Errorf("explicit system with CALABI_INSECURE=1: got %s", got.Mode)
	}
}

func TestCoordTrustExplicitNeedsItsMaterial(t *testing.T) {
	clearTrustEnv(t)
	pin := "sha256:" + strings.Repeat("ab", 32)
	if got, err := coordTrust(coordTrustSpec{Mode: "pin", Pins: []string{pin}}, "k"); err != nil || got.Mode != trust.Pin {
		t.Fatalf("pin: %v, %v", got.Mode, err)
	}
	// The material alone names the mode — even for a key that would otherwise
	// default to the platform CA.
	for _, key := range []string{"k", "tk_abc"} {
		if got, err := coordTrust(coordTrustSpec{Pins: []string{pin}}, key); err != nil || got.Mode != trust.Pin {
			t.Errorf("pins without a mode, key %q: %v, %v; want pin", key, got.Mode, err)
		}
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte(testCAPEM(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := coordTrust(coordTrustSpec{CAFile: caFile}, "k"); err != nil || got.Mode != trust.CA {
		t.Errorf("ca_file without a mode: %v, %v; want ca", got.Mode, err)
	}
	for name, spec := range map[string]coordTrustSpec{
		"pin without a fingerprint": {Mode: "pin"},
		"pin that is not one":       {Mode: "pin", Pins: []string{"abc"}},
		"ca without a file":         {Mode: "ca"},
		"ca file missing":           {Mode: "ca", CAFile: filepath.Join(t.TempDir(), "nope.pem")},
		"unknown mode":              {Mode: "insecure"},
	} {
		if _, err := coordTrust(spec, "k"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
