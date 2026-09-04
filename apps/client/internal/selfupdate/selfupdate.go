// Package selfupdate is the daemon-side half of F4 (silent updates) —
//
// The privileged system service (root LaunchDaemon / LocalSystem) is the one
// component always running AND already elevated, so it owns the update loop:
// poll a signed manifest, and when it names a newer version, download that
// platform's installer, verify BOTH its sha256 and an Ed25519 signature, then
// hand it to the OS installer (increment 2). This package is the pure,
// network-free-testable core: manifest, version compare, download, verify.
//
// Two independent gates protect a root service that auto-applies a downloaded
// file (a very high-value target): the manifest's per-file sha256 AND an
// Ed25519 signature over the file bytes, checked against a public key baked into
// the daemon. OS-installer notarization/signing is only the second line.
package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Manifest is the update descriptor the daemon polls (latest.json). One entry
// per platform key (see PlatformKey).
type Manifest struct {
	Version   string                      `json:"version"`
	Notes     string                      `json:"notes,omitempty"`
	PubDate   string                      `json:"pub_date,omitempty"`
	Platforms map[string]PlatformArtifact `json:"platforms"`
}

// PlatformArtifact is one platform's installer: where to get it and how to
// verify it. Signature is base64(Ed25519 signature over the raw installer bytes).
type PlatformArtifact struct {
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature,omitempty"`
}

// PlatformKey is the manifest key for the running OS/arch. macOS ships a single
// universal installer, so it collapses to darwin-universal; elsewhere the arch
// is normalised to the amd64→x86_64 / arm64→aarch64 spelling installers use.
func PlatformKey() string {
	if runtime.GOOS == "darwin" {
		return "darwin-universal"
	}
	return runtime.GOOS + "-" + normalizeArch(runtime.GOARCH)
}

func normalizeArch(a string) string {
	switch a {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return a
	}
}

// ArtifactForThisPlatform returns the installer entry for the running platform.
func (m *Manifest) ArtifactForThisPlatform() (PlatformArtifact, bool) {
	a, ok := m.Platforms[PlatformKey()]
	return a, ok
}

// IsNewer reports whether candidate is a strictly higher semantic version than
// current. Unparseable inputs (notably a "dev" build) are treated as NOT newer,
// so a dev/self-built daemon never auto-updates itself. Pre-release/build
// suffixes are ignored for the comparison.
func IsNewer(current, candidate string) bool {
	cur := parseVer(current)
	cand := parseVer(candidate)
	if cur == nil || cand == nil {
		return false
	}
	for i := 0; i < 3; i++ {
		if cand[i] != cur[i] {
			return cand[i] > cur[i]
		}
	}
	return false
}

func parseVer(s string) []int {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil
	}
	out := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		out[i] = n
	}
	return out
}

// FetchManifest GETs and decodes the manifest at url. The body is size-capped —
// a manifest is a few hundred bytes; anything large is a misconfiguration or an
// attack, not a real manifest.
func FetchManifest(ctx context.Context, url string) (*Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("selfupdate: manifest HTTP %d", resp.StatusCode)
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, fmt.Errorf("selfupdate: decode manifest: %w", err)
	}
	return &m, nil
}

// Download streams url to dest atomically (temp file + rename). The caller MUST
// still verify the result with VerifySHA256 + VerifySignature before using it.
func Download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("selfupdate: download HTTP %d", resp.StatusCode)
	}
	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// VerifySHA256 checks the file at path against a hex-encoded expected digest.
func VerifySHA256(path, wantHex string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, strings.TrimSpace(wantHex)) {
		return fmt.Errorf("selfupdate: sha256 mismatch (got %s, want %s)", got, wantHex)
	}
	return nil
}

// VerifySignature checks a base64 Ed25519 signature over the file's raw bytes
// against pub (the release public key baked into the daemon).
func VerifySignature(path, sigB64 string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("selfupdate: invalid public key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return fmt.Errorf("selfupdate: decode signature: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, data, sig) {
		return errors.New("selfupdate: signature verification failed")
	}
	return nil
}
