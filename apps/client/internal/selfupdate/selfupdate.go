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
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// maxInstallerBytes caps a downloaded installer. The manifest is unsigned and
// attacker-controllable under this package's own threat model ("an attacker who
// can spoof the manifest host"), and the download runs as root/LocalSystem —
// so an unbounded stream is a disk-fill, and VerifySignature reads the whole
// file into memory afterwards (audit finding UPD-1). Real installers are tens
// of MB; this leaves a wide margin.
const maxInstallerBytes = 512 << 20 // 512 MiB

// versionPattern is the ONLY shape a manifest version may take. It exists
// because the version string used to be concatenated into a filesystem path
// while only its numeric prefix was validated, so "9.9.9+/././victim" wrote
// (and then deleted) a file outside the download directory with service
// privileges. The download path no longer embeds the version at all; this is
// the second lock on the same door, and it also keeps a hostile string out of
// logs and error messages.
var versionPattern = regexp.MustCompile(`^v?[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}([-+][0-9A-Za-z.-]{1,64})?$`)

// ValidateVersion rejects anything that is not a plain semantic version.
func ValidateVersion(v string) error {
	if !versionPattern.MatchString(strings.TrimSpace(v)) {
		return fmt.Errorf("selfupdate: refusing manifest with a malformed version")
	}
	return nil
}

// Manifest is the update descriptor the daemon polls (latest.json). One entry
// per platform key (see PlatformKey).
type Manifest struct {
	Version   string                      `json:"version"`
	Notes     string                      `json:"notes,omitempty"`
	PubDate   string                      `json:"pub_date,omitempty"`
	Platforms map[string]PlatformArtifact `json:"platforms"`
	// Rollback marks a DELIBERATE downgrade: ops re-pointing the manifest at an
	// earlier release to undo a bad one, which is the documented recovery
	// procedure. Without it the anti-rollback floor
	// below would block that procedure along with the attack it exists to stop.
	//
	// It is safe precisely because it lives INSIDE the signed manifest: an
	// attacker replaying an old release cannot add it, and cannot strip it from
	// one that has it, without breaking the signature.
	Rollback bool `json:"rollback,omitempty"`
	// Critical marks a security release: it installs under ModeSecurity as well
	// as ModeAuto, and it ignores the maintenance window and the busy check.
	//
	// A window exists to keep a ROUTINE restart out of the working day. Making a
	// remotely-exploitable fix wait until 3am would be using it for something it
	// was not for. It does NOT override ModeNotify — someone who said "never
	// without me" gets a louder notice, not a surprise restart; the floor that
	// overrides even that is min_supported (U3).
	//
	// Like Rollback, it is safe precisely because it lives INSIDE the signed
	// manifest: it can bypass the user's setting, so it must not be possible to
	// add or strip it without the key.
	Critical bool `json:"critical,omitempty"`
	// MinSupported is the oldest version still supported. A client BELOW it
	// installs regardless of the machine's mode — including "tell me only".
	//
	// This is the floor, and it is the only thing that overrides an explicit
	// "never without me". Reach for it when leaving people where they are is
	// worse than restarting them without warning: a remotely exploitable hole, a
	// protocol change that has made the old client useless anyway. `critical` is
	// for everything else.
	//
	// Signed like the rest of the manifest — it can override the user's setting,
	// so it must not be possible to add or strip without the key.
	MinSupported string `json:"min_supported,omitempty"`
	// Rollout staggers this release across machines over time (U5b). Absent =
	// every machine at once. Signed like the rest: see Rollout.
	Rollout *Rollout `json:"rollout,omitempty"`
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

// FetchManifest GETs and decodes the manifest at url, returning the parsed form
// AND the exact bytes it was parsed from. The body is size-capped — a manifest
// is a few hundred bytes; anything large is a misconfiguration or an attack, not
// a real manifest.
//
// The raw bytes are returned because the signature is over what was actually
// downloaded. Re-serializing the parsed struct to check a signature would verify
// a different byte string than the server sent — the classic way a signature
// check ends up proving nothing.
func FetchManifest(ctx context.Context, url string) (*Manifest, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("selfupdate: manifest HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("selfupdate: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, fmt.Errorf("selfupdate: decode manifest: %w", err)
	}
	return &m, raw, nil
}

// ManifestSigURL is where the detached manifest signature lives: the manifest's
// own URL plus ".sig", which is what `updatekit merge` writes beside it.
func ManifestSigURL(manifestURL string) string { return manifestURL + ".sig" }

// FetchManifestSignature GETs the detached base64 signature for the manifest.
func FetchManifestSignature(ctx context.Context, manifestURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ManifestSigURL(manifestURL), nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("selfupdate: manifest signature HTTP %d (is latest.json.sig published?)", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("selfupdate: read manifest signature: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// VerifyManifestSignature checks a detached base64 ed25519 signature over the
// manifest's exact bytes against the release public key baked into the daemon.
//
// This is what closes the rollback/freeze half of the update threat model: the
// per-installer signature proves "we built this file", but says nothing about
// WHICH VERSION it is, so a manifest claiming 99.0.0 while pointing at an old,
// genuinely signed installer used to be accepted and applied by a root service.
// Signing the manifest binds version, platform and sha256 together.
func VerifyManifestSignature(raw []byte, sigB64 string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("selfupdate: invalid public key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return fmt.Errorf("selfupdate: decode manifest signature: %w", err)
	}
	if !ed25519.Verify(pub, raw, sig) {
		return errors.New("selfupdate: manifest signature verification failed")
	}
	return nil
}

// versionFloorFile records the highest manifest version this machine has ever
// accepted. Signing the manifest stops a forged one; it does NOT stop replaying
// a genuine OLDER one, which is the same downgrade by another route. The floor
// is what makes that replay useless.
const versionFloorFile = "version-floor"

// readVersionFloor returns the highest version seen, or "" when there is none
// (a fresh install, or a machine whose state was cleared — both start open).
func readVersionFloor(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, versionFloorFile))
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(b))
	if ValidateVersion(v) != nil {
		return "" // unreadable/corrupt: ignore rather than wedge updates forever
	}
	return v
}

// writeVersionFloor raises the floor. Best-effort: failing to record it must not
// stop an otherwise verified update, it only means the next check re-learns it.
func writeVersionFloor(dir, v string) {
	_ = os.WriteFile(filepath.Join(dir, versionFloorFile), []byte(v+"\n"), 0o600)
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
	// Read one byte past the cap so hitting it is distinguishable from a file
	// that happens to be exactly maxInstallerBytes long.
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxInstallerBytes+1))
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if n > maxInstallerBytes {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("selfupdate: installer exceeds %d bytes — refusing", int64(maxInstallerBytes))
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
