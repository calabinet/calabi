package selfupdate

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Updater drives one check→download→verify→apply cycle and the periodic loop
// around it — the daemon-side orchestrator over the primitives in selfupdate.go. F4.
type Updater struct {
	ManifestURL    string
	CurrentVersion string
	PubKey         ed25519.PublicKey
	DownloadDir    string
	// Apply runs the verified installer. Default (nil) = applyInstaller: the OS
	// installer, spawned DETACHED so it survives the service restart it triggers.
	// Overridable in tests.
	Apply func(ctx context.Context, installerPath string) error
	Logf  func(format string, args ...any)
}

func (u *Updater) logf(format string, args ...any) {
	if u.Logf != nil {
		u.Logf(format, args...)
	}
}

// CheckAndApply runs one cycle. Returns (true, nil) after it launches an update
// (the service is about to be replaced/restarted), (false, nil) when already
// current, or (false, err) on any failure. A failed check NEVER touches the
// running install — verification gates the apply.
func (u *Updater) CheckAndApply(ctx context.Context) (bool, error) {
	m, raw, err := FetchManifest(ctx, u.ManifestURL)
	if err != nil {
		return false, err
	}
	// NOTHING from the manifest is trusted before its own signature checks out
	// (audit finding UPD-1). Fail closed: a root service that cannot establish
	// where an instruction came from must not follow it.
	sig, err := FetchManifestSignature(ctx, u.ManifestURL)
	if err != nil {
		return false, err
	}
	if err := VerifyManifestSignature(raw, sig, u.PubKey); err != nil {
		return false, err
	}
	// The version reached the filesystem path verbatim before this check.
	if err := ValidateVersion(m.Version); err != nil {
		return false, err
	}
	if err := os.MkdirAll(u.DownloadDir, 0o700); err != nil {
		return false, err
	}
	// Anti-rollback. A valid signature proves we published this manifest, not
	// that we published it LAST: replaying a genuine older one is the same
	// downgrade by another route, and the attacker needs no key for it.
	floor := readVersionFloor(u.DownloadDir)
	if floor != "" && IsNewer(m.Version, floor) && !m.Rollback {
		return false, fmt.Errorf("selfupdate: manifest offers %s but %s was already seen — refusing "+
			"(a deliberate rollback must carry \"rollback\": true inside the signed manifest)", m.Version, floor)
	}
	if !m.Rollback {
		writeVersionFloor(u.DownloadDir, m.Version)
	}
	if !IsNewer(u.CurrentVersion, m.Version) && !m.Rollback {
		u.logf("selfupdate: up to date (current %s, manifest %s)", u.CurrentVersion, m.Version)
		return false, nil
	}
	if m.Rollback && u.CurrentVersion == m.Version {
		u.logf("selfupdate: already on the rollback target %s", m.Version)
		return false, nil
	}
	art, ok := m.ArtifactForThisPlatform()
	if !ok {
		return false, fmt.Errorf("selfupdate: manifest %s has no artifact for %s", m.Version, PlatformKey())
	}
	// A root service auto-applying an UNSIGNED download would be a gift to an
	// attacker who can spoof the manifest host — refuse rather than trust TLS alone.
	if art.SHA256 == "" || art.Signature == "" {
		return false, fmt.Errorf("selfupdate: artifact for %s is missing sha256/signature — refusing", PlatformKey())
	}

	// The installer must come from the same host as the manifest, over the same
	// or a stronger scheme: a spoofed manifest should not be able to redirect a
	// root service's download to an arbitrary origin.
	if err := sameOriginArtifact(u.ManifestURL, art.URL); err != nil {
		return false, err
	}

	// A FIXED filename. The version is attacker-controlled input and has no
	// business in a path built by a service running as root/LocalSystem; it is
	// validated above as well, but the path simply doesn't depend on it now.
	dest := filepath.Join(u.DownloadDir, "calabi-update"+installerExt())
	u.logf("selfupdate: downloading %s", art.URL)
	if err := Download(ctx, art.URL, dest); err != nil {
		return false, err
	}
	// Two independent gates before a root service runs a downloaded file.
	if err := VerifySHA256(dest, art.SHA256); err != nil {
		os.Remove(dest)
		return false, err
	}
	if err := VerifySignature(dest, art.Signature, u.PubKey); err != nil {
		os.Remove(dest)
		return false, err
	}
	u.logf("selfupdate: verified update %s (sha256+sig) — applying", m.Version)

	apply := u.Apply
	if apply == nil {
		apply = applyInstaller
	}
	if err := apply(ctx, dest); err != nil {
		return false, fmt.Errorf("selfupdate: apply: %w", err)
	}
	return true, nil
}

// RunPeriodic checks on an interval until ctx is cancelled. A successful apply
// returns (the installer is taking over and will restart the service); other
// errors are logged and retried next tick — a control-plane blip must not brick
// the running install.
func (u *Updater) RunPeriodic(ctx context.Context, interval time.Duration) {
	// Small initial delay so a freshly-booted service isn't racing the network.
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if applied, err := u.CheckAndApply(ctx); err != nil {
			u.logf("selfupdate: check failed: %v", err)
		} else if applied {
			return
		}
		t.Reset(interval)
	}
}

// sameOriginArtifact requires the installer URL to share the manifest's host,
// and to be https whenever the manifest was fetched over https (a dev/test
// manifest served over plain http may point at an http installer on the same
// host).
func sameOriginArtifact(manifestURL, artifactURL string) error {
	m, err := url.Parse(manifestURL)
	if err != nil {
		return fmt.Errorf("selfupdate: manifest url: %w", err)
	}
	a, err := url.Parse(artifactURL)
	if err != nil {
		return fmt.Errorf("selfupdate: artifact url: %w", err)
	}
	if !strings.EqualFold(a.Host, m.Host) {
		return fmt.Errorf("selfupdate: artifact host %q does not match the manifest host — refusing", a.Host)
	}
	if strings.EqualFold(m.Scheme, "https") && !strings.EqualFold(a.Scheme, "https") {
		return fmt.Errorf("selfupdate: artifact must be served over https — refusing")
	}
	return nil
}

func installerExt() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ".pkg"
}
