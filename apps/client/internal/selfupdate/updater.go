package selfupdate

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	m, err := FetchManifest(ctx, u.ManifestURL)
	if err != nil {
		return false, err
	}
	if !IsNewer(u.CurrentVersion, m.Version) {
		u.logf("selfupdate: up to date (current %s, manifest %s)", u.CurrentVersion, m.Version)
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

	if err := os.MkdirAll(u.DownloadDir, 0o700); err != nil {
		return false, err
	}
	dest := filepath.Join(u.DownloadDir, "calabi-update-"+m.Version+installerExt())
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

func installerExt() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ".pkg"
}
