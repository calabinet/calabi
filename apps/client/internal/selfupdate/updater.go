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
	// Privileged reports whether this process may actually install: it is a
	// privileged OS service, already elevated, that a service manager can restart
	// afterwards. A user-mode daemon can CHECK — and should, so the console can
	// say "there is a newer version" — but must never run an installer it cannot
	// complete. Wired from privilegedForUpdates (cmd/calabi/selfupdate_wire.go).
	Privileged bool
	// Apply runs the verified installer. Default (nil) = applyInstaller: the OS
	// installer, spawned DETACHED so it survives the service restart it triggers.
	// Overridable in tests.
	Apply func(ctx context.Context, installerPath string) error
	Logf  func(format string, args ...any)
	// Managed reports whether the running binary is the copy this platform's
	// update artifact replaces (installed by the desktop installer /.pkg /
	// tarball, not by scoop or Homebrew). nil = the real check, which is the
	// fail-safe default: forgetting to wire it cannot switch the gate off.
	// Tests set it.
	Managed func() bool
	// FetchTimeout bounds the manifest+signature fetch. Zero = the default below.
	// Only tests set it; there is no knob for it in the daemon.
	FetchTimeout time.Duration
}

func (u *Updater) fetchTimeout() time.Duration {
	if u.FetchTimeout > 0 {
		return u.FetchTimeout
	}
	return manifestFetchTimeout
}

func (u *Updater) logf(format string, args ...any) {
	if u.Logf != nil {
		u.Logf(format, args...)
	}
}

// CheckAndApply runs one cycle. Returns (true, nil) after it launches an update
// (the service is about to be replaced/restarted), (false, nil) when there is
// nothing to do HERE — already current, or a newer version this machine cannot
// install itself — or (false, err) on any failure. A failed check NEVER touches
// the running install: verification gates the apply.
//
// "Newer but not installable here" is deliberately not an error. It is the
// steady state of every Linux/agent daemon (latest.json is desktop-only), and
// reporting it as a failure every 6 hours is how that population's log filled
// with noise while nobody learned they were out of date.
func (u *Updater) CheckAndApply(ctx context.Context) (bool, error) {
	st, art, err := u.check(ctx)
	if err != nil {
		return false, err
	}
	if !st.Available {
		u.logf("selfupdate: up to date (current %s, manifest %s)", u.CurrentVersion, st.Latest)
		return false, nil
	}
	if !st.CanApply {
		u.logf("selfupdate: %s is available but this install cannot apply it (%s)", st.Latest, st.Reason)
		return false, nil
	}

	// A FIXED filename. The version is attacker-controlled input and has no
	// business in a path built by a service running as root/LocalSystem; it is
	// validated during the check as well, but the path simply doesn't depend on
	// it now.
	dest := filepath.Join(u.DownloadDir, "calabi-update"+installerExt())
	u.logf("selfupdate: downloading %s", art.URL)
	if err := Download(ctx, art.URL, dest); err != nil {
		return false, err
	}
	// Two independent gates before a privileged service runs a downloaded file.
	if err := VerifySHA256(dest, art.SHA256); err != nil {
		os.Remove(dest)
		return false, err
	}
	if err := VerifySignature(dest, art.Signature, u.PubKey); err != nil {
		os.Remove(dest)
		return false, err
	}
	u.logf("selfupdate: verified update %s (sha256+sig) — applying", st.Latest)

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

// installerExt names the downloaded artifact. It is cosmetic for macOS and
// Windows (the file is handed to an installer either way) but NOT for Linux:
// there the applier opens it as a gzip tarball, and calling it.pkg would make
// every log line about it a small lie.
func installerExt() string {
	switch runtime.GOOS {
	case "windows":
		return ".exe"
	case "linux":
		return ".tar.gz"
	default:
		return ".pkg"
	}
}
