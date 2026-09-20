package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kardianos/service"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/selfupdate"
)

// updatePubKeyB64 is the baked ed25519 PUBLIC key that verifies desktop update
// installers. Its private half signs releases (scripts/updatekit) and is held
// only by ops — NEVER committed. Empty ⇒ self-update disabled. Rotate by
// regenerating the pair (`scripts/updatekit keygen`) and swapping this value.
const updatePubKeyB64 = "+Un1Ssse7lflEeEPsr382+j7WduOrY8K7f4xZPMZ5fs="

// defaultUpdateManifest is the signed update manifest URL. Overridable via
// -ldflags "-X main.defaultUpdateManifest=…" or $CALABI_UPDATE_MANIFEST; empty
// ⇒ disabled.
var defaultUpdateManifest = "https://download.calabi.net/desktop/latest.json"

const updateCheckInterval = 6 * time.Hour

// newUpdateAgent builds the self-update agent, or returns nil when this daemon
// has no business running one.
//
// CHECKING and APPLYING are two different permissions, and this is where they
// part company:
//
//   - Every daemon with a configured manifest CHECKS. Knowing you are out of
//     date is useful even when you cannot fix it yourself — it is what the
//     :7400 console's version card and the "请手动更新" state are made of.
//     Before this, only the privileged system service checked, so a Linux box or
//     a user-mode daemon could sit six versions behind with nothing anywhere
//     saying so.
//   - Only a privileged OS SERVICE applies (see privilegedForUpdates). A
//     user-mode daemon cannot complete an install and must not start one.
//
// Whether it SHOULD install, having established that it can, is the machine's
// Policy (U2) — mode, maintenance window, and whether traffic is moving. That
// lives in the agent, not here.
//
// Returns nil for a dev/self-built daemon: an unparseable version can never be
// "older" than a release, so the check could only ever be a pointless request to
// the CDN from every developer's machine.
func newUpdateAgent(logger *slog.Logger, version, bffConsoleURL string, busy func() bool) *selfupdate.Agent {
	manifest := envOr("CALABI_UPDATE_MANIFEST", defaultUpdateManifest)
	if manifest == "" || updatePubKeyB64 == "" {
		return nil
	}
	if err := selfupdate.ValidateVersion(version); err != nil {
		return nil // dev build
	}
	pub, err := base64.StdEncoding.DecodeString(updatePubKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		logger.Warn("selfupdate: bad baked public key — disabled")
		return nil
	}
	dir, err := creds.DataDir()
	if err != nil {
		logger.Warn("selfupdate: no data dir — disabled", "err", err)
		return nil
	}
	privileged := privilegedForUpdates()
	u := &selfupdate.Updater{
		ManifestURL:    manifest,
		CurrentVersion: version,
		PubKey:         ed25519.PublicKey(pub),
		DownloadDir:    filepath.Join(dir, "updates"),
		Privileged:     privileged,
		Logf:           func(f string, a ...any) { logger.Info(fmt.Sprintf(f, a...)) },
		// U5a: results go to the platform this daemon is logged into.
		Report: newUpdateReporter(bffConsoleURL),
		// U5c: the org's requirement, merged with this machine's own setting.
		OrgPolicy: newOrgPolicyFetcher(bffConsoleURL),
	}
	agent := selfupdate.NewAgent(u, busy)
	p := agent.Policy()
	logger.Info("selfupdate enabled",
		"manifest", manifest, "interval", updateCheckInterval.String(),
		"can_install", privileged, "mode", p.Mode,
		"window", fmt.Sprintf("%02d:00-%02d:00 %s", p.WindowStartHour, p.WindowEndHour, time.Now().Format("MST")),
		"max_defer_days", p.MaxDeferDays)
	return agent
}

// privilegedForUpdates reports whether this process could actually carry an
// install through: replace the binary (or run an installer) AND get the service
// restarted afterwards.
//
// It used to be `CALABI_SYSTEM_SERVICE == "1"` — the marker `daemon install
// --system` bakes in. That marker only describes privilege on macOS, where
// launchd genuinely splits per-user LaunchAgents from root LaunchDaemons. On
// Linux and Windows a plain `daemon install` ALREADY produces a root systemd
// unit / LocalSystem service, so the marker was absent on exactly the machines
// that could update themselves — every hand-installed server was excluded, and
// the console told a uid-0 process it lacked privilege.
//
// The marker still counts (it is set on the desktop installer paths and is the
// cheapest true answer), but it is no longer the only way to qualify.
func privilegedForUpdates() bool {
	return privilegedForUpdatesFrom(
		os.Getenv("CALABI_SYSTEM_SERVICE"), service.Interactive(), runtime.GOOS, os.Geteuid())
}

// privilegedForUpdatesFrom is the rule, with its inputs passed in so the matrix
// is testable on any host.
//
// euid is os.Geteuid(), which is -1 on Windows — hence the explicit windows arm
// rather than a uid comparison that can never be true there.
func privilegedForUpdatesFrom(marker string, interactive bool, goos string, euid int) bool {
	if marker == "1" {
		return true
	}
	// Started from a shell, not by a service manager. Refuse even as root: there
	// is no unit for us to restart, and `systemctl restart calabi` from here
	// would either fail or restart somebody ELSE's service while this process
	// keeps running the old binary.
	if interactive {
		return false
	}
	if goos == "windows" {
		// A service the SCM started is LocalSystem; `daemon install` installs no
		// other kind.
		return true
	}
	// systemd / launchd started us. Only root can replace the binary and drive
	// the restart — a per-user launchd agent or a `systemctl --user` unit cannot.
	return euid == 0
}
