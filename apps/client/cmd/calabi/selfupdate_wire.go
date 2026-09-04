package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/selfupdate"
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

// maybeStartSelfUpdate launches the background updater — ONLY for the machine
// -wide system service (Option A: it runs as root/SYSTEM and can apply the
// installer; a dev/user daemon can't and mustn't). No-op when disabled or when
// not the system service. F4.
func maybeStartSelfUpdate(ctx context.Context, logger *slog.Logger, version string) {
	if os.Getenv("CALABI_SYSTEM_SERVICE") != "1" {
		return // only the privileged system service self-updates
	}
	manifest := envOr("CALABI_UPDATE_MANIFEST", defaultUpdateManifest)
	if manifest == "" || updatePubKeyB64 == "" {
		return
	}
	pub, err := base64.StdEncoding.DecodeString(updatePubKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		logger.Warn("selfupdate: bad baked public key — disabled")
		return
	}
	dir, err := creds.DataDir()
	if err != nil {
		logger.Warn("selfupdate: no data dir — disabled", "err", err)
		return
	}
	u := &selfupdate.Updater{
		ManifestURL:    manifest,
		CurrentVersion: version,
		PubKey:         ed25519.PublicKey(pub),
		DownloadDir:    filepath.Join(dir, "updates"),
		Logf:           func(f string, a ...any) { logger.Info(fmt.Sprintf(f, a...)) },
	}
	logger.Info("selfupdate enabled", "manifest", manifest, "interval", updateCheckInterval.String())
	go u.RunPeriodic(ctx, updateCheckInterval)
}
