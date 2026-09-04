//go:build darwin

package selfupdate

import (
	"context"
	"os/exec"
	"syscall"
)

// applyInstaller runs the macOS installer for the downloaded.pkg. The daemon is
// root (LaunchDaemon), so `installer` can write /Applications + /Library and the
// pkg's postinstall re-bootstraps the LaunchDaemon — which restarts US. We start
// it in a NEW SESSION (Setsid) and don't wait, so tearing the daemon down
// mid-install doesn't take the installer with it (it's reparented to launchd).
func applyInstaller(_ context.Context, pkgPath string) error {
	cmd := exec.Command("installer", "-pkg", pkgPath, "-target", "/")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Release our handle; the installer runs on independently.
	return cmd.Process.Release()
}
