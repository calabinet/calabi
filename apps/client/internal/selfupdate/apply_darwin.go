//go:build darwin

package selfupdate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// applySupported says whether this GOOS has an OS-installer path at all.
// It is what turns "cannot update here" from an error into a reported state
// (Status.Reason == ReasonUnsupportedOS) the console can explain.
const applySupported = true

// installerLogHint: PackageKit logs every install, including the script output
// and the file operation that failed, to the system install log.
const installerLogHint = " — see /var/log/install.log"

// applyInstaller runs the macOS installer for the downloaded.pkg. The daemon is
// root (LaunchDaemon), so `installer` can write /Applications + /Library and the
// pkg's postinstall re-bootstraps the LaunchDaemon — which restarts US. We start
// it in a NEW SESSION (Setsid) so tearing the daemon down mid-install doesn't
// take the installer with it (it's reparented to launchd).
//
// The returned wait only returns while we are alive if the install did not
// restart us — see installerExited.
func applyInstaller(_ context.Context, pkgPath string) (func() error, error) {
	// The installer's own output goes to a FILE beside the pkg, not to a pipe
	// back to us: postinstall stops this daemon mid-install, a pipe would break
	// with it, and the installer's next line of output would die of SIGPIPE.
	outPath := filepath.Join(filepath.Dir(pkgPath), "calabi-update.log")
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer out.Close() // the child holds its own descriptor once started

	cmd := exec.Command("installer", "-pkg", pkgPath, "-target", "/")
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() error {
		err := cmd.Wait()
		if err != nil {
			// "exit status 1" alone says nothing; installer's last line is the
			// one that says what failed.
			if line := lastLine(outPath); line != "" {
				err = fmt.Errorf("%w: %s", err, line)
			}
		}
		return err
	}, nil
}
