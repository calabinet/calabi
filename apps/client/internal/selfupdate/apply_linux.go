//go:build linux

package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// applySupported says whether this GOOS has an OS-installer path at all.
// It is what turns "cannot update here" from an error into a reported state
// (Status.Reason == ReasonUnsupportedOS) the console can explain.
const applySupported = true

// applyInstaller on Linux is a BINARY SWAP, not an installer run.
//
// There is no.pkg or.msi here; the published artifact is the release tarball,
// one static binary in it. That turns out to be simpler than either installer:
// Linux lets you rename a file over a RUNNING executable (the old inode stays
// alive for the process holding it), so the swap is a single atomic rename and
// the restart is systemd's problem.
//
// Every step that can fail is done BEFORE the rename. Once the binary is
// replaced there is no half-applied state worth reasoning about — either the
// service comes back on the new binary or a human has `calabi.old` sitting right
// next to it.
func applyInstaller(ctx context.Context, archivePath string) error {
	// Refuse before touching anything if we could not restart afterwards.
	// Swapping the binary of a service nothing can restart leaves a machine
	// running the old code with the new one on disk, and nothing saying so.
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.New("selfupdate: no systemctl on this machine — refusing to swap the binary of a service nothing can restart")
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("selfupdate: locate own binary: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
		// Replace what the symlink POINTS AT. Renaming over the link itself would
		// silently turn a managed symlink into a regular file and leave the real
		// binary behind, still there and still old.
		self = resolved
	}

	tmp := filepath.Join(filepath.Dir(self), ".calabi-update.new")
	if err := extractBinary(archivePath, tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	// Run it before trusting it. A truncated download that still matched its
	// hash is impossible, but an archive built for the wrong architecture is
	// not — and that failure would otherwise surface as a service that never
	// comes back up.
	if err := verifyRunnable(ctx, tmp); err != nil {
		os.Remove(tmp)
		return err
	}

	// A hard link, not a copy: instant, no extra space, and it gives a human
	// something to move back if the new binary turns out to be broken in a way
	// `version` does not catch.
	backup := self + ".old"
	os.Remove(backup)
	_ = os.Link(self, backup)

	if err := os.Rename(tmp, self); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("selfupdate: swap binary: %w", err)
	}

	// --no-block is load-bearing, not politeness. systemctl started from inside
	// the unit's OWN cgroup would be killed by the stop it just asked for;
	// --no-block queues the job with PID 1 and returns immediately, so the
	// restart survives this process dying.
	unit := serviceUnit()
	cmd := exec.Command(systemctl, "restart", "--no-block", unit)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("selfupdate: binary replaced but restarting %s failed: %w", unit, err)
	}
	return cmd.Process.Release()
}

// serviceUnit is the systemd unit to restart. The installer bakes the name into
// the service environment (serviceConfig), so the running service knows it; a
// daemon started some other way falls back to the default install name.
func serviceUnit() string {
	if v := strings.TrimSpace(os.Getenv("CALABI_SERVICE_NAME")); v != "" {
		return v
	}
	return "calabi"
}

// verifyRunnable checks the extracted binary actually executes on this machine
// and reports a version. Cheap, and it catches the one failure the hash and the
// signature cannot: a correctly published artifact for the wrong architecture.
func verifyRunnable(ctx context.Context, path string) error {
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return fmt.Errorf("selfupdate: the downloaded binary does not run here (%w) — not swapping", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(out)), "calabi ") {
		return fmt.Errorf("selfupdate: the downloaded binary did not identify itself as calabi — not swapping")
	}
	return nil
}
