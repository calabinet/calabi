//go:build windows

package selfupdate

import (
	"context"
	"os/exec"
	"syscall"
)

// Windows process-creation flags (winbase.h). DETACHED_PROCESS gives the
// installer no console tied to ours; CREATE_NEW_PROCESS_GROUP + BREAKAWAY_FROM_JOB
// let it survive our own shutdown when the NSIS installer stops+reinstalls the
// service (which kills this daemon). BREAKAWAY may be a no-op if the service
// isn't in a job; harmless then.
const (
	detachedProcess       = 0x00000008
	createNewProcessGroup = 0x00000200
	createBreakawayFromJob = 0x01000000
)

// applyInstaller runs the NSIS installer silently. The service is LocalSystem
// (already elevated), so /S installs with no prompt; the installer stops +
// reinstalls the service, restarting US. Detached + not waited so it outlives us.
func applyInstaller(_ context.Context, setupPath string) error {
	cmd := exec.Command(setupPath, "/S")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: detachedProcess | createNewProcessGroup | createBreakawayFromJob,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
