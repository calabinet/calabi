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
	detachedProcess        = 0x00000008
	createNewProcessGroup  = 0x00000200
	createBreakawayFromJob = 0x01000000
)

// applySupported says whether this GOOS has an OS-installer path at all.
// It is what turns "cannot update here" from an error into a reported state
// (Status.Reason == ReasonUnsupportedOS) the console can explain.
const applySupported = true

// installerLogHint: a silent NSIS install writes no log anywhere.
const installerLogHint = ""

// applyInstaller runs the NSIS installer silently. The service is LocalSystem
// (already elevated), so /S installs with no prompt; the installer stops +
// reinstalls the service, restarting US. Detached so it outlives us. The wait is
// only for the case where it does NOT take us down: the PREINSTALL hook aborts
// (a service it did not create, or an exe that would not unlock) and exits 2.
func applyInstaller(_ context.Context, setupPath string) (func() error, error) {
	cmd := exec.Command(setupPath, "/S")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: detachedProcess | createNewProcessGroup | createBreakawayFromJob,
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd.Wait, nil
}
